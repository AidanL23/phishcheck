package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

const (
	// ReclaimEvery is how often the reclaim loop scans the PEL.
	ReclaimEvery = 30 * time.Second
	// ReclaimMinIdle is how long an entry must sit unacked before any worker
	// may take it. Keep it above JobTimeout + FinishTimeout (worker.go), or
	// a job that's still running can be claimed and run twice.
	ReclaimMinIdle = 60 * time.Second
	// MaxAttempts is the number of starts after which a job is dead-lettered
	// instead of run again. Handle counts a start in StartAttempt.
	MaxAttempts = 3
)

// RunReclaim is the worker's second goroutine. It scans once right away,
// so a restarted worker doesn't wait 30 s to pick up jobs a crashed one
// left behind, then every ReclaimEvery until ctx is cancelled.
//
// A time.Ticker drops ticks while the receiver is busy. A pass that takes
// longer than 30 s delays the next one; passes never pile up.
func (w *Worker) RunReclaim(ctx context.Context) {
	w.logger.Info("reclaim loop started",
		"every", ReclaimEvery.String(), "min_idle", ReclaimMinIdle.String(), "max_attempts", MaxAttempts)

	w.reclaimPass(ctx)

	t := time.NewTicker(ReclaimEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("reclaim loop stopping")
			return
		case <-t.C:
			w.reclaimPass(ctx)
		}
	}
}

// reclaimPass walks the whole PEL once, claiming one entry per XAUTOCLAIM
// call, and runs or dead-letters each entry it claims.
func (w *Worker) reclaimPass(ctx context.Context) {
	cursor := "0-0" // start of the PEL
	for {
		// Stop between entries on shutdown, the same rule as the main loop.
		if ctx.Err() != nil {
			return
		}

		jobs, next, err := w.q.Claim(ctx, cursor, ReclaimMinIdle)
		if err != nil {
			// A read cut short by shutdown isn't worth an error line.
			if ctx.Err() == nil {
				w.logger.Error("reclaim: autoclaim", "error", err)
			}
			return // the next tick tries again
		}

		for _, job := range jobs {
			// Once claimed, the entry is this worker's. Finish it even if
			// SIGTERM arrives now, for the same reason as the main loop.
			w.reclaim(context.WithoutCancel(ctx), job)
		}

		if next == "0-0" {
			return // scanned to the end of the PEL
		}
		cursor = next
	}
}

// reclaim decides what to do with one claimed entry. It reads the job hash
// first because Handle bumps attempts, so the attempts check has to happen
// before Handle runs.
//
// The order of the cases matters:
//   - DONE comes first. The work is finished and only the XACK was lost, so
//     it's acked even if attempts is 3.
//   - The attempts check comes before FAILED. giveUp writes FAILED and then
//     dead-letters. If the dead-letter step failed, the next pass has to
//     dead-letter again, not just ack a FAILED job with no dead-letter record.
func (w *Worker) reclaim(ctx context.Context, job queue.Job) {
	logger := w.logger.With("job_id", job.JobID, "stream_id", job.StreamID)

	// Its own short deadline: these are a few small Redis calls. Handle,
	// below, sets its own timeouts from ctx.
	opCtx, cancel := context.WithTimeout(ctx, FinishTimeout)
	defer cancel()

	j, err := w.st.GetJob(opCtx, job.JobID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The job hash expired or was never written, so there's nothing to
		// run. Don't write FAILED: that would create a new hash with no
		// filename and no TTL history. Dead-letter it with the reason.
		w.deadLetter(opCtx, logger, job, 0, "job hash not found (expired or never written)")

	case err != nil:
		// Redis read failed. Leave the entry pending for the next pass.
		logger.Error("reclaim: read job, left pending", "error", err)

	case j.State == pb.JobState_JOB_STATE_DONE:
		// The report and DONE are in Redis, and only the XACK was lost.
		// Running it again would redo the work and count an extra attempt.
		logger.Info("reclaimed job already DONE, acking")
		w.ack(opCtx, logger, job)

	case j.Attempts >= MaxAttempts:
		w.giveUp(opCtx, logger, job, j)

	case j.State == pb.JobState_JOB_STATE_FAILED:
		// fail() wrote FAILED, and then its XACK was lost. Same as DONE.
		logger.Info("reclaimed job already FAILED, acking")
		w.ack(opCtx, logger, job)

	default:
		// QUEUED (read, but the worker died before StartAttempt) or RUNNING
		// (died or panicked mid-job) with attempts to spare: run it again.
		logger.Info("reclaimed job, retrying", "attempts_so_far", j.Attempts)
		w.Handle(ctx, job)
	}
}

// giveUp marks the job FAILED, then dead-letters it.
//
// FAILED goes first. If that write fails, nothing has changed and the next
// pass tries again. If FAILED lands but the dead-letter doesn't, the next
// pass reaches the attempts check again and retries the dead-letter. The
// other order is worse: once the dead-letter acks the entry, nothing would
// ever retry a failed FAILED write, and the job would show RUNNING forever.
func (w *Worker) giveUp(ctx context.Context, logger *slog.Logger, job queue.Job, j *store.Job) {
	reason := j.Error
	if reason == "" {
		// A worker that was killed (kill -9, OOM, power loss) writes no error.
		reason = "no error recorded; the worker likely died mid-job"
	}

	// No WorkerID, so the hash keeps the ID of the last worker that ran the
	// job. The dead-letter entry records who gave up on it.
	f := store.JobFields{Error: reason}
	if err := w.st.SetJobState(ctx, job.JobID, pb.JobState_JOB_STATE_FAILED, f); err != nil {
		logger.Error("dead-letter: write FAILED, left pending", "error", err)
		return
	}
	w.deadLetter(ctx, logger, job, int64(j.Attempts), reason)
}

// deadLetter moves the entry to the dead-letter stream and acks it. On
// failure the entry stays pending and the next pass tries again.
func (w *Worker) deadLetter(ctx context.Context, logger *slog.Logger, job queue.Job, attempts int64, reason string) {
	if err := w.q.DeadLetter(ctx, job, attempts, reason); err != nil {
		logger.Error("dead-letter failed, left pending", "error", err)
		return
	}
	// Error level: someone needs to look at a dead-lettered job.
	logger.Error("job dead-lettered", "attempts", attempts, "error", reason)
}

// ack acks an entry whose outcome is already recorded in Redis.
func (w *Worker) ack(ctx context.Context, logger *slog.Logger, job queue.Job) {
	if err := w.q.Ack(ctx, job.StreamID); err != nil {
		logger.Error("ack", "error", err)
	}
}
