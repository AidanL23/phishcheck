package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

const (
	// ReclaimEvery is how often the reclaim loop scans the PEL.
	ReclaimEvery = 30 * time.Second
	// ReclaimMinIdle is how long an entry must sit unacked before any worker
	// may take it. Keep it above MaxHoldTime (worker.go), or a job that's
	// still running can be claimed and run twice.
	ReclaimMinIdle = 60 * time.Second
	// ReclaimReadTimeout bounds reclaim's read of the job hash. It runs after
	// XAUTOCLAIM reset the entry's idle time and before Handle starts its own
	// clocks, so it counts toward MaxHoldTime.
	ReclaimReadTimeout = 2 * time.Second
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
		"every", ReclaimEvery.String(), "min_idle", w.minIdle().String(), "max_attempts", MaxAttempts)

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

// minIdle is ReclaimMinIdle unless the demo override is set.
func (w *Worker) minIdle() time.Duration {
	if w.dbg.ReclaimIdle > 0 {
		return w.dbg.ReclaimIdle
	}
	return ReclaimMinIdle
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

		res, err := w.q.Claim(ctx, cursor, w.minIdle())
		if err != nil {
			// A read cut short by shutdown isn't worth an error line.
			if ctx.Err() == nil {
				w.logger.Error("reclaim: autoclaim", "error", err)
			}
			return // the next tick tries again
		}

		// Error level: the job behind each of these is stuck (its hash keeps
		// saying RUNNING or QUEUED) and needs a person. Redis has already
		// dropped the entry, so this line is the only trace.
		for _, id := range res.Trimmed {
			w.logger.Error("reclaim: pending job lost, its stream entry was trimmed (MAXLEN) before reclaim",
				"stream_id", id)
		}
		for _, id := range res.Malformed {
			w.logger.Warn("reclaim: skipped malformed stream entry", "stream_id", id)
		}

		for _, job := range res.Jobs {
			// Once claimed, the entry is this worker's. Finish it even if
			// SIGTERM arrives now, for the same reason as the main loop.
			w.reclaim(context.WithoutCancel(ctx), job)
		}

		if res.Next == "0-0" {
			return // scanned to the end of the PEL
		}
		cursor = res.Next
	}
}

// reclaim decides what to do with one claimed entry. It reads the job hash
// first because Handle bumps attempts, so the attempts check has to happen
// before Handle runs.
//
// The order of the cases matters. DONE and FAILED come before the attempts
// check: both mean the outcome is already recorded and only the XACK was
// lost, so they're acked whatever attempts says. A job is never FAILED and
// still pending because of giveUp, since giveUp writes FAILED in the same
// MULTI/EXEC as the dead-letter record and the XACK.
func (w *Worker) reclaim(ctx context.Context, job queue.Job) {
	logger := w.logger.With("job_id", job.JobID, "stream_id", job.StreamID)

	// The read gets its own short deadline, ReclaimReadTimeout, because it
	// runs before Handle and counts toward MaxHoldTime.
	readCtx, cancelRead := context.WithTimeout(ctx, ReclaimReadTimeout)
	j, err := w.st.GetJob(readCtx, job.JobID)
	cancelRead()

	// The other branches are a few small writes instead of Handle.
	opCtx, cancel := context.WithTimeout(ctx, FinishTimeout)
	defer cancel()

	switch {
	case errors.Is(err, store.ErrNotFound):
		// The job hash expired or was never written, so there's nothing to
		// run. Don't write FAILED: that would create a new hash with no
		// filename and no TTL history. Dead-letter it with the reason.
		w.deadLetter(opCtx, logger, job, 0, "job hash not found (expired or never written)", nil)

	case err != nil:
		// Redis read failed. Leave the entry pending for the next pass.
		logger.Error("reclaim: read job, left pending", "error", err)

	case j.State == pb.JobState_JOB_STATE_DONE:
		// The report and DONE are in Redis, and only the XACK was lost.
		// Running it again would redo the work and count an extra attempt.
		logger.Info("reclaimed job already DONE, acking")
		w.ack(opCtx, logger, job)

	case j.State == pb.JobState_JOB_STATE_FAILED:
		// fail() wrote FAILED, and then its XACK was lost. Same as DONE,
		// on any attempt: an ordinary failure is not a poison job.
		logger.Info("reclaimed job already FAILED, acking")
		w.ack(opCtx, logger, job)

	case j.Attempts >= MaxAttempts:
		w.giveUp(opCtx, logger, job, j)

	default:
		// QUEUED (read, but the worker died before StartAttempt) or RUNNING
		// (died or panicked mid-job) with attempts to spare: run it again.
		logger.Info("reclaimed job, retrying", "attempts_so_far", j.Attempts)
		w.Handle(ctx, job)
	}
}

// giveUp marks the job FAILED, writes the dead-letter record and acks the
// entry, all in one MULTI/EXEC. Either all three happen or none do, and the
// next pass retries. Done as two steps, a crash between them would leave
// either a FAILED job that reclaim can't tell from an ordinary failure, or
// an acked entry whose job shows RUNNING forever.
func (w *Worker) giveUp(ctx context.Context, logger *slog.Logger, job queue.Job, j *store.Job) {
	reason := j.Error
	if reason == "" {
		// A worker that was killed (kill -9, OOM, power loss) writes no error.
		reason = "no error recorded; the worker likely died mid-job"
	}

	// No WorkerID, so the hash keeps the ID of the last worker that ran the
	// job. The dead-letter entry records who gave up on it.
	f := store.JobFields{Error: reason}
	w.deadLetter(ctx, logger, job, int64(j.Attempts), reason, func(p redis.Pipeliner) {
		w.st.SetJobStateIn(ctx, p, job.JobID, pb.JobState_JOB_STATE_FAILED, f)
	})
}

// deadLetter moves the entry to the dead-letter stream and acks it, plus
// whatever also adds to the same transaction. On failure the entry stays
// pending and the next pass tries again.
func (w *Worker) deadLetter(ctx context.Context, logger *slog.Logger, job queue.Job, attempts int64, reason string, also func(redis.Pipeliner)) {
	if err := w.q.DeadLetter(ctx, job, attempts, reason, also); err != nil {
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
