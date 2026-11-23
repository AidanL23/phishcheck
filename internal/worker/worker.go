// Package worker runs one job end to end and decides whether to XACK it.
// The main loop (cmd/worker) and the reclaim loop (reclaim.go) both call
// Handle, so a reclaimed job goes through exactly the same rules.
package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

const (
	// JobTimeout bounds one attempt: the Redis calls now, DNS from Day 5.
	// It is part of MaxHoldTime, which must stay below ReclaimMinIdle.
	JobTimeout = 50 * time.Second
	// FinishTimeout bounds the FAILED write and the XACK. They get their
	// own deadline, so a job that hit JobTimeout is still recorded and acked.
	FinishTimeout = 5 * time.Second
	// MaxHoldTime is the longest one worker can hold an entry between
	// receiving it (XREADGROUP or XAUTOCLAIM, which both reset its idle
	// time) and its XACK: reclaim's job read, then Handle's attempt and
	// finish. It must stay below ReclaimMinIdle (reclaim.go), or another
	// worker can claim an entry this one is still finishing, and the job runs
	// twice. TestMaxHoldTimeBelowMinIdle enforces it.
	MaxHoldTime = ReclaimReadTimeout + JobTimeout + FinishTimeout // 57 s
)

var (
	// errWrite marks a failed Redis write inside the job. The outcome was
	// never recorded, so the entry stays pending and reclaim retries it.
	errWrite = errors.New("redis write failed")
	// errPanic marks a panic caught by safeProcess. It is not acked, so
	// reclaim retries it, and reclaim.go dead-letters it at MaxAttempts.
	errPanic = errors.New("handler panicked")
)

// Worker holds what every job needs. One per process.
type Worker struct {
	st     *store.Store
	q      *queue.Consumer
	id     string // worker ID, also the consumer name in the group
	logger *slog.Logger
	dbg    Debug // demo switches; zero value = off

	// jobTimeout is JobTimeout. A field only so tests in this package can
	// shorten it; nothing else changes it.
	jobTimeout time.Duration
}

func New(st *store.Store, q *queue.Consumer, id string, logger *slog.Logger, dbg Debug) *Worker {
	return &Worker{st: st, q: q, id: id, logger: logger, dbg: dbg, jobTimeout: JobTimeout}
}

// Debug holds demo-only switches. The zero value turns them all off, and
// that is what normal runs use.
type Debug struct {
	// Sleep stalls every attempt right after StartAttempt marks it RUNNING,
	// so the worker can be killed mid-job (§2.4). 0 = off.
	Sleep time.Duration
	// Panic makes each attempt panic, so the job gets dead-lettered (§2.5).
	Panic bool
	// ReclaimIdle overrides ReclaimMinIdle when > 0. Demo only;
	// cmd/worker rejects unsafe values.
	ReclaimIdle time.Duration
}

// Handle runs one job, writes one summary log line, and acks unless the
// outcome couldn't be recorded or the job panicked. In those cases the entry
// stays in the PEL and the reclaim loop (reclaim.go) picks it up after MinIdle.
//
// ctx must not be the shutdown context (the caller passes
// context.WithoutCancel). If SIGTERM cancelled these Redis calls partway
// through, the job would be left RUNNING with its entry unacked.
func (w *Worker) Handle(ctx context.Context, job queue.Job) {
	start := time.Now()
	logger := w.logger.With("job_id", job.JobID, "stream_id", job.StreamID)

	jobCtx, cancelJob := context.WithTimeout(ctx, w.jobTimeout)
	attempt, err := w.attempt(jobCtx, job.JobID)
	// Check the deadline on the context, not the error: go-redis can report
	// a deadline as a net timeout that doesn't wrap context.DeadlineExceeded.
	timedOut := errors.Is(jobCtx.Err(), context.DeadlineExceeded)
	cancelJob()

	// Integer milliseconds: slog's JSON handler writes a Duration as nanoseconds.
	logger = logger.With("attempt", attempt, "duration_ms", time.Since(start).Milliseconds())

	finishCtx, cancelFinish := context.WithTimeout(ctx, FinishTimeout)
	defer cancelFinish()

	// Order matters: panic before timeout (a panic is a panic, however long
	// it took), timeout before errWrite (a write that failed because the
	// job's own deadline ran out is a timeout, not a Redis problem).
	switch {
	case err == nil:
		logger.Info("job done")

	case errors.Is(err, errPanic):
		// Record the reason for the dead-letter entry, but keep RUNNING:
		// FAILED would end WatchReport while reclaim is still retrying, and
		// reclaim would ack it as an ordinary failure instead of retrying.
		f := store.JobFields{WorkerID: w.id, Error: err.Error()}
		if serr := w.st.SetJobState(finishCtx, job.JobID, pb.JobState_JOB_STATE_RUNNING, f); serr != nil {
			logger.Error("record panic error", "error", serr)
		}
		logger.Error("job panicked, left pending for reclaim", "error", err)
		return // no XACK

	case timedOut:
		if !w.fail(finishCtx, logger, job.JobID, fmt.Errorf("timed out after %s: %w", w.jobTimeout, err)) {
			return // FAILED write failed: no XACK
		}

	case errors.Is(err, errWrite):
		// Redis didn't take the write. Writing FAILED would most likely fail
		// too, and would be wrong anyway: reclaim is about to retry the job.
		logger.Error("redis write failed, left pending for reclaim", "error", err)
		return // no XACK

	default:
		if !w.fail(finishCtx, logger, job.JobID, err) {
			return // FAILED write failed: no XACK
		}
	}

	// XACK removes the entry from the PEL. Acking an entry that is no longer
	// pending is a no-op in Redis, so a duplicate ack can't break anything.
	if aerr := w.q.Ack(finishCtx, job.StreamID); aerr != nil {
		logger.Error("ack", "error", aerr)
	}
}

// fail records FAILED with the reason and reports whether the write worked.
// false means the outcome is not in Redis, so the caller must not ack.
func (w *Worker) fail(ctx context.Context, logger *slog.Logger, jobID string, err error) bool {
	f := store.JobFields{WorkerID: w.id, Error: err.Error()}
	if serr := w.st.SetJobState(ctx, jobID, pb.JobState_JOB_STATE_FAILED, f); serr != nil {
		logger.Error("job failed, and writing FAILED failed; left pending for reclaim",
			"error", err, "write_error", serr)
		return false
	}
	logger.Error("job failed", "error", err)
	return true
}

// attempt bumps the counter, then runs the job under recover. StartAttempt
// sits outside safeProcess so its count still comes back when the job panics.
func (w *Worker) attempt(ctx context.Context, jobID string) (int64, error) {
	n, err := w.st.StartAttempt(ctx, jobID, w.id)
	if err != nil {
		// Two %w (Go 1.20+): errors.Is matches errWrite AND the Redis error.
		return 0, fmt.Errorf("start attempt: %w: %w", errWrite, err)
	}
	return n, w.safeProcess(ctx, jobID)
}

// safeProcess turns a panic in process into an errPanic error, so one bad
// rule on one email fails that job instead of killing the worker.
// recover only catches panics on this goroutine. A rule that starts its
// own goroutine and panics there still crashes the process.
func (w *Worker) safeProcess(ctx context.Context, jobID string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// The stack goes to the log only. It's too big for the job hash,
			// and it's what you need to find the bug.
			w.logger.Error("panic in job", "job_id", jobID,
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			err = fmt.Errorf("%w: %v", errPanic, r) // named return: overrides process's result
		}
	}()
	return w.process(ctx, jobID)
}

// process does the job itself: read job + email -> stub report -> DONE.
// RUNNING is already set by StartAttempt. Writes are tagged errWrite; reads
// are not, so an expired email is a normal FAILED, not an endless retry.
func (w *Worker) process(ctx context.Context, jobID string) error {
	// Demo only: hold the job in RUNNING long enough to kill -9 this worker.
	// It waits on ctx, so it can never outlive JobTimeout.
	if err := w.debugSleep(ctx, jobID); err != nil {
		return err
	}

	// Demo only: must be inside safeProcess so recover() catches it.
	// Handle skips the XACK, and reclaim retries up to MaxAttempts.
	if w.dbg.Panic {
		panic("debug panic: PHISHCHECK_DEBUG_PANIC is set")
	}

	// The API saved the filename in the job hash when it accepted the upload.
	job, err := w.st.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("get job: %w", err)
	}

	raw, err := w.st.GetEmail(ctx, jobID)
	if err != nil {
		return fmt.Errorf("get email: %w", err)
	}
	sum := sha256.Sum256(raw) // hash of the bytes actually analyzed

	// Stub report. Real findings start on Day 3.
	report := &pb.Report{
		JobId:      jobID,
		Verdict:    pb.Verdict_VERDICT_CLEAN,
		Score:      0,
		Filename:   job.Filename,
		Sha256:     hex.EncodeToString(sum[:]),
		WorkerId:   w.id, // which replica did the work (the Day 6 proof)
		AnalyzedAt: timestamppb.Now(),
	}

	if err := w.st.PutReport(ctx, jobID, report); err != nil {
		return fmt.Errorf("put report: %w: %w", errWrite, err)
	}

	// Set DONE last: once the state says DONE, GetReport expects the report to exist.
	done := store.JobFields{WorkerID: w.id}
	if err := w.st.SetJobState(ctx, jobID, pb.JobState_JOB_STATE_DONE, done); err != nil {
		return fmt.Errorf("set DONE: %w: %w", errWrite, err)
	}
	return nil
}

// debugSleep blocks for w.dbg.Sleep, or until ctx ends. A bare time.Sleep
// would ignore the job's deadline and SIGTERM. Returning ctx.Err() means a
// cut-short sleep counts as a timeout in Handle, like any slow job.
func (w *Worker) debugSleep(ctx context.Context, jobID string) error {
	d := w.dbg.Sleep
	if d <= 0 {
		return nil
	}
	// This line is the cue in the demo: once you see it, kill this worker.
	// (w.logger already carries worker_id.)
	w.logger.Info("debug sleep: job is RUNNING, kill this worker now to test reclaim",
		"job_id", jobID, "sleep", d.String())

	t := time.NewTimer(d)
	defer t.Stop() // release the timer if ctx ends first
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("debug sleep: %w", ctx.Err())
	}
}
