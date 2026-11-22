package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

// These tests pin down the two decisions Day 2 is about:
//   - Handle: after one attempt, is the entry acked or left pending for reclaim?
//   - reclaim: for an entry claimed from the PEL, ack, retry, or dead-letter?
// A wrong answer either loses a job (acked too early) or retries it forever.

// harness is one worker on an in-memory Redis.
type harness struct {
	t   *testing.T
	m   *miniredis.Miniredis
	rdb *redis.Client
	st  *store.Store
	w   *Worker
	now time.Time // miniredis's pinned clock; advance moves it
}

func newHarness(t *testing.T, dbg Debug) *harness {
	t.Helper()
	m := miniredis.RunT(t)
	// Pin miniredis's clock so PEL idle times only move when advance is called.
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	m.SetTime(now)
	// No retries: the outage tests stop the server, and go-redis's default
	// 3 retries with backoff would only slow them down.
	rdb := redis.NewClient(&redis.Options{Addr: m.Addr(), MaxRetries: -1})
	t.Cleanup(func() { rdb.Close() })

	st, err := store.New(rdb, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	q := queue.NewConsumer(rdb, "worker-test")
	if err := q.EnsureGroup(context.Background()); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &harness{t: t, m: m, rdb: rdb, st: st, w: New(st, q, "worker-test", logger, dbg), now: now}
}

// submit does what the API does (email, QUEUED, XADD), then reads the entry
// as a worker would, so it sits in the PEL exactly as in production.
func (h *harness) submit(jobID string, withEmail bool) queue.Job {
	h.t.Helper()
	ctx := context.Background()
	if withEmail {
		if err := h.st.PutEmail(ctx, jobID, []byte("From: a@example.com\r\n\r\nhi\r\n")); err != nil {
			h.t.Fatalf("PutEmail: %v", err)
		}
	}
	if err := h.st.SetJobState(ctx, jobID, pb.JobState_JOB_STATE_QUEUED, store.JobFields{Filename: jobID + ".eml"}); err != nil {
		h.t.Fatalf("SetJobState(QUEUED): %v", err)
	}
	if _, err := queue.NewProducer(h.rdb).Enqueue(ctx, jobID); err != nil {
		h.t.Fatalf("Enqueue: %v", err)
	}
	job, err := h.w.q.Next(ctx)
	if err != nil {
		h.t.Fatalf("Next: %v", err)
	}
	return job
}

// setJob overwrites state and attempts directly, to put a job in the exact
// shape a reclaim case needs.
func (h *harness) setJob(jobID string, state pb.JobState, attempts string, errMsg string) {
	h.t.Helper()
	key := "phishcheck:job:" + jobID
	h.m.HSet(key, "state", state.String(), "attempts", attempts)
	if errMsg != "" {
		h.m.HSet(key, "error", errMsg)
	}
}

func (h *harness) job(jobID string) *store.Job {
	h.t.Helper()
	j, err := h.st.GetJob(context.Background(), jobID)
	if err != nil {
		h.t.Fatalf("GetJob(%s): %v", jobID, err)
	}
	return j
}

func (h *harness) pending() int64 {
	h.t.Helper()
	p, err := h.rdb.XPending(context.Background(), queue.Stream, queue.Group).Result()
	if err != nil {
		h.t.Fatalf("XPENDING: %v", err)
	}
	return p.Count
}

func (h *harness) dead() []redis.XMessage {
	h.t.Helper()
	msgs, err := h.rdb.XRange(context.Background(), queue.DeadStream, "-", "+").Result()
	if err != nil {
		h.t.Fatalf("XRANGE dead: %v", err)
	}
	return msgs
}

// outage runs fn while Redis is down, then brings it back with its data.
//
// Stopping the server, not miniredis.SetError: SetError rejects commands
// only while it's set. go-redis gives up on a MULTI/EXEC after the first
// error reply, so clearing the error afterwards let the commands still in
// miniredis's buffer (HINCRBY, EXPIRE) run outside the transaction. That
// made the write-failure test flaky (about half of runs) with a state real
// Redis can't produce. A stopped server runs nothing.
func (h *harness) outage(fn func()) {
	h.t.Helper()
	h.m.Close()
	fn()
	if err := h.m.Restart(); err != nil {
		h.t.Fatalf("miniredis Restart: %v", err)
	}
}

// advance moves miniredis's clock past ReclaimMinIdle, so every pending
// entry becomes claimable, as if 61 s had passed.
func (h *harness) advance() {
	h.now = h.now.Add(ReclaimMinIdle + time.Second)
	h.m.SetTime(h.now)
}

// ---- Handle: the ack decision ----

func TestHandleSuccessAcks(t *testing.T) {
	h := newHarness(t, Debug{})
	job := h.submit("job-1", true)

	h.w.Handle(context.Background(), job)

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_DONE || j.Attempts != 1 || j.WorkerID != "worker-test" {
		t.Errorf("job = %+v; want DONE, attempts 1, worker-test", j)
	}
	if _, err := h.st.GetReport(context.Background(), "job-1"); err != nil {
		t.Errorf("GetReport: %v; DONE must mean the report exists", err)
	}
	if n := h.pending(); n != 0 {
		t.Errorf("pending = %d, want 0 (acked)", n)
	}
}

// An ordinary error (here: the email expired) is final. FAILED + XACK, no retry.
func TestHandleErrorFailsAndAcks(t *testing.T) {
	h := newHarness(t, Debug{})
	job := h.submit("job-1", false) // no email stored

	h.w.Handle(context.Background(), job)

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_FAILED || j.Error == "" || j.FinishedAt.IsZero() {
		t.Errorf("job = %+v; want FAILED with an error and finished_at", j)
	}
	if n := h.pending(); n != 0 {
		t.Errorf("pending = %d, want 0 (acked)", n)
	}
}

// A panic is not acked: reclaim retries it and dead-letters at MaxAttempts
// (§2.5). The job stays RUNNING, so WatchReport doesn't end early, but the
// reason is recorded for the dead-letter entry.
func TestHandlePanicLeavesPending(t *testing.T) {
	h := newHarness(t, Debug{Panic: true})
	job := h.submit("job-1", true)

	h.w.Handle(context.Background(), job) // must not crash the test process

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_RUNNING || j.Attempts != 1 || j.Error == "" {
		t.Errorf("job = %+v; want RUNNING, attempts 1, error recorded", j)
	}
	if n := h.pending(); n != 1 {
		t.Errorf("pending = %d, want 1 (not acked)", n)
	}
}

// If Redis refuses the write, the outcome is not recorded, so the entry
// must stay pending for reclaim (§2.2 step 4).
func TestHandleRedisWriteFailureLeavesPending(t *testing.T) {
	h := newHarness(t, Debug{})
	job := h.submit("job-1", true)

	h.outage(func() { h.w.Handle(context.Background(), job) })

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_QUEUED || j.Attempts != 0 {
		t.Errorf("job = %+v; want untouched (QUEUED, attempts 0)", j)
	}
	if n := h.pending(); n != 1 {
		t.Errorf("pending = %d, want 1 (not acked)", n)
	}
}

// A timeout is final, like an ordinary error: FAILED with the reason, then
// XACK. The FAILED write and the XACK run on their own deadline
// (FinishTimeout), so they still work after the job's deadline has passed.
func TestHandleTimeoutFailsAndAcks(t *testing.T) {
	h := newHarness(t, Debug{Sleep: 5 * time.Second}) // stalls past the timeout
	h.w.jobTimeout = 100 * time.Millisecond
	job := h.submit("job-1", true)

	start := time.Now()
	h.w.Handle(context.Background(), job)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Handle took %s; the sleep should have been cut at the timeout", d)
	}

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_FAILED || !strings.Contains(j.Error, "timed out after 100ms") {
		t.Errorf("job = %s, error %q; want FAILED with a timed-out reason", j.State, j.Error)
	}
	if n := h.pending(); n != 0 {
		t.Errorf("pending = %d, want 0 (acked)", n)
	}
}

// If a worker can hold an entry longer than ReclaimMinIdle, another worker
// can claim it while it's still running, and the job runs twice.
func TestMaxHoldTimeBelowMinIdle(t *testing.T) {
	if MaxHoldTime >= ReclaimMinIdle {
		t.Fatalf("MaxHoldTime %s (read %s + job %s + finish %s) must be below ReclaimMinIdle %s",
			MaxHoldTime, ReclaimReadTimeout, JobTimeout, FinishTimeout, ReclaimMinIdle)
	}
}

// ---- reclaim: the case order ----

func TestReclaimCases(t *testing.T) {
	tests := []struct {
		name     string
		state    pb.JobState
		attempts string
		errMsg   string

		wantState    pb.JobState
		wantAttempts int32
		wantDead     bool
	}{
		{
			// Only the XACK was lost. Redoing the work would bump attempts.
			name: "DONE is acked, not rerun", state: pb.JobState_JOB_STATE_DONE, attempts: "1",
			wantState: pb.JobState_JOB_STATE_DONE, wantAttempts: 1,
		},
		{
			// DONE beats the attempts limit: finished work is never dead-lettered.
			name: "DONE at max attempts is still just acked", state: pb.JobState_JOB_STATE_DONE, attempts: "3",
			wantState: pb.JobState_JOB_STATE_DONE, wantAttempts: 3,
		},
		{
			name: "RUNNING at max attempts is dead-lettered", state: pb.JobState_JOB_STATE_RUNNING, attempts: "3",
			errMsg:    "handler panicked: boom",
			wantState: pb.JobState_JOB_STATE_FAILED, wantAttempts: 3, wantDead: true,
		},
		{
			// An ordinary error on attempt 3 whose XACK was lost. It's a
			// recorded failure, not a poison job, so it's acked like on any
			// other attempt. The FAILED check must come before the attempts
			// check for this. That's safe because giveUp writes FAILED in the
			// same transaction as the dead-letter record and the XACK, so it
			// never leaves a FAILED entry pending.
			name: "FAILED at max attempts is acked, not dead-lettered", state: pb.JobState_JOB_STATE_FAILED, attempts: "3",
			errMsg:    "get email: key not found",
			wantState: pb.JobState_JOB_STATE_FAILED, wantAttempts: 3,
		},
		{
			// fail() wrote FAILED, then its XACK was lost.
			name: "FAILED under max attempts is acked, not rerun", state: pb.JobState_JOB_STATE_FAILED, attempts: "1",
			errMsg:    "get email: key not found",
			wantState: pb.JobState_JOB_STATE_FAILED, wantAttempts: 1,
		},
		{
			// The §2.4 crash: a worker died mid-job.
			name: "RUNNING under max attempts is retried", state: pb.JobState_JOB_STATE_RUNNING, attempts: "1",
			wantState: pb.JobState_JOB_STATE_DONE, wantAttempts: 2,
		},
		{
			// A worker read the entry and died before StartAttempt.
			name: "QUEUED is retried", state: pb.JobState_JOB_STATE_QUEUED, attempts: "0",
			wantState: pb.JobState_JOB_STATE_DONE, wantAttempts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Debug{})
			job := h.submit("job-1", true)
			h.setJob("job-1", tt.state, tt.attempts, tt.errMsg)

			h.w.reclaim(context.Background(), job)

			j := h.job("job-1")
			if j.State != tt.wantState || j.Attempts != tt.wantAttempts {
				t.Errorf("job = %s, attempts %d; want %s, attempts %d",
					j.State, j.Attempts, tt.wantState, tt.wantAttempts)
			}
			if n := h.pending(); n != 0 {
				t.Errorf("pending = %d, want 0 (every case here ends acked)", n)
			}

			dead := h.dead()
			if !tt.wantDead {
				if len(dead) != 0 {
					t.Errorf("dead stream has %d entries, want 0", len(dead))
				}
				return
			}
			if len(dead) != 1 {
				t.Fatalf("dead stream has %d entries, want 1", len(dead))
			}
			if got := dead[0].Values["error"]; got != tt.errMsg {
				t.Errorf("dead entry error = %v, want %q (the last recorded error)", got, tt.errMsg)
			}
			if got := dead[0].Values["attempts"]; got != tt.attempts {
				t.Errorf("dead entry attempts = %v, want %s", got, tt.attempts)
			}
		})
	}
}

// The job hash expired, so there is nothing to run. Dead-letter it, and
// don't recreate the hash by writing FAILED.
func TestReclaimMissingJobIsDeadLettered(t *testing.T) {
	h := newHarness(t, Debug{})
	job := h.submit("job-1", true)
	h.m.Del("phishcheck:job:job-1")

	h.w.reclaim(context.Background(), job)

	if _, err := h.st.GetJob(context.Background(), "job-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetJob: err = %v; want ErrNotFound (hash must not be recreated)", err)
	}
	if n := h.pending(); n != 0 {
		t.Errorf("pending = %d, want 0", n)
	}
	if dead := h.dead(); len(dead) != 1 || dead[0].Values["attempts"] != "0" {
		t.Errorf("dead stream = %+v; want 1 entry with attempts 0", dead)
	}
}

// A Redis read error tells reclaim nothing, so the entry stays pending.
func TestReclaimReadErrorLeavesPending(t *testing.T) {
	h := newHarness(t, Debug{})
	job := h.submit("job-1", true)

	h.outage(func() { h.w.reclaim(context.Background(), job) })

	if n := h.pending(); n != 1 {
		t.Errorf("pending = %d, want 1", n)
	}
	if dead := h.dead(); len(dead) != 0 {
		t.Errorf("dead stream has %d entries, want 0", len(dead))
	}
}

// ---- end to end: the two Day 2 "Done when" checks, without real waits ----

// §2.5: a job that panics three times lands in the dead-letter stream.
func TestPanicThreeTimesIsDeadLettered(t *testing.T) {
	h := newHarness(t, Debug{Panic: true})
	job := h.submit("job-1", true)

	h.w.Handle(context.Background(), job) // attempt 1, from the main loop
	for pass := 1; pass <= 3; pass++ {    // attempts 2 and 3, then give up
		if n := h.pending(); n != 1 {
			t.Fatalf("before pass %d: pending = %d, want 1", pass, n)
		}
		h.advance()
		h.w.reclaimPass(context.Background())
	}

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_FAILED || j.Attempts != MaxAttempts {
		t.Errorf("job = %s, attempts %d; want FAILED, attempts %d", j.State, j.Attempts, MaxAttempts)
	}
	if n := h.pending(); n != 0 {
		t.Errorf("pending = %d, want 0", n)
	}
	if dead := h.dead(); len(dead) != 1 {
		t.Errorf("dead stream has %d entries, want exactly 1", len(dead))
	}

	// A later pass finds nothing: no second dead-letter entry, no extra attempt.
	h.advance()
	h.w.reclaimPass(context.Background())
	if dead := h.dead(); len(dead) != 1 {
		t.Errorf("after an extra pass: dead stream has %d entries, want 1", len(dead))
	}
}

// §2.4: a worker dies mid-job, and another worker's reclaim pass finishes it
// with attempts 2 and its own worker_id. Also checks that reclaim leaves an
// entry alone until it has been idle for ReclaimMinIdle.
func TestCrashedJobIsReclaimedByAnotherWorker(t *testing.T) {
	h := newHarness(t, Debug{})
	ctx := context.Background()

	// worker-a reads the job, marks it RUNNING, then is killed (no Handle, no ack).
	if err := h.st.PutEmail(ctx, "job-1", []byte("From: a@example.com\r\n\r\nhi\r\n")); err != nil {
		t.Fatalf("PutEmail: %v", err)
	}
	if err := h.st.SetJobState(ctx, "job-1", pb.JobState_JOB_STATE_QUEUED, store.JobFields{}); err != nil {
		t.Fatalf("SetJobState: %v", err)
	}
	if _, err := queue.NewProducer(h.rdb).Enqueue(ctx, "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := queue.NewConsumer(h.rdb, "worker-a").Next(ctx); err != nil {
		t.Fatalf("worker-a Next: %v", err)
	}
	if _, err := h.st.StartAttempt(ctx, "job-1", "worker-a"); err != nil {
		t.Fatalf("StartAttempt: %v", err)
	}

	// Too soon: the entry hasn't been idle 60 s, so it's left with worker-a.
	h.w.reclaimPass(ctx)
	if j := h.job("job-1"); j.State != pb.JobState_JOB_STATE_RUNNING || j.WorkerID != "worker-a" {
		t.Fatalf("before MinIdle: job = %+v; want still RUNNING on worker-a", j)
	}

	h.advance()
	h.w.reclaimPass(ctx) // h.w is worker-test, standing in for worker B

	j := h.job("job-1")
	if j.State != pb.JobState_JOB_STATE_DONE || j.Attempts != 2 || j.WorkerID != "worker-test" {
		t.Errorf("job = %s, attempts %d, worker %s; want DONE, attempts 2, worker-test",
			j.State, j.Attempts, j.WorkerID)
	}
	r, err := h.st.GetReport(ctx, "job-1")
	if err != nil || r.GetWorkerId() != "worker-test" {
		t.Errorf("report = %v, %v; want worker_id worker-test", r, err)
	}
	if n := h.pending(); n != 0 {
		t.Errorf("pending = %d, want 0", n)
	}
}
