package queue

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedis starts an in-memory Redis for one test. RunT stops it when the test ends.
func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	m := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return rdb
}

// newConsumer returns a consumer whose group exists, as a worker has after startup.
func newConsumer(t *testing.T, rdb *redis.Client, name string) *Consumer {
	t.Helper()
	c := NewConsumer(rdb, name)
	if err := c.EnsureGroup(context.Background()); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	return c
}

// pendingCount is the size of the group's PEL: entries read but not acked.
func pendingCount(t *testing.T, rdb *redis.Client) int64 {
	t.Helper()
	p, err := rdb.XPending(context.Background(), Stream, Group).Result()
	if err != nil {
		t.Fatalf("XPENDING: %v", err)
	}
	return p.Count
}

func TestEnqueueNextAck(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)
	c := newConsumer(t, rdb, "worker-a")

	streamID, err := NewProducer(rdb).Enqueue(ctx, "job-1")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Claim check: the entry holds the job ID and nothing else, never the email.
	msgs, err := rdb.XRange(ctx, Stream, "-", "+").Result()
	if err != nil || len(msgs) != 1 || len(msgs[0].Values) != 1 || msgs[0].Values[fieldJobID] != "job-1" {
		t.Fatalf("stream = %+v, %v; want one entry with only job_id", msgs, err)
	}

	job, err := c.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if job != (Job{StreamID: streamID, JobID: "job-1"}) {
		t.Fatalf("Next = %+v, want job-1 at %s", job, streamID)
	}

	// Read but not acked: it waits in the PEL. Reclaim depends on this.
	if n := pendingCount(t, rdb); n != 1 {
		t.Errorf("pending before Ack = %d, want 1", n)
	}
	if err := c.Ack(ctx, job.StreamID); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if n := pendingCount(t, rdb); n != 0 {
		t.Errorf("pending after Ack = %d, want 0", n)
	}
}

func TestEnsureGroupIsIdempotentAndKeepsEarlierJobs(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	// The API can accept a job before any worker has created the group.
	if _, err := NewProducer(rdb).Enqueue(ctx, "early"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	c := NewConsumer(rdb, "worker-a")
	for i := 1; i <= 2; i++ { // the second call returns BUSYGROUP, which must be ignored
		if err := c.EnsureGroup(ctx); err != nil {
			t.Fatalf("EnsureGroup call %d: %v", i, err)
		}
	}

	// The group starts at "0", not "$", so the earlier job is still delivered.
	job, err := c.Next(ctx)
	if err != nil || job.JobID != "early" {
		t.Fatalf("Next = %+v, %v; want job early", job, err)
	}
}

func TestNextAcksMalformedEntry(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)
	c := newConsumer(t, rdb, "worker-a")

	// Written straight to the stream, because Enqueue refuses an empty ID.
	if err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: Stream, Values: map[string]any{"wrong": "x"}}).Err(); err != nil {
		t.Fatalf("XAdd: %v", err)
	}

	if _, err := c.Next(ctx); !errors.Is(err, ErrMalformedEntry) {
		t.Fatalf("Next: err = %v, want ErrMalformedEntry", err)
	}
	// Acked at once, or every reclaim pass would claim it again forever.
	if n := pendingCount(t, rdb); n != 0 {
		t.Errorf("pending = %d, want 0", n)
	}
}

func TestClaimTakesOnlyIdleEntries(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)
	a := newConsumer(t, rdb, "worker-a")
	b := newConsumer(t, rdb, "worker-b")

	if _, err := NewProducer(rdb).Enqueue(ctx, "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// worker-a reads the job, then "dies" without acking.
	if _, err := a.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}

	// Delivered milliseconds ago, so it can't be idle a minute yet.
	res, err := b.Claim(ctx, "0-0", time.Minute)
	if err != nil || len(res.Jobs) != 0 {
		t.Fatalf("Claim(1m) = %+v, %v; want nothing", res, err)
	}

	// A min idle of 0 makes every pending entry claimable: it stands in for 60 s passing.
	res, err = b.Claim(ctx, "0-0", 0)
	if err != nil || len(res.Jobs) != 1 || res.Jobs[0].JobID != "job-1" || res.Next != "0-0" {
		t.Fatalf("Claim(0) = %+v, %v; want job-1 and a finished scan", res, err)
	}
	if len(res.Trimmed) != 0 || len(res.Malformed) != 0 {
		t.Errorf("Claim(0) = %+v; want no trimmed or malformed entries", res)
	}

	// Still pending (not acked) but now owned by worker-b.
	ext, err := rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: Stream, Group: Group, Start: "-", End: "+", Count: 10,
	}).Result()
	if err != nil || len(ext) != 1 || ext[0].Consumer != "worker-b" {
		t.Errorf("PEL = %+v, %v; want one entry owned by worker-b", ext, err)
	}
}

func TestDeadLetterRecordsAndAcks(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)
	c := newConsumer(t, rdb, "worker-a")

	if _, err := NewProducer(rdb).Enqueue(ctx, "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	job, err := c.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	// also's commands commit in the same transaction (the worker writes FAILED this way).
	also := func(p redis.Pipeliner) { p.HSet(ctx, "phishcheck:job:job-1", "state", "JOB_STATE_FAILED") }
	if err := c.DeadLetter(ctx, job, 3, "handler panicked", also); err != nil {
		t.Fatalf("DeadLetter: %v", err)
	}
	if got := rdb.HGet(ctx, "phishcheck:job:job-1", "state").Val(); got != "JOB_STATE_FAILED" {
		t.Errorf("job state = %q; want the also command applied", got)
	}

	// The original is acked, so reclaim stops retrying it.
	if n := pendingCount(t, rdb); n != 0 {
		t.Errorf("pending = %d, want 0", n)
	}

	// The dead-letter entry carries what an analyst needs to triage it.
	dead, err := rdb.XRange(ctx, DeadStream, "-", "+").Result()
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead stream = %+v, %v; want 1 entry", dead, err)
	}
	want := map[string]string{
		fieldJobID:          "job-1",
		fieldStreamID:       job.StreamID,
		fieldAttempts:       "3", // Redis stores every field value as a string
		fieldError:          "handler panicked",
		fieldDeadLetteredBy: "worker-a",
	}
	for k, v := range want {
		if got := dead[0].Values[k]; got != v {
			t.Errorf("dead entry %s = %v, want %q", k, got, v)
		}
	}
}

func TestClaimAcksAndReportsMalformedEntry(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)
	b := newConsumer(t, rdb, "worker-b")

	// worker-a reads it straight from Redis, so Next doesn't ack it first.
	if err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: Stream, Values: map[string]any{"wrong": "x"}}).Err(); err != nil {
		t.Fatalf("XAdd: %v", err)
	}
	if err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group: Group, Consumer: "worker-a", Streams: []string{Stream, ">"}, Count: 1,
	}).Err(); err != nil {
		t.Fatalf("XREADGROUP: %v", err)
	}

	res, err := b.Claim(ctx, "0-0", 0)
	if err != nil || len(res.Jobs) != 0 || len(res.Malformed) != 1 {
		t.Fatalf("Claim = %+v, %v; want one malformed entry and no jobs", res, err)
	}
	// Acked, or every pass would claim it again. Reported, so it gets a log line.
	if n := pendingCount(t, rdb); n != 0 {
		t.Errorf("pending = %d, want 0", n)
	}
}

// Pins down what §2.7 gets wrong: go-redis does not cut a blocking
// XREADGROUP short when the context is cancelled. Next waits out the BLOCK
// and returns ErrNoJob, and the worker loop then exits at its ctx check. So
// shutdown can take up to blockFor (5 s) longer than the in-flight job.
func TestNextIgnoresCancelUntilBlockEnds(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 5 s BLOCK")
	}
	rdb := newTestRedis(t)
	c := newConsumer(t, rdb, "worker-a")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.Next(ctx)
	d := time.Since(start)

	if !errors.Is(err, ErrNoJob) {
		t.Errorf("Next: err = %v, want ErrNoJob (the BLOCK timing out)", err)
	}
	if d < blockFor-500*time.Millisecond {
		t.Errorf("Next returned after %s; go-redis now unblocks on cancel, so update the "+
			"stepStop comment in cmd/worker and this test", d)
	}
}

func TestNextReturnsErrNoJobWhenIdle(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 5 s BLOCK")
	}
	rdb := newTestRedis(t)
	c := newConsumer(t, rdb, "worker-a")

	start := time.Now()
	if _, err := c.Next(context.Background()); !errors.Is(err, ErrNoJob) {
		t.Fatalf("Next on empty stream: err = %v, want ErrNoJob", err)
	}
	// It must wait out the BLOCK. Returning at once would make the worker loop spin.
	if d := time.Since(start); d < blockFor-500*time.Millisecond {
		t.Errorf("Next returned after %s, want about %s", d, blockFor)
	}
}
