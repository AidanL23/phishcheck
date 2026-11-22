//go:build integration

package queue

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Runs against a real Redis, because miniredis drops a trimmed pending entry
// without reporting it, and that report is exactly what this tests.
//
//	REDIS_ADDR=localhost:6379 go test -tags integration ./internal/queue/
//
// It uses DB 15 and flushes only that DB, so the Compose Redis's data in DB 0
// is left alone.
func newIntegrationRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	ctx := context.Background()
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("FLUSHDB on DB 15: %v", err)
	}
	t.Cleanup(func() {
		rdb.FlushDB(context.Background())
		rdb.Close()
	})
	return rdb
}

// A pending entry trimmed off the stream (MAXLEN on Enqueue) must come back
// in Trimmed. Redis 7 removes it from the PEL as it reports it, so if Claim
// dropped it, the job would be lost with no trace.
func TestClaimReportsTrimmedPendingEntry(t *testing.T) {
	ctx := context.Background()
	rdb := newIntegrationRedis(t)
	a := newConsumer(t, rdb, "worker-a")
	b := newConsumer(t, rdb, "worker-b")

	if _, err := NewProducer(rdb).Enqueue(ctx, "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	job, err := a.Next(ctx) // pending on worker-a, which then "dies"
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if err := rdb.XTrimMaxLen(ctx, Stream, 0).Err(); err != nil { // what MAXLEN does under load
		t.Fatalf("XTRIM: %v", err)
	}

	res, err := b.Claim(ctx, "0-0", 0)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if len(res.Jobs) != 0 || len(res.Trimmed) != 1 || res.Trimmed[0] != job.StreamID {
		t.Fatalf("Claim = %+v; want Trimmed [%s] and no jobs", res, job.StreamID)
	}
	if n := pendingCount(t, rdb); n != 0 {
		t.Errorf("pending = %d, want 0 (Redis 7 drops it as it reports it)", n)
	}
}

// The panic-demo guard (cmd/worker) depends on consumer idle times, which
// miniredis doesn't track for XREADGROUP (it reports -1, "always active").
func TestOtherActiveConsumers(t *testing.T) {
	ctx := context.Background()
	rdb := newIntegrationRedis(t)

	a := newConsumer(t, rdb, "worker-a")
	demo := newConsumer(t, rdb, "panic-demo")
	if _, err := NewProducer(rdb).Enqueue(ctx, "job-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := a.Next(ctx); err != nil { // worker-a is live: it just read
		t.Fatalf("Next: %v", err)
	}

	got, err := demo.OtherActiveConsumers(ctx, time.Minute)
	if err != nil || len(got) != 1 || got[0] != "worker-a" {
		t.Fatalf("OtherActiveConsumers = %v, %v; want [worker-a]", got, err)
	}

	// Quiet for longer than `within`: worker-a counts as gone (killed or
	// stopped). 200 ms stands in for the real 60 s.
	time.Sleep(200 * time.Millisecond)
	got, err = demo.OtherActiveConsumers(ctx, 100*time.Millisecond)
	if err != nil || len(got) != 0 {
		t.Fatalf("after 200 ms quiet: OtherActiveConsumers = %v, %v; want none", got, err)
	}
}
