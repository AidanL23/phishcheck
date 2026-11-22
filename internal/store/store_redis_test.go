package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
)

const testTTL = 7 * 24 * time.Hour // the production default (PHISHCHECK_TTL=168h)

// fixedNow is every test store's clock. Nanoseconds included, to prove
// RFC3339Nano keeps full precision.
var fixedNow = time.Date(2026, 11, 21, 15, 4, 5, 123456789, time.UTC)

// newTestStore starts an in-memory Redis for one test and returns a Store
// on it. RunT stops the server when the test ends.
func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	m := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { rdb.Close() })

	s, err := New(rdb, testTTL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.now = func() time.Time { return fixedNow }
	return s, m
}

func TestEmailRoundTripAndExpiry(t *testing.T) {
	s, m := newTestStore(t)
	ctx := context.Background()
	raw := []byte("From: a@example.com\r\n\r\nhi\r\n") // CRLF on purpose: bytes must come back unchanged

	if err := s.PutEmail(ctx, "job-1", raw); err != nil {
		t.Fatalf("PutEmail: %v", err)
	}
	got, err := s.GetEmail(ctx, "job-1")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("GetEmail = %q, %v; want %q", got, err, raw)
	}

	// The TTL is what stops raw emails piling up in Redis.
	if ttl := m.TTL(emailKey("job-1")); ttl != testTTL {
		t.Errorf("email TTL = %s, want %s", ttl, testTTL)
	}

	// miniredis never expires keys by itself; FastForward ages every TTL.
	m.FastForward(testTTL)
	if _, err := s.GetEmail(ctx, "job-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetEmail after TTL: err = %v, want ErrNotFound", err)
	}
}

func TestJobLifecycle(t *testing.T) {
	s, m := newTestStore(t)
	ctx := context.Background()
	key := jobKey("job-1")

	// QUEUED: what the API writes when it accepts an upload.
	err := s.SetJobState(ctx, "job-1", pb.JobState_JOB_STATE_QUEUED,
		JobFields{Filename: "clean.eml", SHA256: "abc123"})
	if err != nil {
		t.Fatalf("SetJobState(QUEUED): %v", err)
	}
	// HSET sets no TTL; this fails if the EXPIRE in the transaction goes missing.
	if ttl := m.TTL(key); ttl != testTTL {
		t.Errorf("job TTL after QUEUED = %s, want %s", ttl, testTTL)
	}

	// Age the hash first, so the check below proves StartAttempt refreshes the TTL.
	m.FastForward(testTTL / 2)
	n, err := s.StartAttempt(ctx, "job-1", "worker-ab12")
	if err != nil || n != 1 {
		t.Fatalf("StartAttempt = %d, %v; want 1, nil", n, err)
	}
	if ttl := m.TTL(key); ttl != testTTL {
		t.Errorf("job TTL after StartAttempt = %s, want %s (refreshed)", ttl, testTTL)
	}

	// DONE sets only WorkerID. Empty fields must not wipe filename or sha256.
	err = s.SetJobState(ctx, "job-1", pb.JobState_JOB_STATE_DONE, JobFields{WorkerID: "worker-ab12"})
	if err != nil {
		t.Fatalf("SetJobState(DONE): %v", err)
	}

	j, err := s.GetJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if j.State != pb.JobState_JOB_STATE_DONE || j.WorkerID != "worker-ab12" ||
		j.Filename != "clean.eml" || j.SHA256 != "abc123" || j.Attempts != 1 {
		t.Errorf("GetJob = %+v", j)
	}
	// Each state stamped its own field; all three survive the string round trip.
	for name, ts := range map[string]time.Time{
		"submitted_at": j.SubmittedAt, "started_at": j.StartedAt, "finished_at": j.FinishedAt,
	} {
		if !ts.Equal(fixedNow) {
			t.Errorf("%s = %s, want %s", name, ts, fixedNow)
		}
	}
}

// A retry is what reclaim does after a crash or failure. The new attempt
// must not carry the last one's error or finish time.
func TestStartAttemptRetryClearsLastFailure(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if _, err := s.StartAttempt(ctx, "job-1", "worker-a"); err != nil {
		t.Fatalf("first StartAttempt: %v", err)
	}
	if err := s.SetJobState(ctx, "job-1", pb.JobState_JOB_STATE_FAILED, JobFields{Error: "boom"}); err != nil {
		t.Fatalf("SetJobState(FAILED): %v", err)
	}

	n, err := s.StartAttempt(ctx, "job-1", "worker-b")
	if err != nil || n != 2 {
		t.Fatalf("second StartAttempt = %d, %v; want 2, nil", n, err)
	}

	j, err := s.GetJob(ctx, "job-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if j.State != pb.JobState_JOB_STATE_RUNNING || j.WorkerID != "worker-b" ||
		j.Attempts != 2 || j.Error != "" || !j.FinishedAt.IsZero() {
		t.Errorf("after retry: %+v", j)
	}
}

func TestGetJobErrors(t *testing.T) {
	s, m := newTestStore(t)
	ctx := context.Background()

	// HGETALL returns an empty map, not redis.Nil, for a missing key.
	if _, err := s.GetJob(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetJob(missing): err = %v, want ErrNotFound", err)
	}

	// An unknown state is corruption. Calling it "not found" would hide it.
	m.HSet(jobKey("bad"), fieldState, "JOB_STATE_BOGUS")
	if _, err := s.GetJob(ctx, "bad"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("GetJob(bad state): err = %v, want a non-ErrNotFound error", err)
	}
}

func TestReportRoundTrip(t *testing.T) {
	s, m := newTestStore(t)
	ctx := context.Background()

	want := &pb.Report{
		JobId:    "job-1",
		Verdict:  pb.Verdict_VERDICT_SUSPICIOUS,
		Score:    35,
		WorkerId: "worker-ab12",
		Findings: []*pb.Finding{{
			RuleId:   "REPLY_TO_MISMATCH",
			Severity: pb.Severity_SEVERITY_MEDIUM,
			Evidence: "From: a@x.com; Reply-To: b@y.net",
		}},
	}
	if err := s.PutReport(ctx, "job-1", want); err != nil {
		t.Fatalf("PutReport: %v", err)
	}

	got, err := s.GetReport(ctx, "job-1")
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	// proto.Equal, not ==: generated messages hold internal state that breaks plain comparison.
	if !proto.Equal(got, want) {
		t.Errorf("GetReport = %v, want %v", got, want)
	}
	if ttl := m.TTL(reportKey("job-1")); ttl != testTTL {
		t.Errorf("report TTL = %s, want %s", ttl, testTTL)
	}

	if _, err := s.GetReport(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetReport(missing): err = %v, want ErrNotFound", err)
	}
}
