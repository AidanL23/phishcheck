package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
)

// ErrNotFound means the key never existed or its TTL ran out
var ErrNotFound = errors.New("key not found")

const prefix = "phishcheck:"

func emailKey(id string) string  { return prefix + "email:" + id }
func jobKey(id string) string    { return prefix + "job:" + id }
func reportKey(id string) string { return prefix + "report:" + id }

// Field names in the phishcheck:job:{id} hash
const (
	fieldState    = "state"
	fieldWorkerID = "worker_id"
	fieldError    = "error"
	fieldFilename = "filename"
	fieldSHA256   = "sha256"
	fieldAttempts = "attempts"

	// Timestamps, as RFC 3339 strings in UTC (§2.6).
	fieldSubmittedAt = "submitted_at"
	fieldStartedAt   = "started_at"
	fieldFinishedAt  = "finished_at"
)

// timeLayout is RFC 3339 with fractional seconds. Plain time.RFC3339 stops
// at whole seconds, so every offset --wait prints would be a whole number.
const timeLayout = time.RFC3339Nano

type Store struct {
	rdb *redis.Client
	ttl time.Duration
	now func() time.Time // time.Now; tests in this package can swap in a fixed clock
}

func New(rdb *redis.Client, ttl time.Duration) (*Store, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("store: ttl must be positive, got %s", ttl)
	}
	return &Store{rdb: rdb, ttl: ttl, now: time.Now}, nil
}

// PutEmail stores the raw .eml under phishcheck:email:{id}
// The key expires after the store's TTL, so emails never pile up in Redis.
// The API calls this before enqueueing the job, so the email always exists
func (s *Store) PutEmail(ctx context.Context, id string, raw []byte) error {
	if err := s.rdb.Set(ctx, emailKey(id), raw, s.ttl).Err(); err != nil {
		return fmt.Errorf("store: put email: %s: %w", id, err)
	}
	return nil
}

// GetEmail returns the raw .eml for a job, or ErrNotFound if it is missing or expired
func (s *Store) GetEmail(ctx context.Context, id string) ([]byte, error) {
	b, err := s.rdb.Get(ctx, emailKey(id)).Bytes()
	if errors.Is(err, redis.Nil) { // key doesn't exist
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get email: %s: %w", id, err)
	}
	return b, nil
}

// JobFields are written only when non-empty, so a later state change
// never overwrites fields that were set earlier (RUNNING keeps the filename from QUEUED)
type JobFields struct {
	WorkerID string
	Error    string
	Filename string
	SHA256   string
}

type Job struct {
	ID       string
	State    pb.JobState
	WorkerID string
	Error    string
	Filename string
	SHA256   string
	Attempts int32

	SubmittedAt time.Time // set with QUEUED
	StartedAt   time.Time // set by StartAttempt; a retry overwrites it
	FinishedAt  time.Time // set with DONE or FAILED
}

// SetJobState updates the job hash at phishcheck:job:{id} and refreshes its TTL.
// Empty fields in f are skipped, so earlier values (like filename) are kept.
func (s *Store) SetJobState(ctx context.Context, id string, state pb.JobState, f JobFields) error {
	// HSET takes no TTL, so EXPIRE follows it. MULTI/EXEC runs the two back to
	// back with no other command in between (Redis doesn't roll back, but
	// EXPIRE can't fail on a key HSET just wrote), so the hash can never be
	// left without an expiry.
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		s.SetJobStateIn(ctx, p, id, state, f)
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: set job %s to %s: %w", id, state, err)
	}
	return nil
}

// SetJobStateIn queues SetJobState's HSET and EXPIRE on p without running
// them, so a caller can commit the state change in its own transaction
// (the worker's dead-letter step does). Errors surface when p executes.
func (s *Store) SetJobStateIn(ctx context.Context, p redis.Pipeliner, id string, state pb.JobState, f JobFields) {
	values := map[string]any{fieldState: state.String()} // stored as "JOB_STATE_QUEUED", for readability

	// The state picks the timestamp, so no caller can forget one.
	// RUNNING is stamped by StartAttempt, not here.
	switch state {
	case pb.JobState_JOB_STATE_QUEUED:
		values[fieldSubmittedAt] = s.stamp()
	case pb.JobState_JOB_STATE_DONE, pb.JobState_JOB_STATE_FAILED:
		values[fieldFinishedAt] = s.stamp()
	}

	if f.WorkerID != "" {
		values[fieldWorkerID] = f.WorkerID
	}
	if f.Error != "" {
		values[fieldError] = f.Error
	}
	if f.Filename != "" {
		values[fieldFilename] = f.Filename
	}
	if f.SHA256 != "" {
		values[fieldSHA256] = f.SHA256
	}

	key := jobKey(id)
	p.HSet(ctx, key, values)
	p.Expire(ctx, key, s.ttl)
}

// GetJob reads the job hash at phishcheck:job:{id}.
// It returns ErrNotFound if the job is missing or expired.
func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	m, err := s.rdb.HGetAll(ctx, jobKey(id)).Result()
	if err != nil {
		return nil, fmt.Errorf("store: get job: %s: %w", id, err)
	}
	// HGETALL returns an empty map, not redis.Nil, for a missing key.
	if len(m) == 0 {
		return nil, ErrNotFound
	}
	// Turn the stored name ("JOB_STATE_DONE") back into the enum value.
	state, ok := pb.JobState_value[m[fieldState]]
	if !ok {
		return nil, fmt.Errorf("store: job %s has unknown state %q", id, m[fieldState])
	}

	// attempts is missing until the first StartAttempt, which reads as 0.
	var attempts int64
	if v := m[fieldAttempts]; v != "" {
		attempts, err = strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("store: job %s has bad attempts %q: %w", id, v, err)
		}
	}

	// One error variable for all three, so a bad value in any of them fails
	// the read, like a bad attempts value does.
	var terr error
	submitted := parseTime(m, fieldSubmittedAt, &terr)
	started := parseTime(m, fieldStartedAt, &terr)
	finished := parseTime(m, fieldFinishedAt, &terr)
	if terr != nil {
		return nil, fmt.Errorf("store: job %s: %w", id, terr)
	}

	return &Job{
		ID:          id,
		State:       pb.JobState(state),
		WorkerID:    m[fieldWorkerID],
		Error:       m[fieldError],
		Filename:    m[fieldFilename],
		SHA256:      m[fieldSHA256],
		Attempts:    int32(attempts),
		SubmittedAt: submitted,
		StartedAt:   started,
		FinishedAt:  finished,
	}, nil
}

// stamp returns the current time in the format stored in the job hash.
// UTC, so the raw value reads the same in redis-cli on any machine.
func (s *Store) stamp() string {
	return s.now().UTC().Format(timeLayout)
}

// parseTime reads one timestamp field. A missing field is the zero Time,
// not an error. Only the first parse error is kept in *errp.
func parseTime(m map[string]string, field string, errp *error) time.Time {
	v := m[field]
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeLayout, v)
	if err != nil && *errp == nil {
		*errp = fmt.Errorf("bad %s %q: %w", field, v, err)
	}
	return t
}

// StartAttempt marks the job RUNNING on workerID, stamps started_at, and adds
// 1 to attempts, returning the new count. It clears the previous attempt's
// error and finished_at. started_at is overwritten each attempt.
//
// One MULTI/EXEC, so the count never changes without the state.
func (s *Store) StartAttempt(ctx context.Context, id, workerID string) (int64, error) {
	key := jobKey(id)
	var incr *redis.IntCmd // filled in when the transaction runs
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, key,
			fieldState, pb.JobState_JOB_STATE_RUNNING.String(),
			fieldWorkerID, workerID,
			fieldStartedAt, s.stamp())
		p.HDel(ctx, key, fieldError, fieldFinishedAt) // HDEL takes several fields in one call
		incr = p.HIncrBy(ctx, key, fieldAttempts, 1)
		p.Expire(ctx, key, s.ttl)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: start attempt %s: %w", id, err)
	}
	// Inside a pipeline, Val() is only valid after EXEC has returned.
	return incr.Val(), nil
}

// PutReport stores the report as protobuf bytes under phishcheck:report:{id} with the store's TTL.
// Proto bytes, not JSON, so the API can hand them back with no conversion
func (s *Store) PutReport(ctx context.Context, id string, r *pb.Report) error {
	b, err := proto.Marshal(r)
	if err != nil {
		return fmt.Errorf("store: marshal report %s: %w", id, err)
	}

	if err := s.rdb.Set(ctx, reportKey(id), b, s.ttl).Err(); err != nil {
		return fmt.Errorf("store: put report: %s: %w", id, err)
	}
	return nil
}

// GetReport returns the report for a job, or ErrNotFound if it is missing or expired.
func (s *Store) GetReport(ctx context.Context, id string) (*pb.Report, error) {
	b, err := s.rdb.Get(ctx, reportKey(id)).Bytes()
	if errors.Is(err, redis.Nil) { // Key doesn't exist.
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get report: %s: %w", id, err)
	}
	// Decode the bytes back into a Report struct
	r := &pb.Report{}
	if err := proto.Unmarshal(b, r); err != nil {
		return nil, fmt.Errorf("store: unmarshal report %s: %w", id, err)
	}
	return r, nil
}
