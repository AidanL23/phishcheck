package store

import (
	"context"
	"errors"
	"fmt"
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
)

type Store struct {
	rdb *redis.Client
	ttl time.Duration
}

func New(rdb *redis.Client, ttl time.Duration) (*Store, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("store: ttl must be positive, got %s", ttl)
	}
	return &Store{rdb: rdb, ttl: ttl}, nil
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
}

// SetJobState updates the job hash at phishcheck:job:{id} and refreshes its TTL.
// Empty fields in f are skipped, so earlier values (like filename) are kept.
func (s *Store) SetJobState(ctx context.Context, id string, state pb.JobState, f JobFields) error {
	values := map[string]any{fieldState: state.String()} // stored as "JOB_STATE_QUEUED for readability"

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
	// HSET takes no TTL, so EXPIRE follows it. MULTI/EXEC applies both or neither,
	// so the hash can never be left without an expiry.
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, key, values)
		p.Expire(ctx, key, s.ttl)
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: set job %s to %s: %w", id, state, err)
	}
	return nil
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

	return &Job{
		ID:       id,
		State:    pb.JobState(state),
		WorkerID: m[fieldWorkerID],
		Error:    m[fieldError],
		Filename: m[fieldFilename],
		SHA256:   m[fieldSHA256],
	}, nil
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
