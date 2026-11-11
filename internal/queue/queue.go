// Package queue carries job IDs from the API to the workers on a Redis Stream.
// Only the job ID goes on the stream (claim check); the raw email lives under
// its own key in internal/store.
package queue

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// Stream is the Redis Stream that holds submitted jobs
	Stream = "phishcheck:jobs"
	// Group is the consumer group every worker joins.
	Group = "workers"

	fieldJobID = "job_id"
	maxLen     = 10000           // stream len cap
	blockFor   = 5 * time.Second // how long next waits before returning ErrNoJob
)

var (
	// ErrNoJob means Next waited blockFor and nothing arrived
	ErrNoJob = errors.New("queue: no job available")
	// ErrMalformedEntry means an entry had no job_id. Next has already acked it.
	ErrMalformedEntry = errors.New("queue: malformed entry has no job_id")
)

// Job is one entry read from the stream
type Job struct {
	StreamID string // ID Redis assigned to the entry; Ack needs it
	JobID    string // ID of the job stored in internal/store
}

// Producer appends jobs to the stream. The API uses it
type Producer struct {
	rdb redis.Cmdable
}

// NewProducer wraps a Redis client. Cmdable accepts *redis.Client and test clients.
func NewProducer(rdb redis.Cmdable) *Producer {
	return &Producer{rdb: rdb}
}

// Enqueue adds jobID to the stream. Call it last, after the email is
// stored, or a worker may read an ID whose email doesn't exist yet.
func (p *Producer) Enqueue(ctx context.Context, jobID string) (string, error) {
	if jobID == "" {
		return "", errors.New("queue: enqueue: empty job ID")
	}
	id, err := p.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: Stream,
		MaxLen: maxLen,
		Approx: true, // MAXLEN ~ : trims whole nodes, far cheaper than an exact trim
		ID:     "*",  //Redis assigns a time-ordered ID
		Values: map[string]any{fieldJobID: jobID},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("queue: enqueue: %s: %w", jobID, err)
	}
	return id, nil
}

// Consumer reads jobs from the stream and acknowledges them. Workers use it.
type Consumer struct {
	rdb  redis.Cmdable
	name string //consumer name inside the group: the worker ID
}

// NewConsumer wraps a Redis client. Cmdable accepts *redis.Client and test clients.
func NewConsumer(rdb redis.Cmdable, name string) *Consumer {
	return &Consumer{rdb: rdb, name: name}
}

// EnsureGroup creates the consumer group if it does not already exist.
// It is safe to call on every worker start
func (c *Consumer) EnsureGroup(ctx context.Context) error {
	// "0", not "$": otherwise jobs enqueued before the first worker are skipped.
	err := c.rdb.XGroupCreateMkStream(ctx, Stream, Group, "0").Err()
	if err != nil && !strings.HasPrefix(err.Error(), "BUSYGROUP") {
		return fmt.Errorf("queue: ensure group: %w", err)
	}
	return nil // BUSYGROUP means the group already exists
}

// Next blocks up to blockFor for one new job. It returns errNoJob on timeout
// and the context's error if ctx is canceled while waiting.
// The returned job stays pending until Ack is called
func (c *Consumer) Next(ctx context.Context) (Job, error) {
	streams, err := c.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    Group,
		Consumer: c.name,
		Streams:  []string{Stream, ">"},
		Block:    blockFor,
		Count:    1,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return Job{}, ErrNoJob // block timed out with nothing to read
	}
	if err != nil {
		return Job{}, fmt.Errorf("queue: read: %w", err)
	}
	if len(streams) == 0 || len(streams[0].Messages) == 0 {
		return Job{}, ErrNoJob
	}

	msg := streams[0].Messages[0] // one stream requested, Count 1
	jobID, _ := msg.Values[fieldJobID].(string)
	if jobID == "" {
		// Ack it now, or this bad entry would sit in the pending list forever.
		if err := c.Ack(ctx, msg.ID); err != nil {
			return Job{}, err
		}
		return Job{}, fmt.Errorf("%w: entry %s", ErrMalformedEntry, msg.ID)
	}
	return Job{StreamID: msg.ID, JobID: jobID}, nil
}

// Ack removes the entry from the group's pending list: the job is finished.
// Acking an entry that is no longer pending is a no-op in Redis, not an error.
func (c *Consumer) Ack(ctx context.Context, streamID string) error {
	if err := c.rdb.XAck(ctx, Stream, Group, streamID).Err(); err != nil {
		return fmt.Errorf("queue: ack %s: %w", streamID, err)
	}
	return nil
}
