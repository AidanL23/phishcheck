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
	// DeadStream holds jobs given up on after 3 attempts.
	DeadStream = "phishcheck:jobs:dead"

	fieldJobID = "job_id"
	// Extra fields on a dead-letter entry.
	fieldStreamID       = "stream_id"        // original entry ID
	fieldAttempts       = "attempts"         // times the job started
	fieldError          = "error"            // last recorded error
	fieldDeadLetteredBy = "dead_lettered_by" // worker that gave up

	// claimCount is 1 so each claimed entry runs right away. In a batch,
	// later entries could sit idle long enough to be claimed twice.
	claimCount = 1

	maxLen     = 10000           // phishcheck:jobs length cap (Appendix B.3)
	deadMaxLen = 1000            // phishcheck:jobs:dead length cap (Appendix B.3)
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

// ConsumerClient is what Consumer needs from Redis: the typed commands plus
// Do, for the raw XAUTOCLAIM in Claim. *redis.Client satisfies it.
type ConsumerClient interface {
	redis.Cmdable
	Do(ctx context.Context, args ...any) *redis.Cmd
}

// Consumer reads jobs from the stream and acknowledges them. Workers use it.
type Consumer struct {
	rdb  ConsumerClient
	name string //consumer name inside the group: the worker ID
}

// NewConsumer wraps a Redis client, usually a *redis.Client.
func NewConsumer(rdb ConsumerClient, name string) *Consumer {
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

// Next blocks up to blockFor for one new job. It returns ErrNoJob on timeout
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

// ClaimResult is what one XAUTOCLAIM call found.
type ClaimResult struct {
	// Jobs are entries now owned by this consumer, to run or dead-letter.
	Jobs []Job
	// Next is the PEL cursor for the next call; "0-0" means the scan is done.
	Next string
	// Trimmed are stream IDs of pending entries whose stream entry was
	// trimmed (MAXLEN on Enqueue) before anyone reclaimed them. The job ID
	// went with the entry, so the job hash is stuck as it was (usually
	// RUNNING) and the job can't be retried or dead-lettered. Redis 7 drops
	// these from the PEL as it reports them, so this is the only record:
	// the caller must log them.
	Trimmed []string
	// Malformed are stream IDs of claimed entries with no job_id. They are
	// already acked, the same as in Next.
	Malformed []string
}

// Claim runs one XAUTOCLAIM. It moves at most claimCount entries that have
// been pending longer than minIdle, from whichever consumer held them, to
// this consumer.
//
// start is a cursor into the PEL: pass "0-0" to begin a pass, then the
// returned Next on each later call.
//
// It sends the raw command, not rdb.XAutoClaim: go-redis drops the reply's
// third element, the trimmed IDs (Redis 7+), and they'd vanish unlogged.
func (c *Consumer) Claim(ctx context.Context, start string, minIdle time.Duration) (ClaimResult, error) {
	raw, err := c.rdb.Do(ctx, "XAUTOCLAIM", Stream, Group, c.name,
		idleMillis(minIdle), start, "COUNT", claimCount).Result()
	if err != nil {
		return ClaimResult{}, fmt.Errorf("queue: autoclaim: %w", err)
	}

	// Reply: [next-cursor, [[id, [field, value, ...]], ...], [trimmed-id, ...]].
	// Redis 6.2 has no third element.
	reply, ok := raw.([]any)
	if !ok || len(reply) < 2 {
		return ClaimResult{}, fmt.Errorf("queue: autoclaim: unexpected reply %#v", raw)
	}
	next, ok := reply[0].(string)
	entries, ok2 := reply[1].([]any)
	if !ok || !ok2 {
		return ClaimResult{}, fmt.Errorf("queue: autoclaim: unexpected reply %#v", raw)
	}

	res := ClaimResult{Next: next}
	for _, e := range entries {
		id, values, ok := parseEntry(e)
		switch {
		case !ok:
			return ClaimResult{}, fmt.Errorf("queue: autoclaim: unexpected entry %#v", e)
		case values == nil:
			// Redis 6.2 reports a trimmed entry as [id, nil] and keeps it in
			// the PEL. Ack it, or every pass would claim it again.
			if err := c.Ack(ctx, id); err != nil {
				return ClaimResult{}, err
			}
			res.Trimmed = append(res.Trimmed, id)
		case values[fieldJobID] == "":
			// Ack it, or every pass would claim this bad entry again.
			if err := c.Ack(ctx, id); err != nil {
				return ClaimResult{}, err
			}
			res.Malformed = append(res.Malformed, id)
		default:
			res.Jobs = append(res.Jobs, Job{StreamID: id, JobID: values[fieldJobID]})
		}
	}

	if len(reply) >= 3 {
		trimmed, ok := reply[2].([]any)
		if !ok {
			return ClaimResult{}, fmt.Errorf("queue: autoclaim: unexpected trimmed list %#v", reply[2])
		}
		for _, t := range trimmed {
			if id, ok := t.(string); ok {
				res.Trimmed = append(res.Trimmed, id)
			}
		}
	}
	return res, nil
}

// parseEntry reads one [id, [field, value, ...]] stream entry. values is nil
// when the entry's fields are nil (a trimmed entry on Redis 6.2).
func parseEntry(e any) (id string, values map[string]string, ok bool) {
	pair, isSlice := e.([]any)
	if !isSlice || len(pair) != 2 {
		return "", nil, false
	}
	if id, ok = pair[0].(string); !ok {
		return "", nil, false
	}
	if pair[1] == nil {
		return id, nil, true
	}
	fields, isSlice := pair[1].([]any)
	if !isSlice || len(fields)%2 != 0 {
		return "", nil, false
	}
	values = make(map[string]string, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		k, _ := fields[i].(string)
		v, _ := fields[i+1].(string)
		values[k] = v
	}
	return id, values, true
}

// idleMillis converts minIdle for XAUTOCLAIM, rounding a sub-millisecond
// value up to 1 so it never becomes "0" (claim everything) by accident.
func idleMillis(d time.Duration) int64 {
	if d > 0 && d < time.Millisecond {
		return 1
	}
	return d.Milliseconds()
}

// OtherActiveConsumers returns the other consumers in the group that talked
// to Redis (XREADGROUP or XAUTOCLAIM) within the last `within`. A live
// worker does one of those at least every ReclaimEvery (30 s), even mid-job,
// because its reclaim goroutine keeps ticking.
func (c *Consumer) OtherActiveConsumers(ctx context.Context, within time.Duration) ([]string, error) {
	consumers, err := c.rdb.XInfoConsumers(ctx, Stream, Group).Result()
	if err != nil {
		return nil, fmt.Errorf("queue: list consumers: %w", err)
	}
	var active []string
	for _, x := range consumers {
		if x.Name != c.name && x.Idle < within {
			active = append(active, x.Name)
		}
	}
	return active, nil
}

// DeadLetter copies the job to DeadStream and acks the original entry, in
// one MULTI/EXEC. also, if not nil, adds more commands to the same
// transaction (the worker uses it to write FAILED on the job hash), so they
// commit together with the dead-letter record or not at all. The store and
// the queue must share one Redis for that.
//
// If the connection drops before EXEC, nothing runs and the entry stays
// pending for the next pass. Once EXEC runs, all of it has happened. So a
// job is never acked without a dead-letter record, and never recorded twice.
func (c *Consumer) DeadLetter(ctx context.Context, job Job, attempts int64, reason string, also func(redis.Pipeliner)) error {
	_, err := c.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.XAdd(ctx, &redis.XAddArgs{
			Stream: DeadStream,
			MaxLen: deadMaxLen,
			Approx: true,
			ID:     "*",
			Values: map[string]any{
				fieldJobID:          job.JobID,
				fieldStreamID:       job.StreamID,
				fieldAttempts:       attempts,
				fieldError:          reason,
				fieldDeadLetteredBy: c.name,
			},
		})
		p.XAck(ctx, Stream, Group, job.StreamID)
		if also != nil {
			also(p)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("queue: dead-letter %s: %w", job.JobID, err)
	}
	return nil
}
