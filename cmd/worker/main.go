// Command worker reads job IDs from the phishcheck:jobs stream and hands each
// one to internal/worker, which analyzes the stored email, writes the Report,
// and decides whether to ack. The analysis is still a stub until Day 3: every
// email comes back VERDICT_CLEAN with score 0.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/AidanL23/phishcheck/internal/config"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
	"github.com/AidanL23/phishcheck/internal/worker"
)

func main() {
	// One JSON object per line on stdout. Docker, jq and a SIEM can all parse it.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// go-redis logs plain text to stderr by default. Docker merges stderr
	// into the same stream as stdout, so send it through slog to keep every line JSON.
	redis.SetLogger(redisLogger{l: slog.Default()})

	// run returns an error rather than calling os.Exit, so its deferred
	// cleanup (rdb.Close, stop) still runs.
	if err := run(); err != nil {
		slog.Error("worker exited", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// Cancelled on Ctrl+C or SIGTERM (`docker stop`). Both loops stop taking
	// new jobs, and run waits for any job in progress (reclaimWG below).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// After the first signal, a second one kills the worker at once.
	// That counts as a crash, so reclaim retries the job.
	context.AfterFunc(ctx, stop)

	// Load reports every invalid env var at once, so a bad deploy fails here
	// with the full list, not on the first job.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	workerID, err := newWorkerID()
	if err != nil {
		return err
	}
	// .With puts worker_id on every line this logger writes.
	logger := slog.Default().With("worker_id", workerID)

	// Log the settings before dialing: if the connection fails, this line
	// shows what the worker tried. LogValue redacts the Redis password.
	logger.Info("worker starting", "config", cfg)

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword, // empty in local dev
	})
	defer rdb.Close()

	// Fail at startup if Redis is down, not on the first job.
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping %s: %w", cfg.RedisAddr, err)
	}

	st, err := store.New(rdb, cfg.TTL)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	// The worker ID is also this worker's consumer name in the "workers" group.
	q := queue.NewConsumer(rdb, workerID)

	// Safe to call on every start: creates the group, ignores BUSYGROUP.
	if err := q.EnsureGroup(ctx); err != nil {
		return fmt.Errorf("ensure group: %w", err)
	}

	// A sleep at or past JobTimeout makes every job time out and go FAILED,
	// so the crash demo would show a failure, not a recovery. Refuse it here.
	if cfg.DebugSleep >= worker.JobTimeout {
		return fmt.Errorf("config: PHISHCHECK_DEBUG_SLEEP=%s must be below the job timeout (%s)",
			cfg.DebugSleep, worker.JobTimeout)
	}
	if cfg.DebugSleep > 0 {
		// Warn level, so a sleep someone forgot to turn off stands out in the logs.
		logger.Warn("debug sleep enabled: every job will stall", "debug_sleep", cfg.DebugSleep.String())
	}

	// An idle at or below one attempt's max time can claim a running job
	// and run it twice. Only the panic demo (no sleep) is fast enough to allow it.
	safeIdle := worker.JobTimeout + worker.FinishTimeout
	if cfg.ReclaimIdle > 0 && cfg.ReclaimIdle <= safeIdle && (!cfg.DebugPanic || cfg.DebugSleep > 0) {
		return fmt.Errorf("config: PHISHCHECK_RECLAIM_IDLE=%s must be above %s, "+
			"unless PHISHCHECK_DEBUG_PANIC=1 and PHISHCHECK_DEBUG_SLEEP is unset or 0s",
			cfg.ReclaimIdle, safeIdle)
	}
	if cfg.DebugPanic {
		logger.Warn("debug panic enabled: every job will panic and end in the dead-letter stream")
	}
	if cfg.ReclaimIdle > 0 {
		// Only guards this process: run the demo with no other workers.
		logger.Warn("reclaim min idle overridden", "reclaim_idle", cfg.ReclaimIdle.String())
	}

	// One Worker, shared by the main loop and the reclaim goroutine.
	w := worker.New(st, q, workerID, logger, worker.Debug{
		Sleep:       cfg.DebugSleep,
		Panic:       cfg.DebugPanic,
		ReclaimIdle: cfg.ReclaimIdle,
	})

	// The main loop runs jobs inline, so only this goroutine can still be
	// mid-job at shutdown. wg.Go handles Add(1) and Done().
	var reclaimWG sync.WaitGroup
	reclaimWG.Go(func() { w.RunReclaim(ctx) })

	logger.Info("worker ready")

	for {
		// Shutdown is checked here, between jobs. It can't interrupt a job
		// that has been read: nextStep always hands it to w.Handle, which
		// runs it on a context the signal doesn't cancel.
		if ctx.Err() != nil {
			logger.Info("worker stopping, waiting for the reclaim loop")
			// Waits for at most one job, about 60 s (see JobTimeout). Day 6's
			// stop_grace_period (70 s) must stay above this.
			reclaimWG.Wait()
			// Return only after the wait, so the deferred rdb.Close
			// can't run under a live job.
			logger.Info("worker stopped")
			return nil
		}

		msg, err := q.Next(ctx) // blocks for up to 5 s
		switch nextStep(err, ctx.Err() != nil) {
		case stepIdle:
			// The BLOCK timed out with nothing to read. Normal while idle; don't log it.
			continue
		case stepStop:
			// ctx was already cancelled when Next ran, so go-redis refused the
			// call. A read that was already blocking isn't interrupted: it waits
			// out the 5 s BLOCK and returns as stepIdle. The top of the loop exits.
			continue
		case stepSkip:
			// Next already acked the bad entry. One bad entry says nothing
			// about Redis's health, so warn and read the next one right away.
			logger.Warn("skipped malformed stream entry", "error", err)
			continue
		case stepBackoff:
			// Redis or network error. Back off so a dead connection
			// doesn't turn into a hot loop that floods the log.
			logger.Error("read from stream", "error", err)
			sleepCtx(ctx, time.Second)
			continue
		}

		w.Handle(context.WithoutCancel(ctx), msg)
	}
}

// step is what the worker loop does with one result from Next.
type step int

const (
	stepHandle  step = iota // got a job: run it, even if shutdown has started
	stepIdle                // the BLOCK timed out with nothing to read
	stepStop                // shutdown interrupted the blocking read
	stepSkip                // an entry with no job_id, already acked by Next
	stepBackoff             // Redis or network error
)

// nextStep decides what the loop does with Next's result. A job that was
// read is always handled, even if the signal arrived a moment later: Next
// has already put it in this consumer's pending list. Dropping it would
// leave it there until the reclaim loop took it 60 to 90 s later.
func nextStep(err error, stopping bool) step {
	switch {
	case err == nil:
		return stepHandle
	case errors.Is(err, queue.ErrNoJob):
		return stepIdle
	case errors.Is(err, queue.ErrMalformedEntry):
		return stepSkip
	case stopping:
		return stepStop
	default:
		return stepBackoff
	}
}

// newWorkerID returns "<hostname>-<4 hex chars>", e.g. "LAPTOP-KB519V12-3f9a".
// The hostname tells you which machine or container ran the job. The random
// suffix stops two workers on the same host from sharing one consumer name.
func newWorkerID() (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	b := make([]byte, 2) // 2 bytes = 4 hex characters
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random suffix: %w", err)
	}
	return host + "-" + hex.EncodeToString(b), nil
}

// sleepCtx sleeps for d, or returns early if ctx is cancelled, so Ctrl+C
// doesn't have to wait out the backoff.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// redisLogger adapts slog to go-redis's logging interface.
type redisLogger struct{ l *slog.Logger }

func (r redisLogger) Printf(ctx context.Context, format string, v ...any) {
	r.l.WarnContext(ctx, fmt.Sprintf(format, v...), "component", "go-redis")
}
