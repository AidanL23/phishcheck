package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/AidanL23/phishcheck/internal/queue"
)

func TestNewWorkerID(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Skip("no hostname:", err)
	}
	re := regexp.MustCompile("^" + regexp.QuoteMeta(host) + "-[0-9a-f]{4}$")
	seen := map[string]bool{}
	for range 8 {
		id, err := newWorkerID()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(id) {
			t.Fatalf("worker ID %q does not match <hostname>-<4 hex>", id)
		}
		seen[id] = true
	}
	// Two workers on one host must not share a consumer name. Eight draws
	// from 65536 all colliding would mean the suffix isn't random.
	if len(seen) < 2 {
		t.Errorf("8 calls gave %d distinct IDs", len(seen))
	}
}

func TestSleepCtxSleeps(t *testing.T) {
	start := time.Now()
	sleepCtx(context.Background(), 20*time.Millisecond)
	if d := time.Since(start); d < 20*time.Millisecond {
		t.Errorf("returned after %s, want at least 20ms", d)
	}
}

func TestSleepCtxReturnsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		sleepCtx(ctx, time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sleepCtx ignored a cancelled context")
	}
}

func TestRedisLoggerWritesJSON(t *testing.T) {
	var buf bytes.Buffer
	l := redisLogger{l: slog.New(slog.NewJSONHandler(&buf, nil))}
	l.Printf(context.Background(), "redis: dial %s: %v", "localhost:6379", "refused")

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("not one JSON line: %v\n%s", err, buf.String())
	}
	if line["level"] != "WARN" || line["component"] != "go-redis" ||
		line["msg"] != "redis: dial localhost:6379: refused" {
		t.Errorf("got %v", line)
	}
}

func TestNextStep(t *testing.T) {
	redisDown := errors.New("queue: read: dial tcp: connection refused")
	tests := []struct {
		name     string
		err      error
		stopping bool
		want     step
	}{
		{"got a job", nil, false, stepHandle},
		// The Day 1 bug: SIGTERM landing after XREADGROUP returned an entry
		// used to skip it, leaving it pending and unacked with nobody to run it.
		{"got a job, then shutdown started", nil, true, stepHandle},
		{"idle", queue.ErrNoJob, false, stepIdle},
		{"idle at shutdown", queue.ErrNoJob, true, stepIdle},
		{"read interrupted by shutdown", fmt.Errorf("queue: read: %w", context.Canceled), true, stepStop},
		{"redis error", redisDown, false, stepBackoff},
		// Not a Redis outage: warn and keep reading, no 1 s backoff.
		{"malformed entry", fmt.Errorf("%w: entry 1-0", queue.ErrMalformedEntry), false, stepSkip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextStep(tt.err, tt.stopping); got != tt.want {
				t.Errorf("nextStep(%v, %v) = %d, want %d", tt.err, tt.stopping, got, tt.want)
			}
		})
	}
}
