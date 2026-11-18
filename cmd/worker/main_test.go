package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"testing"
	"time"
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
