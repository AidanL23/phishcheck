// Package config loads PhishCheck settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

// Config holds every setting the API and worker read at startup.
type Config struct {
	GRPCAddr        string        // PHISHCHECK_GRPC_ADDR
	RedisAddr       string        // REDIS_ADDR
	RedisPassword   string        // REDIS_PASSWORD; never logged
	MaxEmailBytes   int64         // PHISHCHECK_MAX_EMAIL_BYTES
	TTL             time.Duration // PHISHCHECK_TTL
	TrustedAuthserv string        // PHISHCHECK_TRUSTED_AUTHSERV; empty means trust nothing
	DNSTimeout      time.Duration // PHISHCHECK_DNS_TIMEOUT
	DebugSleep      time.Duration // PHISHCHECK_DEBUG_SLEEP; demo only, 0 = off
	DebugPanic      bool          // PHISHCHECK_DEBUG_PANIC; demo only, false = off
	ReclaimIdle     time.Duration // PHISHCHECK_RECLAIM_IDLE; 0 = the worker's built-in 60s
}

// Load reads the configuration from the process environment.
// It returns every invalid variable at once, not just the first.
func Load() (Config, error) {
	return load(os.Getenv)
}

func load(getenv func(string) string) (Config, error) {
	var errs []error
	cfg := Config{
		GRPCAddr:        str(getenv, "PHISHCHECK_GRPC_ADDR", ":50051"),
		RedisAddr:       str(getenv, "REDIS_ADDR", "localhost:6379"),
		RedisPassword:   getenv("REDIS_PASSWORD"),
		TrustedAuthserv: getenv("PHISHCHECK_TRUSTED_AUTHSERV"),
	}
	cfg.MaxEmailBytes = positiveInt(getenv, "PHISHCHECK_MAX_EMAIL_BYTES", 25<<20, &errs) // 25 MB
	cfg.TTL = positiveDuration(getenv, "PHISHCHECK_TTL", 168*time.Hour, &errs)
	cfg.DNSTimeout = positiveDuration(getenv, "PHISHCHECK_DNS_TIMEOUT", 3*time.Second, &errs)
	// Demo only (§2.4): stall each job after RUNNING so a worker can be
	// killed mid-job. 0 must be accepted: Day 6's compose file sets "0s".
	cfg.DebugSleep = nonNegativeDuration(getenv, "PHISHCHECK_DEBUG_SLEEP", 0, &errs)
	// Demo only (§2.5): every job panics and ends in the dead-letter stream.
	cfg.DebugPanic = boolean(getenv, "PHISHCHECK_DEBUG_PANIC", false, &errs)
	// The safe minimum is checked in cmd/worker; config can't import worker.
	cfg.ReclaimIdle = nonNegativeDuration(getenv, "PHISHCHECK_RECLAIM_IDLE", 0, &errs)
	return cfg, errors.Join(errs...)
}

// LogValue makes slog print the config with the Redis password redacted.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("grpc_addr", c.GRPCAddr),
		slog.String("redis_addr", c.RedisAddr),
		slog.Bool("redis_password_set", c.RedisPassword != ""),
		slog.Int64("max_email_bytes", c.MaxEmailBytes),
		slog.String("ttl", c.TTL.String()),
		slog.String("trusted_authserv", c.TrustedAuthserv),
		slog.String("dns_timeout", c.DNSTimeout.String()),
		slog.String("debug_sleep", c.DebugSleep.String()),
		slog.Bool("debug_panic", c.DebugPanic),
		slog.String("reclaim_idle", c.ReclaimIdle.String()),
	)
}

func str(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func positiveInt(getenv func(string) string, key string, def int64, errs *[]error) int64 {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		*errs = append(*errs, fmt.Errorf("%s=%q: want a positive whole number", key, v))
		return def
	}
	return n
}

func positiveDuration(getenv func(string) string, key string, def time.Duration, errs *[]error) time.Duration {
	v := getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		*errs = append(*errs, fmt.Errorf("%s=%q: want a positive duration like 168h or 3s", key, v))
		return def
	}
	return d
}

// nonNegativeDuration is positiveDuration with 0 allowed, for settings
// where 0 means "off". Negative values and missing units still fail.
func nonNegativeDuration(getenv func(string) string, key string, def time.Duration, errs *[]error) time.Duration {
	v := getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		*errs = append(*errs, fmt.Errorf("%s=%q: want a duration like 45s, or 0s for off", key, v))
		return def
	}
	return d
}

// boolean reads an on/off switch. Accepts 1/0 and true/false;
// "yes" or "on" is an error, not a silent false.
func boolean(getenv func(string) string, key string, def bool, errs *[]error) bool {
	v := getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s=%q: want 1 or 0 (true or false)", key, v))
		return def
	}
	return b
}
