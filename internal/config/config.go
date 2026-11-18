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
	return cfg, errors.Join(errs...)
}

// LogValue makes slog print the config with the Redis password redacted.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("grpc_addr", c.GRPCAddr),
		slog.String("redis_addr", c.RedisAddr),
		slog.Bool("redis_password_set", c.RedisPassword != ""),
		slog.Int64("max_email_bytes", c.MaxEmailBytes),
		slog.Duration("ttl", c.TTL),
		slog.String("trusted_authserv", c.TrustedAuthserv),
		slog.Duration("dns_timeout", c.DNSTimeout),
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
