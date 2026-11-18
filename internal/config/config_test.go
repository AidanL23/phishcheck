package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Load promises every invalid variable at once, so one bad deploy is one fix.
func TestLoadReportsEveryBadVariable(t *testing.T) {
	_, err := load(env(map[string]string{
		"PHISHCHECK_MAX_EMAIL_BYTES": "lots",
		"PHISHCHECK_TTL":             "forever",
		"PHISHCHECK_DNS_TIMEOUT":     "-1s",
	}))
	if err == nil {
		t.Fatal("want an error")
	}
	for _, key := range []string{"PHISHCHECK_MAX_EMAIL_BYTES", "PHISHCHECK_TTL", "PHISHCHECK_DNS_TIMEOUT"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error does not mention %s:\n%v", key, err)
		}
	}
}

func TestLogValueRedactsPassword(t *testing.T) {
	cfg, err := load(env(map[string]string{"REDIS_PASSWORD": "hunter2-secret"}))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("starting", "config", cfg)
	out := buf.String()
	if strings.Contains(out, "hunter2-secret") {
		t.Fatalf("password leaked into the log line:\n%s", out)
	}
	if !strings.Contains(out, `"redis_password_set":true`) {
		t.Errorf("want redis_password_set:true in:\n%s", out)
	}
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(env(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GRPCAddr != ":50051" || cfg.RedisAddr != "localhost:6379" ||
		cfg.MaxEmailBytes != 26214400 || cfg.TTL != 168*time.Hour ||
		cfg.DNSTimeout != 3*time.Second || cfg.TrustedAuthserv != "" {
		t.Errorf("wrong defaults: %+v", cfg)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := load(env(map[string]string{
		"REDIS_ADDR":                  "redis:6379",
		"PHISHCHECK_TTL":              "24h",
		"PHISHCHECK_TRUSTED_AUTHSERV": "mx.example.com",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RedisAddr != "redis:6379" || cfg.TTL != 24*time.Hour || cfg.TrustedAuthserv != "mx.example.com" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	tests := map[string]map[string]string{
		"ttl in days":       {"PHISHCHECK_TTL": "7d"},
		"zero dns timeout":  {"PHISHCHECK_DNS_TIMEOUT": "0s"},
		"negative max size": {"PHISHCHECK_MAX_EMAIL_BYTES": "-1"},
		"size with units":   {"PHISHCHECK_MAX_EMAIL_BYTES": "25MB"},
	}
	for name, vars := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := load(env(vars)); err == nil {
				t.Errorf("want an error for %v, got nil", vars)
			}
		})
	}
}
