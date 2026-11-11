package config

import (
	"testing"
	"time"
)

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
