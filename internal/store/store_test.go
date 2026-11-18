package store

import (
	"strings"
	"testing"
	"time"
)

func TestKeys(t *testing.T) {
	id := "6f1c2e8a-0000-4000-8000-000000000001"
	tests := map[string]string{
		emailKey(id):  "phishcheck:email:" + id,
		jobKey(id):    "phishcheck:job:" + id,
		reportKey(id): "phishcheck:report:" + id,
	}
	for got, want := range tests {
		if got != want {
			t.Errorf("key = %q, want %q", got, want)
		}
	}
	// The three kinds must never collide, or a GET on one would read another.
	if emailKey(id) == jobKey(id) || jobKey(id) == reportKey(id) || emailKey(id) == reportKey(id) {
		t.Error("key kinds collide")
	}
	for got := range tests {
		if !strings.HasPrefix(got, prefix) {
			t.Errorf("%q lacks the %q prefix that scopes every key", got, prefix)
		}
	}
}

func TestNewRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := New(nil, ttl); err == nil {
			t.Errorf("New(ttl=%s): want error (a zero TTL would make every key permanent)", ttl)
		}
	}
	s, err := New(nil, time.Hour)
	if err != nil || s.ttl != time.Hour {
		t.Errorf("New(1h) = %+v, %v", s, err)
	}
}
