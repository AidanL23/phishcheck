package queue

import (
	"context"
	"testing"
)

// A nil client proves the empty ID is refused before any Redis call:
// reaching XAdd would panic.
func TestEnqueueRejectsEmptyID(t *testing.T) {
	id, err := NewProducer(nil).Enqueue(context.Background(), "")
	if err == nil || id != "" {
		t.Fatalf("Enqueue(\"\") = %q, %v; want an error", id, err)
	}
}
