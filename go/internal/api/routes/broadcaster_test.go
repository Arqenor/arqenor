package routes

import (
	"testing"

	"arqenor/go/internal/store"
)

func TestAlertBroadcaster_RejectsBeyondCap(t *testing.T) {
	b := NewAlertBroadcaster(2)

	// First two subscribers admitted.
	id1, _, ok := b.Subscribe()
	if !ok {
		t.Fatal("first subscriber rejected unexpectedly")
	}
	id2, _, ok := b.Subscribe()
	if !ok {
		t.Fatal("second subscriber rejected unexpectedly")
	}

	// Third must be rejected.
	if _, _, ok := b.Subscribe(); ok {
		t.Fatal("third subscriber accepted past cap")
	}

	if got := b.SubscriberCount(); got != 2 {
		t.Errorf("SubscriberCount = %d, want 2", got)
	}

	// Unsubscribe one and a new subscriber should now succeed.
	b.Unsubscribe(id1)
	if got := b.SubscriberCount(); got != 1 {
		t.Errorf("after unsubscribe, count = %d, want 1", got)
	}
	if _, _, ok := b.Subscribe(); !ok {
		t.Error("subscriber rejected after slot freed")
	}

	// Cleanup.
	b.Unsubscribe(id2)
}

func TestAlertBroadcaster_PublishDeliversToAll(t *testing.T) {
	b := NewAlertBroadcaster(0) // 0 = unlimited

	_, ch1, ok := b.Subscribe()
	if !ok {
		t.Fatal("subscribe 1")
	}
	_, ch2, ok := b.Subscribe()
	if !ok {
		t.Fatal("subscribe 2")
	}

	a := store.Alert{ID: "a1", Severity: "high", Kind: "test", Message: "hello"}
	b.Publish(a)

	for i, ch := range []<-chan store.Alert{ch1, ch2} {
		select {
		case got := <-ch:
			if got.ID != "a1" {
				t.Errorf("subscriber %d: got ID %q, want a1", i, got.ID)
			}
		default:
			t.Errorf("subscriber %d: nothing received", i)
		}
	}
}

func TestAlertBroadcaster_UnlimitedWhenZero(t *testing.T) {
	b := NewAlertBroadcaster(0)
	for i := 0; i < 50; i++ {
		if _, _, ok := b.Subscribe(); !ok {
			t.Fatalf("subscriber %d rejected with cap=0 (unlimited)", i)
		}
	}
}
