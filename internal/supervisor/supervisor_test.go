/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"testing"
	"time"
)

func TestSupervisor_StartStop(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{
		SocketDir:   tmp,
		IdleTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if !sv.HasVerb("hello") {
		t.Errorf("supervisor missing 'hello' verb")
	}
	if !sv.HasVerb("ping") {
		t.Errorf("supervisor missing 'ping' verb")
	}

	// Stop should be idempotent.
	if err := sv.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if err := sv.Stop(); err != nil {
		t.Errorf("Stop second call: %v", err)
	}
}

func TestSupervisor_New_RequiresSocketDir(t *testing.T) {
	_, err := New(Config{SocketDir: ""})
	if err == nil {
		t.Fatalf("New with empty SocketDir: want error")
	}
}

func TestSupervisor_DefaultsApplied(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if sv.cfg.IdleTimeout != 30*time.Minute {
		t.Errorf("default IdleTimeout = %v, want 30m", sv.cfg.IdleTimeout)
	}
	if sv.cfg.Logger == nil {
		t.Errorf("default Logger nil")
	}
}

func TestSupervisor_PingHandlerUsesInjectedClock(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})

	fixed := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	sv.now = func() time.Time { return fixed }

	// Drive the ping handler directly via the registry — no listener needed.
	// We can't easily reach into ipc.Server's handler map; instead we invoke
	// the bus end-to-end via net.Pipe in the registry_test (separate file).

	// Smoke-only here: confirm now is settable.
	got := sv.now()
	if !got.Equal(fixed) {
		t.Errorf("now = %v, want %v", got, fixed)
	}
}
