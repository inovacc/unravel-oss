/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLock_SecondAcquireBlocked(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "daemon.lock")

	lk, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { _ = lk.release() }()

	// A second acquisition of the same path must report contention, not
	// silently succeed (which is what lets two daemons co-own the singleton).
	if _, err := acquireFileLock(path); !errors.Is(err, errLockHeld) {
		t.Fatalf("second acquire: got %v, want errLockHeld", err)
	}
}

func TestFileLock_ReleaseAllowsReacquire(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "daemon.lock")

	lk, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := lk.release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	lk2, err := acquireFileLock(path)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	if err := lk2.release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

// TestSupervisor_SecondStartDetectsSingleton pins the host-singleton race fix:
// once one supervisor holds the lock, a second Start on the same SocketDir
// must refuse with ErrSingletonHeld instead of removing+rebinding the socket
// and hijacking the live endpoint.
func TestSupervisor_SecondStartDetectsSingleton(t *testing.T) {
	tmp := t.TempDir()

	sv1, err := New(Config{SocketDir: tmp, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New sv1: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv1.Start(ctx); err != nil {
		t.Fatalf("Start sv1: %v", err)
	}
	defer func() { _ = sv1.Stop() }()

	sv2, err := New(Config{SocketDir: tmp, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New sv2: %v", err)
	}
	err = sv2.Start(ctx)
	if !errors.Is(err, ErrSingletonHeld) {
		t.Fatalf("second Start: got %v, want ErrSingletonHeld", err)
	}
	// sv2 must not have hijacked the endpoint: sv1 still owns the lock.
	_ = sv2.Stop()
}

// TestSupervisor_StartAfterStopReacquires confirms the lock is released on
// Stop so a fresh daemon can take over (e.g. after a clean restart).
func TestSupervisor_StartAfterStopReacquires(t *testing.T) {
	tmp := t.TempDir()

	sv1, err := New(Config{SocketDir: tmp, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New sv1: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := sv1.Start(ctx); err != nil {
		t.Fatalf("Start sv1: %v", err)
	}
	if err := sv1.Stop(); err != nil {
		t.Fatalf("Stop sv1: %v", err)
	}

	sv2, err := New(Config{SocketDir: tmp, IdleTimeout: time.Hour})
	if err != nil {
		t.Fatalf("New sv2: %v", err)
	}
	if err := sv2.Start(ctx); err != nil {
		t.Fatalf("Start sv2 after sv1 stopped: %v (lock not released?)", err)
	}
	_ = sv2.Stop()
}
