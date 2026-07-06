//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errLockHeld is returned by acquireFileLock when another process already
// holds the exclusive lock. Callers treat this as "a peer owns the
// singleton" rather than an error to remediate.
var errLockHeld = errors.New("supervisor: daemon lock already held")

// fileLock is an OS advisory exclusive lock held for the daemon's lifetime.
// The fd must stay open: closing it releases the flock on POSIX.
type fileLock struct {
	f *os.File
}

// acquireFileLock opens (creating if needed) path and takes an exclusive,
// non-blocking advisory lock (flock LOCK_EX|LOCK_NB). On contention it
// returns errLockHeld. The lock is held until release() (or process death,
// which the kernel reaps automatically — so a crashed daemon's lock clears).
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errLockHeld
		}
		return nil, fmt.Errorf("flock %s: %w", path, err)
	}
	return &fileLock{f: f}, nil
}

// release unlocks and closes the lock file. Idempotent-safe for nil receiver.
func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	if err != nil {
		return fmt.Errorf("close lock file: %w", err)
	}
	return nil
}
