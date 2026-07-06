//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// errLockHeld is returned by acquireFileLock when another process already
// holds the exclusive lock. Callers treat this as "a peer owns the
// singleton" rather than an error to remediate.
var errLockHeld = errors.New("supervisor: daemon lock already held")

// fileLock is an OS exclusive lock held for the daemon's lifetime via
// LockFileEx over an os.File handle. The handle must stay open for the
// lock to persist.
type fileLock struct {
	f *os.File
}

// acquireFileLock opens (creating if needed) path and takes an exclusive,
// fail-immediately byte-range lock (LockFileEx LOCKFILE_EXCLUSIVE_LOCK |
// LOCKFILE_FAIL_IMMEDIATELY). On contention it returns errLockHeld. The
// lock is released by release() or by process death (the OS closes the
// handle and drops the lock), so a crashed daemon's lock clears.
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	// Lock a single byte region [0,1); the region need not contain data.
	var ol windows.Overlapped
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &ol,
	)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, errLockHeld
		}
		return nil, fmt.Errorf("lock file %s: %w", path, err)
	}
	return &fileLock{f: f}, nil
}

// release unlocks and closes the lock file. Safe for a nil receiver.
func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &ol)
	err := l.f.Close()
	l.f = nil
	if err != nil {
		return fmt.Errorf("close lock file: %w", err)
	}
	return nil
}
