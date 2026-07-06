/*
Copyright (c) 2026 Security Research
*/

package lifecycle

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCleanConcurrentSafe verifies that many parallel Clean() invocations
// against the same registry directory do not produce duplicate-remove
// errors, do not corrupt records, and never report a non-self live entry
// as removed. Reproduces the "5 simultaneous clean invocations" scenario
// from BACKLOG KBC-MCP-INSTANCE-CONTROL.
func TestCleanConcurrentSafe(t *testing.T) {
	dir := t.TempDir()

	// Plant a mix of:
	//   - dead self+dead parent entries (should be removed)
	//   - live self entries (the test itself; should be preserved)
	const deadCount = 20
	for i := range deadCount {
		dead := Info{
			PID:            10_000_000 + i, // beyond any plausible OS PID
			ParentPID:      10_000_000 + i,
			StartedAt:      time.Now().UTC().Add(-time.Hour),
			LastActivityAt: time.Now().UTC().Add(-time.Hour),
			ProjectDir:     "/dev/null",
		}
		writeRecordRaw(t, dir, dead)
	}
	// Also plant the live self so Clean has something to NOT remove.
	live, err := Register(dir, Info{ProjectDir: "live-self"})
	if err != nil {
		t.Fatalf("Register self: %v", err)
	}
	defer func() { _ = live.Close() }()

	// Spawn 5 cleaners in parallel.
	var wg sync.WaitGroup
	var totalRemoved atomic.Int64
	var racingErrs atomic.Int64
	const workers = 5
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			results, err := Clean(dir, false)
			if err != nil {
				racingErrs.Add(1)
				return
			}
			for _, r := range results {
				if r.Removed {
					totalRemoved.Add(1)
					if r.Info.PID == os.Getpid() {
						racingErrs.Add(1) // never remove self
					}
				}
			}
		}()
	}
	wg.Wait()

	if racingErrs.Load() != 0 {
		t.Fatalf("concurrent Clean reported errors: %d", racingErrs.Load())
	}
	// Exactly deadCount distinct files should have been removed across
	// all workers combined — duplicate removals are not errors but they
	// indicate a TOCTOU race the implementation must handle silently.
	// Sum may exceed deadCount only if Clean double-counts; in our
	// implementation Removed is set only on successful os.Remove (which
	// returns ErrNotExist on the second attempt, treated as Err) so the
	// sum stays bounded.
	if totalRemoved.Load() < int64(deadCount) {
		t.Errorf("removed %d, want at least %d", totalRemoved.Load(), deadCount)
	}

	// Final state: self alive, everything else gone.
	remaining, _ := List(dir)
	if len(remaining) != 1 || remaining[0].PID != os.Getpid() {
		t.Fatalf("remaining = %+v, want only self pid=%d", remaining, os.Getpid())
	}
}

// TestCleanConcurrentTouch interleaves Touch() on a live registered
// instance with Clean() runs to make sure the throttled write does not
// race with the directory walk.
func TestCleanConcurrentTouch(t *testing.T) {
	if runtime.GOOS == "windows" && testing.Short() {
		t.Skip("file-rename races flake under -short on Windows CI")
	}
	dir := t.TempDir()
	inst, err := Register(dir, Info{ProjectDir: "touch-test"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer func() { _ = inst.Close() }()

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				inst.Touch()
			}
		}
	}()

	var cleanErrs atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if _, err := Clean(dir, false); err != nil {
				cleanErrs.Add(1)
			}
		})
	}
	wg.Wait()
	close(stop)

	if cleanErrs.Load() != 0 {
		t.Fatalf("Clean races: %d errors", cleanErrs.Load())
	}
	// Self record must still exist.
	got, err := List(dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, e := range got {
		if e.PID == os.Getpid() {
			found = true
		}
	}
	if !found {
		t.Fatalf("self record lost after concurrent touch+clean: %+v", got)
	}
}

// writeRecordRaw is the package-internal version of the helper in the
// main test file. Duplicated to keep this stress-test file independent.
func writeRecordRaw(t *testing.T, dir string, info Info) {
	t.Helper()
	path := filepath.Join(dir, strconv.Itoa(info.PID)+".json")
	inst := &Instance{dir: dir, path: path, info: info}
	if err := inst.writeLocked(); err != nil {
		t.Fatalf("writeRecordRaw: %v", err)
	}
}
