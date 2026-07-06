package main

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/inovacc/unravel-oss/cmd"
	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/internal/elevate"
)

func init() {
	ai.LoadEnv(".env")

	// Prevent OOM: cap memory at 2GB and GC aggressively.
	debug.SetMemoryLimit(2 * 1024 * 1024 * 1024)
	debug.SetGCPercent(20)

	// Start global RAM monitor if UNRAVEL_MEMWATCH is set.
	// Logs memory stats to stderr at regular intervals.
	// Usage: UNRAVEL_MEMWATCH=5s unravel dissect app.apk
	if interval := os.Getenv("UNRAVEL_MEMWATCH"); interval != "" {
		d, err := time.ParseDuration(interval)
		if err != nil {
			d = 10 * time.Second
		}
		go memWatch(d)
	}
}

// memWatch logs runtime memory stats to stderr at the given interval.
// Reports: heap in use, heap alloc, sys (total from OS), GC count, goroutines.
// Automatically warns when heap exceeds 1GB.
func memWatch(interval time.Duration) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var stats runtime.MemStats
	peak := uint64(0)

	for {
		time.Sleep(interval)
		runtime.ReadMemStats(&stats)

		heapMB := stats.HeapInuse / (1024 * 1024)
		allocMB := stats.HeapAlloc / (1024 * 1024)
		sysMB := stats.Sys / (1024 * 1024)
		if stats.HeapInuse > peak {
			peak = stats.HeapInuse
		}
		peakMB := peak / (1024 * 1024)

		level := slog.LevelInfo
		if heapMB > 1024 {
			level = slog.LevelWarn
		}

		logger.Log(nil, level, fmt.Sprintf("mem: heap=%dMB alloc=%dMB sys=%dMB peak=%dMB gc=%d goroutines=%d",
			heapMB, allocMB, sysMB, peakMB, stats.NumGC, runtime.NumGoroutine()))
	}
}

// setupElevateChildRelay scans os.Args for the hidden --__elevate-child
// <path> marker injected by internal/elevate.ReExec. When present, redirects
// stdout + stderr to the named file so the parent (which dispatched UAC and
// hid this console) can stream output back to the original terminal. Removes
// the marker from os.Args so cobra's flag parser doesn't trip on it.
func setupElevateChildRelay() {
	args := os.Args
	for i := 1; i < len(args); i++ {
		if args[i] == elevate.ElevateChildFlag && i+1 < len(args) {
			path := args[i+1]
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
			if err == nil {
				os.Stdout = f
				os.Stderr = f
			}
			os.Args = append(args[:i], args[i+2:]...)
			return
		}
	}
}

func main() {
	setupElevateChildRelay()
	cmd.Execute()
}
