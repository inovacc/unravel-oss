/*
Copyright (c) 2026 Security Research

mockilspy is a tiny stand-in for the real ilspycmd binary, used by the
decompile package's tests. Behavior is selected via MOCK_ILSPYCMD_MODE.

Modes:
  - ok:      write a stub Mock.cs into <-o> and exit 0
  - crash:   print "panic: bad metadata" to stderr and exit 1
  - garbage: write random-ish bytes to stdout and exit 0
  - hang:    sleep 5 seconds then exit 0 (used with short ctx timeouts)
  - version: print "mock-ilspycmd 9.9.9" to stdout and exit 0

Concurrency tracking: when MOCK_ILSPYCMD_COUNTER_FILE is set, the binary
uses a lockfile-based atomic increment/decrement around its work to let
TestDecompiler_BoundedParallel observe max-in-flight.
*/
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

func main() {
	mode := os.Getenv("MOCK_ILSPYCMD_MODE")

	// Parse args: support `--version`, `-p`, `-o <dir>`, positional asm path.
	var outDir string
	var asm string
	args := os.Args[1:]

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version":
			fmt.Println("mock-ilspycmd 9.9.9")
			os.Exit(0)
		case "-p":
			// project mode flag — no-op
		case "-o":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		default:
			if asm == "" {
				asm = args[i]
			}
		}
	}

	if mode == "version" {
		fmt.Println("mock-ilspycmd 9.9.9")
		os.Exit(0)
	}

	counterFile := os.Getenv("MOCK_ILSPYCMD_COUNTER_FILE")
	if counterFile != "" {
		incrementCounter(counterFile, int64(+1))
		defer func() { incrementCounter(counterFile, int64(-1)) }()
		// Sleep so concurrency overlap is observable.
		time.Sleep(50 * time.Millisecond)
	}

	switch mode {
	case "crash":
		fmt.Fprintln(os.Stderr, "panic: bad metadata")
		os.Exit(1)
	case "hang":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "garbage":
		// Emit a chunk of pseudo-random bytes to stdout.
		var buf [256]byte
		seed := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(seed >> uint(i%56))
		}
		_, _ = os.Stdout.Write(buf[:])
		os.Exit(0)
	case "ok", "":
		// Write a stub <out>/MockNs/Mock.cs.
		if outDir == "" {
			fmt.Fprintln(os.Stderr, "mockilspy: missing -o <dir>")
			os.Exit(2)
		}
		_ = asm // unused in ok mode
		nsDir := filepath.Join(outDir, "MockNs")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mockilspy:", err)
			os.Exit(3)
		}
		body := "// mock\nnamespace MockNs { public class Mock {} }\n"
		if err := os.WriteFile(filepath.Join(nsDir, "Mock.cs"), []byte(body), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "mockilspy:", err)
			os.Exit(4)
		}
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "mockilspy: unknown MOCK_ILSPYCMD_MODE:", mode)
		os.Exit(5)
	}
}

// incrementCounter performs an "atomic" inc/dec around a file using a sidecar
// lockfile created via O_EXCL spin loop. Good enough for test concurrency
// observation; not a real distributed primitive.
var procMu sync.Mutex

func incrementCounter(path string, delta int64) {
	procMu.Lock()
	defer procMu.Unlock()

	lock := path + ".lock"
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			break
		}
		time.Sleep(time.Millisecond)
	}
	defer func() { _ = os.Remove(lock) }()

	cur := readCounter(path)
	cur += delta
	writeCounter(path, cur)
}

func readCounter(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 8 {
		// Fall back to text parse in case file was authored in text mode.
		if v, perr := strconv.ParseInt(string(data), 10, 64); perr == nil {
			return v
		}
		return 0
	}
	return int64(binary.LittleEndian.Uint64(data[:8]))
}

func writeCounter(path string, v int64) {
	max := readMax(path)
	if v > max {
		max = v
	}
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], uint64(v))
	binary.LittleEndian.PutUint64(buf[8:], uint64(max))
	_ = os.WriteFile(path, buf[:], 0o600)
}

func readMax(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 16 {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(data[8:16]))
}
