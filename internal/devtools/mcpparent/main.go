/*
Copyright (c) 2026 Security Research

mcpparent is a tiny test helper used by the binary-level integration
test for the unravel mcp parent watcher. It spawns the unravel binary
in 'mcp' mode, prints the child's PID to stdout (so the test can
observe it), wires a long-lived stdin so the child does not see EOF,
and then sleeps until the operating system terminates it. When the
test kills mcpparent the unravel child becomes orphaned and the parent
watcher inside the child should cancel its server context, ending the
process within ~5 s + idle-timeout.

Not built by 'go build ./...' in the default tree because it lives
under internal/devtools/; the integration test invokes 'go build' on
this package directly into a temp dir.

Usage:

	mcpparent <unravel-binary-path>
*/

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mcpparent <unravel-binary-path>")
		os.Exit(2)
	}
	bin := os.Args[1]

	// Pass --idle-timeout 24h so the watcher (not the idle timer) is
	// the path under test. The watcher polls every 5s in production.
	cmd := exec.Command(bin, "mcp", "--idle-timeout", "24h")

	// Give the child a stdin that never closes — we want the parent
	// watcher to be the trigger, not stdin EOF. io.Pipe holds the read
	// end open as long as mcpparent is alive; killing mcpparent closes
	// it implicitly via OS cleanup.
	r, w := io.Pipe()
	cmd.Stdin = r
	cmd.Stdout = os.Stderr // forward MCP JSON-RPC output to our stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "mcpparent: start: %v\n", err)
		os.Exit(1)
	}

	// Print the child PID on stdout so the test harness can capture it.
	fmt.Println(cmd.Process.Pid)
	_ = os.Stdout.Sync()

	// Keep the pipe writer alive (and thus the child's stdin open) so
	// nothing causes a premature EOF.
	go func() {
		defer func() { _ = w.Close() }()
		// Block until killed; the goroutine never returns under normal
		// test flow.
		select {}
	}()

	// Idle until the OS terminates us. A bounded sleep is used so
	// runaway helpers don't accumulate on the test host.
	time.Sleep(5 * time.Minute)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
