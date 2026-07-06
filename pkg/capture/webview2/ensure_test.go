/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- Unit-test seam ----------------------------------------------------------
//
// ProcessHost / Process now live in host.go (83-03). This file keeps only the
// programmable fakeHost / fakeProcess doubles + the Ensure assertions.

// fakeProcess is a recordable Process for both MethodDirect (PID>0) and
// MethodAUMID (PID=0) paths.
type fakeProcess struct {
	pid        int
	releaseErr error
}

func (p *fakeProcess) PID() int       { return p.pid }
func (p *fakeProcess) Wait() error    { return nil }
func (p *fakeProcess) Release() error { return p.releaseErr }

// fakeHost is the unit-test double mirroring spectra fake_host_test.go.
type fakeHost struct {
	mu sync.Mutex

	findResults []findResult
	killErr     map[int]error

	resolveExeOut string
	resolveExeErr error

	spawnProc *fakeProcess
	spawnErr  error

	spawnAUMIDProc *fakeProcess
	spawnAUMIDErr  error

	cleanupErr error

	calls []string
}

type findResult struct {
	pids []int
	err  error
}

func (h *fakeHost) record(op string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, op)
}

// Calls returns the recorded operation names in invocation order.
func (h *fakeHost) Calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.calls))
	copy(out, h.calls)
	return out
}

func (h *fakeHost) Find(_ context.Context, _ string) ([]int, error) {
	h.record("Find")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.findResults) == 0 {
		return nil, nil
	}
	res := h.findResults[0]
	h.findResults = h.findResults[1:]
	return res.pids, res.err
}

func (h *fakeHost) Kill(_ context.Context, pid int) error {
	h.record("Kill")
	if h.killErr != nil {
		if e, ok := h.killErr[pid]; ok {
			return e
		}
	}
	return nil
}

func (h *fakeHost) ResolveExe(_ context.Context, _ string) (string, error) {
	h.record("ResolveExe")
	return h.resolveExeOut, h.resolveExeErr
}

func (h *fakeHost) Spawn(_ context.Context, _ string, _ []string, _ []string) (Process, error) {
	h.record("Spawn")
	if h.spawnErr != nil {
		return nil, h.spawnErr
	}
	if h.spawnProc != nil {
		return h.spawnProc, nil
	}
	return &fakeProcess{pid: 4242}, nil
}

func (h *fakeHost) SpawnAUMID(_ context.Context, _ string, _ int) (Process, error) {
	h.record("SpawnAUMID")
	if h.spawnAUMIDErr != nil {
		return nil, h.spawnAUMIDErr
	}
	if h.spawnAUMIDProc != nil {
		return h.spawnAUMIDProc, nil
	}
	return &fakeProcess{pid: 0}, nil
}

func (h *fakeHost) CleanupHKCUEnv(_ context.Context) error {
	h.record("CleanupHKCUEnv")
	return h.cleanupErr
}

// Compile-time proof the double satisfies the seam.
var _ ProcessHost = (*fakeHost)(nil)

// jsonServer stands up a /json endpoint returning the canonical CDP target
// list so Probe (via cdp.Client.DiscoverTargets) sees a real HTTP surface.
func jsonServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

// TestEnsure covers probe-first, NoKill guard, and the D-09 honest BLOCK.
func TestEnsure(t *testing.T) {
	t.Run("probe_first_port_already_up", func(t *testing.T) {
		srv := jsonServer(t, `[{"url":"https://teams.microsoft.com/v2/x",`+
			`"webSocketDebuggerUrl":"ws://127.0.0.1:9999/devtools/page/ABC"}]`)
		defer srv.Close()

		h := &fakeHost{}
		att, err := ensureWith(context.Background(), Target{
			Kind: "teams-desktop",
			Port: portOf(t, srv),
		}, h)
		if err != nil {
			t.Fatalf("ensureWith: %v", err)
		}
		if att.Spawned {
			t.Fatalf("expected Spawned=false on probe-first hit")
		}
		if att.WebSocketDebugURL == "" {
			t.Fatalf("expected webSocketDebuggerUrl from probe")
		}
		// Probe-first short-circuits before any host call.
		if len(h.Calls()) != 0 {
			t.Fatalf("expected no host calls on probe-first, got %v", h.Calls())
		}
	})

	t.Run("nokill_running_without_cdp_blocks", func(t *testing.T) {
		// Port closed (unused port) + process found + NoKill => guard.
		h := &fakeHost{findResults: []findResult{{pids: []int{1234}}}}
		_, err := ensureWith(context.Background(), Target{
			Kind:   "teams-desktop",
			Port:   1, // nothing listening
			NoKill: true,
		}, h)
		if !errors.Is(err, ErrTargetRunningWithoutCDP) {
			t.Fatalf("expected ErrTargetRunningWithoutCDP, got %v", err)
		}
	})

	t.Run("d09_honest_block_on_never_open", func(t *testing.T) {
		// No process running, MethodDirect spawn succeeds, port never opens
		// => bounded poll then *LaunchTimeoutError (no fabricated success).
		h := &fakeHost{
			findResults:   []findResult{{pids: nil}},
			resolveExeOut: `C:\fake\install`,
			spawnProc:     &fakeProcess{pid: 4242},
		}
		_, err := ensureWith(context.Background(), Target{
			Kind:          "teams-desktop",
			Port:          1, // never opens
			LaunchTimeout: 600 * time.Millisecond,
			PollInterval:  100 * time.Millisecond,
		}, h)
		if !errors.Is(err, ErrCDPLaunchTimeout) {
			t.Fatalf("expected ErrCDPLaunchTimeout (D-09 honest BLOCK), got %v", err)
		}
		var lte *LaunchTimeoutError
		if !errors.As(err, &lte) {
			t.Fatalf("expected *LaunchTimeoutError with captured evidence, got %T", err)
		}
		if lte.Kind != "teams-desktop" {
			t.Fatalf("LaunchTimeoutError missing evidence: %+v", lte)
		}
	})

	t.Run("aumid_cleanup_runs_on_every_exit", func(t *testing.T) {
		h := &fakeHost{
			findResults:    []findResult{{pids: nil}},
			spawnAUMIDProc: &fakeProcess{pid: 0},
		}
		_, err := ensureWith(context.Background(), Target{
			Kind:          "wa-desktop",
			Port:          1,
			LaunchTimeout: 300 * time.Millisecond,
			PollInterval:  100 * time.Millisecond,
		}, h)
		if !errors.Is(err, ErrCDPLaunchTimeout) {
			t.Fatalf("expected timeout, got %v", err)
		}
		// D-04 transactional revert: CleanupHKCUEnv must have run.
		sawCleanup := false
		for _, c := range h.Calls() {
			if c == "CleanupHKCUEnv" {
				sawCleanup = true
			}
		}
		if !sawCleanup {
			t.Fatalf("MethodAUMID must run CleanupHKCUEnv on exit; calls=%v", h.Calls())
		}
	})
}
