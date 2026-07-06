/*
Copyright (c) 2026 Security Research
*/

// Package lifecycle maintains a filesystem-backed registry of running
// `unravel mcp` stdio server instances so they can be enumerated and
// cleaned up after their parent has gone away.
//
// One JSON file per PID at $LOCALAPPDATA/Unravel/mcp/instances/<pid>.json
// (or the equivalent XDG_STATE_HOME location on Unix). Atomic rename on
// write so concurrent listers never see a half-written record. The
// registry is best-effort: errors writing/reading do not block server
// startup or shutdown, they just surface in logs.
//
// Acceptance criteria for KBC-MCP-INSTANCE-CONTROL (BACKLOG):
//   - Register on server start, Touch on every incoming request,
//     Deregister on clean shutdown.
//   - Clean(force) removes entries whose ParentPID is dead and whose
//     LastActivityAt is older than staleThreshold (or unconditionally
//     when force=true). Returns the list of cleaned entries so callers
//     can issue a final kill signal if needed.
package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Info is the persisted shape of a registered MCP instance.
type Info struct {
	PID            int       `json:"pid"`
	ParentPID      int       `json:"parent_pid"`
	StartedAt      time.Time `json:"started_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	ProjectDir     string    `json:"project_dir"`
	Version        string    `json:"version"`
	Executable     string    `json:"executable"`
}

// Instance is a live handle returned by Register. It owns the on-disk
// record for the current process. All methods are safe for concurrent
// use; Touch and Close are no-ops when the registry is disabled.
type Instance struct {
	dir  string
	path string
	mu   sync.Mutex
	info Info
	off  bool
}

// staleThreshold is how long an instance must be silent before Clean
// (without --force) considers it eligible for removal.
const staleThreshold = 10 * time.Minute

// DefaultDir returns the per-host registry directory. Errors here
// disable the registry rather than fail the server, mirroring the
// HAR-transport fallback pattern in pkg/mcptools/server.go.
func DefaultDir() (string, error) {
	if d := os.Getenv("UNRAVEL_MCP_INSTANCE_DIR"); d != "" {
		return d, nil
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			return "", errors.New("LOCALAPPDATA not set")
		}
		return filepath.Join(base, "Unravel", "mcp", "instances"), nil
	default:
		base := os.Getenv("XDG_STATE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "state")
		}
		return filepath.Join(base, "unravel", "mcp", "instances"), nil
	}
}

// Register writes the current process's record to dir/<pid>.json and
// returns a live Instance. A nil-but-no-error Instance means the
// registry was opted out of (empty dir). The returned Instance must
// be Closed on shutdown; callers should treat the returned err as
// non-fatal and log it.
func Register(dir string, info Info) (*Instance, error) {
	if dir == "" {
		return &Instance{off: true}, nil
	}
	if info.PID == 0 {
		info.PID = os.Getpid()
	}
	if info.ParentPID == 0 {
		info.ParentPID = os.Getppid()
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = time.Now().UTC()
	}
	if info.LastActivityAt.IsZero() {
		info.LastActivityAt = info.StartedAt
	}
	if info.Executable == "" {
		if exe, err := os.Executable(); err == nil {
			info.Executable = exe
		}
	}
	if info.ProjectDir == "" {
		if wd, err := os.Getwd(); err == nil {
			info.ProjectDir = wd
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &Instance{off: true}, fmt.Errorf("mkdir registry: %w", err)
	}
	path := filepath.Join(dir, strconv.Itoa(info.PID)+".json")
	inst := &Instance{dir: dir, path: path, info: info}
	if err := inst.writeLocked(); err != nil {
		return &Instance{off: true}, err
	}
	return inst, nil
}

// Touch atomically updates LastActivityAt. Safe to call on every
// incoming JSON-RPC request; the implementation throttles disk writes
// to once per second so a tools/call storm doesn't thrash the registry.
func (i *Instance) Touch() {
	if i == nil || i.off {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now().UTC()
	// Throttle: skip writes within 1s of the previous one.
	if now.Sub(i.info.LastActivityAt) < time.Second {
		return
	}
	i.info.LastActivityAt = now
	_ = i.writeLocked() // best-effort; ignore write errors on touch
}

// Close removes the registry record. Safe to call multiple times.
func (i *Instance) Close() error {
	if i == nil || i.off {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.path == "" {
		return nil
	}
	err := os.Remove(i.path)
	i.path = ""
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PID returns the recorded process ID.
func (i *Instance) PID() int {
	if i == nil {
		return 0
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.info.PID
}

// writeLocked persists i.info to i.path atomically. Caller must hold i.mu.
func (i *Instance) writeLocked() error {
	if i.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(i.info, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registry record: %w", err)
	}
	tmp := i.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write registry tmp: %w", err)
	}
	if err := os.Rename(tmp, i.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename registry record: %w", err)
	}
	return nil
}

// List enumerates every registry entry in dir, skipping unreadable
// files. Returns entries in PID order.
func List(dir string) ([]Info, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var info Info
		if err := json.Unmarshal(raw, &info); err != nil {
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// CleanResult is the outcome of a single Clean() decision.
type CleanResult struct {
	Info    Info
	Removed bool
	Reason  string // "parent-dead", "stale", "self-dead", "force"
	Err     error
}

// Clean walks the registry and removes entries whose owning process is
// no longer alive OR (when force=false) whose parent process is dead
// AND whose LastActivityAt is older than staleThreshold. force=true
// drops the activity check (removes any entry whose parent or self is
// dead). Self (the calling process) is always preserved.
//
// Clean does NOT signal the still-living target process; it only
// removes the registry file. Callers that want to terminate the
// process should follow up with os.FindProcess(...).Kill() on entries
// returned with Removed=false (caller policy).
func Clean(dir string, force bool) ([]CleanResult, error) {
	infos, err := List(dir)
	if err != nil {
		return nil, err
	}
	self := os.Getpid()
	now := time.Now().UTC()
	var out []CleanResult
	for _, info := range infos {
		if info.PID == self {
			continue
		}
		r := CleanResult{Info: info}
		switch {
		case !processAlive(info.PID):
			r.Reason = "self-dead"
		case info.ParentPID > 1 && !processAlive(info.ParentPID):
			if force || now.Sub(info.LastActivityAt) > staleThreshold {
				if force {
					r.Reason = "force"
				} else {
					r.Reason = "parent-dead+stale"
				}
			}
		case force:
			r.Reason = "force"
		}
		if r.Reason == "" {
			out = append(out, r)
			continue
		}
		path := filepath.Join(dir, strconv.Itoa(info.PID)+".json")
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			r.Err = err
			out = append(out, r)
			continue
		}
		r.Removed = true
		out = append(out, r)
	}
	return out, nil
}

// processAlive is the package-private alias that internal call sites
// (Clean, etc.) use to invoke the platform-specific ProcessAlive.
// New external callers should use ProcessAlive directly.
//
// The implementation is in process_alive_unix.go and process_alive_windows.go
// — split by build tag because os.Process.Signal(0) is unreliable on
// Windows for fresh handles (returns EWINDOWS rather than ErrProcessDone
// for already-dead PIDs whose handle was never Waited on).
func processAlive(pid int) bool { return ProcessAlive(pid) }
