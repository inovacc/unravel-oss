/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditSchemaVersion is the schema version stamped into every record.
const auditSchemaVersion = 1

// AuditRecord is one append-only forensic line written to inject-log.jsonl.
//
// The log is the load-bearing mitigation for Phase 46's threat model: every
// successful Inject call writes one record before the result is returned to
// the caller. There is no flag to disable this.
type AuditRecord struct {
	SchemaVersion int       `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	HostUser      string    `json:"host_user"`
	TargetPath    string    `json:"target_path"`
	Method        string    `json:"method"`
	ScriptName    string    `json:"script_name"`
	ScriptSHA256  string    `json:"script_sha256"`
	Persistent    bool      `json:"persistent"`
	OutputPath    string    `json:"output_path,omitempty"`
}

// auditMu serializes Append calls in-process. POSIX guarantees O_APPEND
// writes <PIPE_BUF are atomic across processes, but the in-process mutex
// keeps each JSON line whole even on platforms that don't honor that.
var auditMu sync.Mutex

// LogPath returns the resolved JSONL path. Honors UNRAVEL_INJECT_LOG for tests.
func LogPath() string {
	if p := os.Getenv("UNRAVEL_INJECT_LOG"); p != "" {
		return p
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "Unravel", "inject-log.jsonl")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "github.com/inovacc/unravel-oss/inject-log.jsonl"
	}
	return filepath.Join(home, "unravel", "inject-log.jsonl")
}

// Append writes one JSON line to the audit log. It always stamps the schema
// version and refuses to omit any field.
//
// File mode 0600. Parent directory created on demand. fsync after each write.
func Append(rec AuditRecord) error {
	rec.SchemaVersion = auditSchemaVersion
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	if rec.HostUser == "" {
		rec.HostUser = currentHostUser()
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	path := LogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		// Non-fatal: tempdir for tests may already exist; fall through and
		// let OpenFile surface the real error if any.
		if !errors.Is(err, os.ErrExist) {
			// proceed — OpenFile will fail loudly if the dir is truly bad
		}
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()

	if _, err := fh.Write(line); err != nil {
		return err
	}
	if err := fh.Sync(); err != nil {
		return err
	}
	return nil
}

// currentHostUser returns the resolved OS user; falls back to "unknown".
func currentHostUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}
