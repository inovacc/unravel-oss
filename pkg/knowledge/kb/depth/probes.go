/*
Copyright (c) 2026 Security Research

Package depth implements the Phase 30 SCOR-01 12-dimension depth-scoring
helper. Probes inspect a knowledge-source folder layout and (optionally) a
read-only DB connection, returning per-dimension coverage that ComputeDepth
aggregates into an equal-weight 0..100 score.

Decisions encoded here:

  - D-30-DEPTH-FORMULA — score = round((covered/12) * 100), equal-weight,
    no framework conditioning.
  - D-30-DEPTH-PROBES  — fixed 12-dim list in declared order:
    identity, framework, deps, ui, managed_source, wire_protocol, auth,
    native, webview, storage, telemetry, runtime.

Probes are best-effort signal, NOT validation. Any IO/JSON error returns
(false, "") and is logged at slog.Debug. knowledge.json reads are bounded
at 64 MiB via io.LimitReader (T-30-01-01 mitigation). Recursive walks
short-circuit on threshold (T-30-01-02 mitigation) and skip symlinks.

License: BSD-3-Clause.
*/
package depth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const knowledgeJSONMaxBytes = 64 << 20 // 64 MiB cap on knowledge.json reads

// Probe is one of the 12 fixed depth dimensions. Fn returns whether the
// dimension is covered and a short evidence hint for debug logging only.
type Probe struct {
	Name string
	Fn   func(ksDir string, conn *sql.Conn) (covered bool, evidence string)
}

// AllProbes is the fixed Phase 30 list. ORDER MATTERS for stable
// covered/missing slices and deterministic test output.
var AllProbes = []Probe{
	{Name: "identity", Fn: probeIdentity},
	{Name: "framework", Fn: probeFramework},
	{Name: "deps", Fn: probeDeps},
	{Name: "ui", Fn: probeUI},
	{Name: "managed_source", Fn: probeManagedSource},
	{Name: "wire_protocol", Fn: probeWireProtocol},
	{Name: "auth", Fn: probeAuth},
	{Name: "native", Fn: probeNative},
	{Name: "webview", Fn: probeWebview},
	{Name: "storage", Fn: probeStorage},
	{Name: "telemetry", Fn: probeTelemetry},
	{Name: "runtime", Fn: probeRuntime},
}

// readKnowledgeJSON loads <ksDir>/knowledge.json into a generic map. Returns
// (nil, false) on any error (missing file, parse error, IO failure). Reader
// is wrapped in io.LimitReader to bound memory at 64 MiB.
func readKnowledgeJSON(ksDir string) (map[string]any, bool) {
	if ksDir == "" {
		return nil, false
	}
	path := filepath.Join(filepath.Clean(ksDir), "knowledge.json")
	f, err := os.Open(path)
	if err != nil {
		slog.Debug("depth: knowledge.json open failed", "path", path, "err", err)
		return nil, false
	}
	defer func() { _ = f.Close() }()

	limited := io.LimitReader(f, knowledgeJSONMaxBytes)
	var m map[string]any
	if err := json.NewDecoder(limited).Decode(&m); err != nil {
		slog.Debug("depth: knowledge.json decode failed", "path", path, "err", err)
		return nil, false
	}
	return m, true
}

// dirHasFiles returns true when dir exists and contains at least one regular
// file (non-recursive).
func dirHasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			return true
		}
	}
	return false
}

// dirExists returns true if the path exists and is a directory.
func dirExists(dir string) bool {
	st, err := os.Stat(dir)
	if err != nil {
		return false
	}
	return st.IsDir()
}

// fileExists returns true if path exists and is a regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.Mode().IsRegular()
}

// countRegularFiles walks root recursively and returns the number of regular
// (non-symlink) files, short-circuiting at limit. Symlinks are skipped to
// mitigate T-30-01-02 (loop DoS).
func countRegularFiles(root string, limit int) int {
	count := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // best-effort probe
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			count++
			if count >= limit {
				return errors.New("limit reached")
			}
		}
		return nil
	})
	return count
}

// findFirstWithExt walks root and returns true on the first regular file
// whose name has any of the given extensions (lower-case, dot-prefixed).
// Symlinks skipped. Stops at first hit.
func findFirstWithExt(root string, exts ...string) bool {
	stop := errors.New("found")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, ferr error) error {
		if ferr != nil {
			return nil //nolint:nilerr // best-effort
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := strings.ToLower(d.Name())
		for _, ext := range exts {
			if strings.HasSuffix(name, ext) {
				return stop
			}
		}
		return nil
	})
	return errors.Is(err, stop)
}

// --- Probes -----------------------------------------------------------------

// probeIdentity covers when kb_apps has at least one row with non-null
// package_id, platform, and publisher. Returns false when conn is nil.
func probeIdentity(ksDir string, conn *sql.Conn) (bool, string) {
	if conn == nil {
		return false, ""
	}
	const q = `SELECT 1 FROM kb_apps WHERE package_id IS NOT NULL AND platform IS NOT NULL AND publisher IS NOT NULL LIMIT 1`
	var one int
	row := conn.QueryRowContext(context.Background(), q)
	if err := row.Scan(&one); err != nil {
		slog.Debug("depth: probeIdentity query failed", "err", err)
		return false, ""
	}
	return true, "kb_apps row with package_id+platform+publisher"
}

// probeFramework covers when knowledge.json has a non-empty top-level
// "framework" string field.
func probeFramework(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	m, ok := readKnowledgeJSON(ksDir)
	if !ok {
		return false, ""
	}
	if v, ok := m["framework"].(string); ok && v != "" {
		return true, "knowledge.json.framework=" + v
	}
	return false, ""
}

// probeDeps covers when knowledge.json has at least one dependency under
// dependencies / deps / manifest.dependencies.
func probeDeps(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	m, ok := readKnowledgeJSON(ksDir)
	if !ok {
		return false, ""
	}
	if hasNonEmpty(m["dependencies"]) {
		return true, "knowledge.json.dependencies non-empty"
	}
	if hasNonEmpty(m["deps"]) {
		return true, "knowledge.json.deps non-empty"
	}
	if mf, ok := m["manifest"].(map[string]any); ok && hasNonEmpty(mf["dependencies"]) {
		return true, "knowledge.json.manifest.dependencies non-empty"
	}
	return false, ""
}

// probeUI covers when sources/ui/ has at least one regular file OR xaml/ exists.
func probeUI(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	uiDir := filepath.Join(clean, "sources", "ui")
	if dirHasFiles(uiDir) {
		return true, "sources/ui/ has files"
	}
	xamlDir := filepath.Join(clean, "xaml")
	if dirExists(xamlDir) {
		return true, "xaml/ exists"
	}
	return false, ""
}

// probeManagedSource covers when decompiled/ OR sources/source/ exists with
// >= 10 regular files (recursive count, capped early).
func probeManagedSource(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	for _, sub := range []string{"decompiled", filepath.Join("sources", "source")} {
		dir := filepath.Join(clean, sub)
		if !dirExists(dir) {
			continue
		}
		// Cap at 11 to short-circuit per T-30-01-02.
		n := countRegularFiles(dir, 11)
		if n >= 10 {
			return true, sub + " has >=10 files"
		}
	}
	return false, ""
}

// probeWireProtocol covers when at least one *.proto exists under ksDir OR
// knowledge.json.protobuf_modules is a non-empty array.
func probeWireProtocol(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	if findFirstWithExt(clean, ".proto") {
		return true, "*.proto found"
	}
	if m, ok := readKnowledgeJSON(clean); ok {
		if hasNonEmpty(m["protobuf_modules"]) {
			return true, "knowledge.json.protobuf_modules non-empty"
		}
	}
	return false, ""
}

// probeAuth covers when sources/auth/ exists OR knowledge.json has any fact
// under "auth".
func probeAuth(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	if dirExists(filepath.Join(clean, "sources", "auth")) {
		return true, "sources/auth/ exists"
	}
	if m, ok := readKnowledgeJSON(clean); ok {
		if hasNonEmpty(m["auth"]) {
			return true, "knowledge.json.auth non-empty"
		}
	}
	return false, ""
}

// probeNative covers when at least one .so / .dylib / .dll appears under a
// native/ or lib*/ subdirectory.
func probeNative(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	stop := errors.New("found")
	err := filepath.WalkDir(clean, func(path string, d fs.DirEntry, ferr error) error {
		if ferr != nil {
			return nil //nolint:nilerr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !(strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".dylib") || strings.HasSuffix(name, ".dll")) {
			return nil
		}
		// Heuristic: under native/ or lib*/ ancestor segment.
		rel, rerr := filepath.Rel(clean, path)
		if rerr != nil {
			return nil //nolint:nilerr
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for i := 0; i < len(parts)-1; i++ {
			seg := strings.ToLower(parts[i])
			if seg == "native" || strings.HasPrefix(seg, "lib") {
				return stop
			}
		}
		return nil
	})
	if errors.Is(err, stop) {
		return true, "native shared library under native/ or lib*/"
	}
	return false, ""
}

// probeWebview covers webview/, cache/, or knowledge.json.webview non-empty.
func probeWebview(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	if dirExists(filepath.Join(clean, "webview")) {
		return true, "webview/ exists"
	}
	if dirExists(filepath.Join(clean, "cache")) {
		return true, "cache/ exists"
	}
	if m, ok := readKnowledgeJSON(clean); ok {
		if hasNonEmpty(m["webview"]) {
			return true, "knowledge.json.webview non-empty"
		}
	}
	return false, ""
}

// probeStorage covers storage/, leveldb/, localstate/, or any .sqlite/.db file.
func probeStorage(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	for _, sub := range []string{"storage", "leveldb", "localstate"} {
		if dirExists(filepath.Join(clean, sub)) {
			return true, sub + "/ exists"
		}
	}
	if findFirstWithExt(clean, ".sqlite", ".db") {
		return true, "sqlite/db file found"
	}
	return false, ""
}

// probeTelemetry covers knowledge.json.telemetry non-empty OR telemetry/ dir.
func probeTelemetry(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	if m, ok := readKnowledgeJSON(clean); ok {
		if hasNonEmpty(m["telemetry"]) {
			return true, "knowledge.json.telemetry non-empty"
		}
	}
	dir := filepath.Join(clean, "telemetry")
	if dirExists(dir) {
		// Any file under telemetry/.
		if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
			return true, "telemetry/ non-empty"
		}
	}
	return false, ""
}

// probeRuntime covers frida/, runtime/, or capture.json.
func probeRuntime(ksDir string, _ *sql.Conn) (bool, string) {
	if ksDir == "" {
		return false, ""
	}
	clean := filepath.Clean(ksDir)
	if dirExists(filepath.Join(clean, "frida")) {
		return true, "frida/ exists"
	}
	if dirExists(filepath.Join(clean, "runtime")) {
		return true, "runtime/ exists"
	}
	if fileExists(filepath.Join(clean, "capture.json")) {
		return true, "capture.json exists"
	}
	return false, ""
}

// hasNonEmpty reports whether v is a non-empty array, object, or string.
func hasNonEmpty(v any) bool {
	switch x := v.(type) {
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case string:
		return x != ""
	default:
		return false
	}
}
