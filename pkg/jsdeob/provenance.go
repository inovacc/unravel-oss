/*
Copyright (c) 2026 Security Research
*/
package jsdeob

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"
)

// HeaderInput is the data populated into the per-file provenance header
// for jsdeob-ai output.
type HeaderInput struct {
	Decompiler    string    `json:"decompiler"` // "jsdeob-ai"
	Model         string    `json:"model"`
	PromptName    string    `json:"prompt_name"`
	PromptHash    string    `json:"prompt_hash"`
	RawRel        string    `json:"raw_rel"`
	BeautifiedRel string    `json:"beautified_rel"`
	Timestamp     time.Time `json:"timestamp"`
}

// FileMeta is one entry in ModuleMeta.Files. The D-25 field
// FrameworkDetected is the JSON-encoded FrameworkInfo for this file when
// matched, nil otherwise.
type FileMeta struct {
	Path              string                   `json:"path"`
	SizeRaw           int64                    `json:"size_raw"`
	SizeBeautified    int64                    `json:"size_beautified"`
	Beautified        bool                     `json:"beautified"`
	Reason            string                   `json:"reason,omitempty"`
	ChunkCount        int                      `json:"chunk_count"`
	NameQuality       string                   `json:"name_quality"`
	FrameworkDetected *framework.FrameworkInfo `json:"framework_detected"`
	Errors            []string                 `json:"errors,omitempty"`
}

// ModuleMeta is the per-module _meta.json schema. Field name "Module"
// instead of Phase 5's "Assembly" / Phase 6.01's "Jar" per D-21.
type ModuleMeta struct {
	Module     string     `json:"module"`
	SHA256     string     `json:"sha256,omitempty"`
	Decompiler string     `json:"decompiler"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    time.Time  `json:"ended_at"`
	Files      []FileMeta `json:"files"`
	Errors     []string   `json:"errors,omitempty"`
}

// ModuleManifestEntry is one entry in RunManifest.Modules.
type ModuleManifestEntry struct {
	Name           string   `json:"name"`
	SHA256         string   `json:"sha256,omitempty"`
	Beautified     bool     `json:"beautified"`
	RawPath        string   `json:"raw_path"`
	BeautifiedPath string   `json:"beautified_path,omitempty"`
	FileCount      int      `json:"file_count"`
	Errors         []string `json:"errors,omitempty"`
}

// RunManifest is the run-level manifest.json for a jsdeob-ai run.
type RunManifest struct {
	RunID            string                   `json:"run_id"`
	StartedAt        time.Time                `json:"started_at"`
	EndedAt          time.Time                `json:"ended_at"`
	Decompiler       string                   `json:"decompiler"`
	AIModel          string                   `json:"ai_model"`
	PromptHash       string                   `json:"prompt_hash"`
	PromptPath       string                   `json:"prompt_path"`
	AIEnabled        bool                     `json:"ai_enabled"`
	Input            string                   `json:"input"`
	InputMode        string                   `json:"input_mode"`
	PrimaryFramework *framework.FrameworkInfo `json:"primary_framework,omitempty"`
	Modules          []ModuleManifestEntry    `json:"modules"`
	Errors           []string                 `json:"errors,omitempty"`
}

// NewRunID returns a fresh UUIDv4 string for RunManifest.RunID.
func NewRunID() string { return uuid.NewString() }

// Header format: two `// unravel:` comment lines.
//
// Line 1: `// unravel: jsdeob-ai | <model> | javascript.md@<hash> | <ts>`
// Line 2: `// raw: <rawRel>  beautified: <beautifiedRel>`
var (
	headerLine1RE = regexp.MustCompile(
		`^// unravel: jsdeob-ai \| (\S+) \| ([\w.\-]+)@([0-9a-f]+) \| (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$`,
	)
	headerLine2RE = regexp.MustCompile(
		`^// raw: (\S+)\s+beautified: (\S+)$`,
	)
)

// WriteHeader writes the two-line provenance header. PromptHash is
// truncated to 8 hex chars in the visible header (full hash recorded in
// manifest.json). Timestamp is RFC3339 UTC. defer/recover at boundary
// (D-22).
func WriteHeader(w io.Writer, h HeaderInput) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("WriteHeader panic: %v", r)
		}
	}()
	hash := h.PromptHash
	if len(hash) > 8 {
		hash = hash[:8]
	}
	ts := h.Timestamp.UTC().Format(time.RFC3339)
	prompt := h.PromptName
	if prompt == "" {
		prompt = "javascript.md"
	}
	if !strings.HasSuffix(prompt, ".md") {
		prompt = prompt + ".md"
	}
	line1 := fmt.Sprintf("// unravel: jsdeob-ai | %s | %s@%s | %s\n",
		h.Model, prompt, hash, ts)
	line2 := fmt.Sprintf("// raw: %s  beautified: %s\n",
		h.RawRel, h.BeautifiedRel)
	if _, err := io.WriteString(w, line1); err != nil {
		return err
	}
	if _, err := io.WriteString(w, line2); err != nil {
		return err
	}
	return nil
}

// ParseHeader reverse-parses the two-line header from the top of a
// beautified .js file.
func ParseHeader(text string) (*HeaderInput, error) {
	defer func() { _ = recover() }()
	lines := strings.SplitN(text, "\n", 3)
	if len(lines) < 2 {
		return nil, fmt.Errorf("header: need at least 2 lines, got %d", len(lines))
	}
	m1 := headerLine1RE.FindStringSubmatch(lines[0])
	if m1 == nil {
		return nil, fmt.Errorf("header: line 1 malformed: %q", lines[0])
	}
	m2 := headerLine2RE.FindStringSubmatch(lines[1])
	if m2 == nil {
		return nil, fmt.Errorf("header: line 2 malformed: %q", lines[1])
	}
	ts, err := time.Parse(time.RFC3339, m1[4])
	if err != nil {
		return nil, fmt.Errorf("header: parse timestamp: %w", err)
	}
	return &HeaderInput{
		Decompiler:    "jsdeob-ai",
		Model:         m1[1],
		PromptName:    strings.TrimSuffix(m1[2], ".md"),
		PromptHash:    m1[3],
		Timestamp:     ts,
		RawRel:        m2[1],
		BeautifiedRel: m2[2],
	}, nil
}

// rejectSymlink Lstats path; if the path exists and is a symlink, returns
// an error (T-06-06). Non-existent paths are OK.
func rejectSymlink(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink rejected at output path: %s", path)
	}
	return nil
}

// SanitizeOutPath cleans candidate, rejects ".." traversal, makes it
// absolute, and (when root != "") verifies the result resolves under
// root. Mirrors pkg/java/beautify.sanitizeOutPath (T-06-01). Exported
// so beautify_ai.go can invoke at IO boundaries.
func SanitizeOutPath(root, candidate string) (string, error) {
	if candidate == "" {
		return "", fmt.Errorf("sanitize: empty path")
	}
	if strings.Contains(candidate, "..") {
		return "", fmt.Errorf("sanitize: path traversal rejected: %q", candidate)
	}
	cleaned := filepath.Clean(candidate)
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return "", fmt.Errorf("sanitize: path traversal rejected after clean: %q", candidate)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("sanitize: abs %q: %w", candidate, err)
	}
	if root != "" {
		rootAbs, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			return "", fmt.Errorf("sanitize: abs root %q: %w", root, err)
		}
		rel, err := filepath.Rel(rootAbs, abs)
		if err != nil {
			return "", fmt.Errorf("sanitize: rel %q under %q: %w", abs, rootAbs, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("sanitize: path %q escapes root %q", abs, rootAbs)
		}
	}
	return abs, nil
}

// atomicWriteJSON marshals v as indented JSON and writes it atomically
// (temp file + os.Rename) to path. Symlink at path is rejected per
// T-06-06. defer/recover (D-22).
func atomicWriteJSON(path string, v any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("atomicWriteJSON panic: %v", r)
		}
	}()
	if err := rejectSymlink(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".meta-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// WriteModuleMeta atomic-writes m to <dir>/_meta.json.
func WriteModuleMeta(dir string, m ModuleMeta) error {
	if dir == "" {
		return fmt.Errorf("WriteModuleMeta: empty dir")
	}
	abs, err := SanitizeOutPath("", dir)
	if err != nil {
		return fmt.Errorf("WriteModuleMeta: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("WriteModuleMeta: mkdir: %w", err)
	}
	return atomicWriteJSON(filepath.Join(abs, "_meta.json"), m)
}

// WriteRunManifest atomic-writes rm to <out>/manifest.json.
func WriteRunManifest(out string, rm RunManifest) error {
	if out == "" {
		return fmt.Errorf("WriteRunManifest: empty out")
	}
	abs, err := SanitizeOutPath("", out)
	if err != nil {
		return fmt.Errorf("WriteRunManifest: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("WriteRunManifest: mkdir: %w", err)
	}
	return atomicWriteJSON(filepath.Join(abs, "manifest.json"), rm)
}
