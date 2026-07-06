/*
Copyright (c) 2026 Security Research
*/
package decompile

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
)

// HeaderInput is the data populated into the per-file provenance header.
type HeaderInput struct {
	ILSpyVersion  string    `json:"ilspy_version"`
	Model         string    `json:"model"`
	PromptName    string    `json:"prompt_name"`
	PromptHash    string    `json:"prompt_hash"`
	RawRel        string    `json:"raw_rel"`
	BeautifiedRel string    `json:"beautified_rel"`
	Timestamp     time.Time `json:"timestamp"`
}

// FileMeta is one entry in AssemblyMeta.Files.
type FileMeta struct {
	Path           string   `json:"path"`
	SizeRaw        int64    `json:"size_raw"`
	SizeBeautified int64    `json:"size_beautified"`
	Beautified     bool     `json:"beautified"`
	ChunkCount     int      `json:"chunk_count"`
	NameQuality    string   `json:"name_quality"`
	Errors         []string `json:"errors,omitempty"`
}

// AssemblyMeta is the per-assembly _meta.json schema (D-14).
type AssemblyMeta struct {
	Assembly           string     `json:"assembly"`
	SHA256             string     `json:"sha256,omitempty"`
	ILSpyCmdVersion    string     `json:"ilspycmd_version"`
	DecompileStartedAt time.Time  `json:"decompile_started_at"`
	DecompileEndedAt   time.Time  `json:"decompile_ended_at"`
	Files              []FileMeta `json:"files"`
	Errors             []string   `json:"errors,omitempty"`
}

// AssemblyManifestEntry is one entry in RunManifest.Assemblies.
type AssemblyManifestEntry struct {
	Name           string   `json:"name"`
	SHA256         string   `json:"sha256,omitempty"`
	Decompiled     bool     `json:"decompiled"`
	Beautified     bool     `json:"beautified"`
	RawPath        string   `json:"raw_path"`
	BeautifiedPath string   `json:"beautified_path,omitempty"`
	FileCount      int      `json:"file_count"`
	Errors         []string `json:"errors,omitempty"`
}

// RunManifest is the run-level manifest.json (D-14).
type RunManifest struct {
	RunID            string                  `json:"run_id"`
	StartedAt        time.Time               `json:"started_at"`
	EndedAt          time.Time               `json:"ended_at"`
	ILSpyCmdVersion  string                  `json:"ilspycmd_version"`
	AIModel          string                  `json:"ai_model"`
	PromptHash       string                  `json:"prompt_hash"`
	PromptPath       string                  `json:"prompt_path"`
	AIEnabled        bool                    `json:"ai_enabled"`
	Input            string                  `json:"input"`
	InputMode        string                  `json:"input_mode"`
	IncludeFramework bool                    `json:"include_framework"`
	Concurrency      int                     `json:"concurrency"`
	Assemblies       []AssemblyManifestEntry `json:"assemblies"`
	Errors           []string                `json:"errors,omitempty"`
}

// NewRunID returns a fresh UUIDv4 string for RunManifest.RunID.
func NewRunID() string {
	return uuid.NewString()
}

// headerLine1RE / headerLine2RE define the parseable header format.
//
// Line 1: `// unravel: ilspycmd <ver> | <model> | csharp.md@<hash> | <ts>`
// Line 2: `// raw: <rawRel>  beautified: <beautifiedRel>`
var (
	headerLine1RE = regexp.MustCompile(
		`^// unravel: ilspycmd (\S+) \| (\S+) \| ([\w.\-]+)@([0-9a-f]+) \| (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$`,
	)
	headerLine2RE = regexp.MustCompile(
		`^// raw: (\S+)\s+beautified: (\S+)$`,
	)
)

// WriteHeader writes the two-line provenance header. PromptHash is
// truncated to 8 hex chars in the visible header (full hash is in
// manifest.json). Timestamp is formatted as time.RFC3339 in UTC.
func WriteHeader(w io.Writer, h HeaderInput) error {
	defer func() { _ = recover() }() // D-20

	hash := h.PromptHash
	if len(hash) > 8 {
		hash = hash[:8]
	}
	ts := h.Timestamp.UTC().Format(time.RFC3339)
	prompt := h.PromptName
	if prompt == "" {
		prompt = "csharp.md"
	}
	if !strings.HasSuffix(prompt, ".md") {
		prompt = prompt + ".md"
	}
	line1 := fmt.Sprintf("// unravel: ilspycmd %s | %s | %s@%s | %s\n",
		h.ILSpyVersion, h.Model, prompt, hash, ts)
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

// ParseHeader reverse-parses the two-line provenance header from the
// top of a beautified .cs file. Returns an error if either line is
// missing or malformed.
func ParseHeader(text string) (*HeaderInput, error) {
	defer func() { _ = recover() }() // D-20

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
	ts, err := time.Parse(time.RFC3339, m1[5])
	if err != nil {
		return nil, fmt.Errorf("header: parse timestamp: %w", err)
	}
	return &HeaderInput{
		ILSpyVersion:  m1[1],
		Model:         m1[2],
		PromptName:    strings.TrimSuffix(m1[3], ".md"),
		PromptHash:    m1[4],
		Timestamp:     ts,
		RawRel:        m2[1],
		BeautifiedRel: m2[2],
	}, nil
}

// rejectSymlink Lstats path; if it exists and is a symlink, returns an
// error (T-05-06). Non-existent paths are OK (we are about to create them).
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

// atomicWriteJSON marshals v as indented JSON and writes it atomically
// (temp file + os.Rename) to path. The parent dir must exist.
// Symlink at path is rejected per T-05-06.
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
	// atomic rename — the actual rename step.
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// WriteAssemblyMeta atomic-writes m to <dir>/_meta.json. dir must exist
// and not be a symlink at <dir>/_meta.json.
func WriteAssemblyMeta(dir string, m AssemblyMeta) error {
	if dir == "" {
		return fmt.Errorf("WriteAssemblyMeta: empty dir")
	}
	abs, err := sanitizeOutPath("", dir)
	if err != nil {
		return fmt.Errorf("WriteAssemblyMeta: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("WriteAssemblyMeta: mkdir: %w", err)
	}
	return atomicWriteJSON(filepath.Join(abs, "_meta.json"), m)
}

// WriteRunManifest atomic-writes rm to <out>/manifest.json.
func WriteRunManifest(out string, rm RunManifest) error {
	if out == "" {
		return fmt.Errorf("WriteRunManifest: empty out")
	}
	abs, err := sanitizeOutPath("", out)
	if err != nil {
		return fmt.Errorf("WriteRunManifest: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("WriteRunManifest: mkdir: %w", err)
	}
	return atomicWriteJSON(filepath.Join(abs, "manifest.json"), rm)
}
