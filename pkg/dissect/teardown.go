/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TeardownDir returns the base teardown directory: %LOCALAPPDATA%/Unravel/dissect
func TeardownDir() string {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		if home, err := os.UserHomeDir(); err == nil {
			local = filepath.Join(home, ".local", "share")
		} else {
			local = os.TempDir()
		}
	}

	return filepath.Join(local, "Unravel", "dissect")
}

// TeardownManifest records which steps were flushed and where.
type TeardownManifest struct {
	ID             string                  `json:"id"`
	Source         string                  `json:"source"`
	OutputDirLabel string                  `json:"output_dir_label,omitempty"`
	CreatedAt      time.Time               `json:"created_at"`
	Steps          map[string]TeardownStep `json:"steps"`
}

// TeardownStep records a single flushed analysis step.
type TeardownStep struct {
	File     string        `json:"file"`
	Size     int64         `json:"size"`
	Duration time.Duration `json:"duration"`
	Status   string        `json:"status"`
}

// TeardownWriter manages per-step result flushing to disk.
// Each analysis step writes its result as a separate JSON file inside
// a UUIDv7-named directory under %LOCALAPPDATA%/Unravel/dissect/.
//
// This keeps RAM usage flat: after flushing, the caller nils the result
// pointer on DissectResult so the GC can reclaim the memory.
type TeardownWriter struct {
	mu      sync.Mutex
	baseDir string
	id      string
	steps   map[string]TeardownStep
}

// NewTeardownWriter creates a teardown directory with a UUIDv7 name and
// returns the writer. The directory is created immediately.
func NewTeardownWriter(source string) (*TeardownWriter, error) {
	id := newUUIDv7()
	dir := filepath.Join(TeardownDir(), id)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create teardown dir: %w", err)
	}

	return &TeardownWriter{
		baseDir: dir,
		id:      id,
		steps:   make(map[string]TeardownStep),
	}, nil
}

// NewTeardownWriterAt creates a teardown writer at a specific directory
// (for custom output paths like D:\unravel_teardowns\apks).
func NewTeardownWriterAt(dir string) (*TeardownWriter, error) {
	id := newUUIDv7()
	full := filepath.Join(dir, id)

	if err := os.MkdirAll(full, 0o755); err != nil {
		return nil, fmt.Errorf("create teardown dir: %w", err)
	}

	return &TeardownWriter{
		baseDir: full,
		id:      id,
		steps:   make(map[string]TeardownStep),
	}, nil
}

// Dir returns the teardown directory path.
func (tw *TeardownWriter) Dir() string {
	return tw.baseDir
}

// ID returns the UUIDv7 identifier for this teardown session.
func (tw *TeardownWriter) ID() string {
	return tw.id
}

// Flush serializes a step result to disk as JSON and records the step metadata.
// The caller should nil the corresponding pointer on DissectResult after this
// returns successfully, then call runtime.GC() to reclaim the memory.
func (tw *TeardownWriter) Flush(name string, v any, duration time.Duration, status string) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	filename := sanitizeStepName(name) + ".json"
	path := filepath.Join(tw.baseDir, filename)

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}

	tw.steps[name] = TeardownStep{
		File:     filename,
		Size:     int64(len(data)),
		Duration: duration,
		Status:   status,
	}

	return nil
}

// Load reads a previously flushed step result from disk into the target pointer.
func (tw *TeardownWriter) Load(name string, v any) error {
	tw.mu.Lock()
	step, ok := tw.steps[name]
	tw.mu.Unlock()

	if !ok {
		return fmt.Errorf("step %q not flushed", name)
	}

	path := filepath.Join(tw.baseDir, step.File)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}

	return json.Unmarshal(data, v)
}

// WriteManifest writes the teardown manifest (index of all flushed steps).
//
// BUG-06 / D-06: the manifest now records `output_dir_label` derived from the
// caller-supplied output directory basename. Future tooling can use this to
// detect output mislabel (e.g. `-o ./out/whatsapp` cache-hitting on a Discord
// payload would surface as label="whatsapp" but Source="<discord path>"; a
// downstream linter can flag the mismatch).
func (tw *TeardownWriter) WriteManifest(source string) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	manifest := TeardownManifest{
		ID:             tw.id,
		Source:         source,
		OutputDirLabel: filepath.Base(filepath.Dir(tw.baseDir)),
		CreatedAt:      time.Now().UTC(),
		Steps:          tw.steps,
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	return os.WriteFile(filepath.Join(tw.baseDir, "manifest.json"), data, 0o644)
}

// renderReport ALWAYS re-renders DISSECT_REPORT.md from the current invocation,
// regardless of whether the analysis was a fresh run or a cache hit. The
// caller passes currentSource (the absolute input path of THIS call) and
// outDir (the output workspace path); SourcePath is stamped on `result` so
// the report header reflects this invocation rather than whatever was cached.
//
// BUG-06 / D-06: fixes the stale-cache mislabel where a cache hit on hash=h
// from a prior run against pathA would write a report carrying pathA into a
// new output dir for pathB.
func renderReport(outDir string, currentSource string, result *DissectResult) error {
	if result == nil {
		return fmt.Errorf("renderReport: nil result")
	}
	// Stamp current source on the result so report header is correct even
	// when result was reconstructed from cache.
	if currentSource != "" {
		result.SourcePath = currentSource
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("renderReport: mkdir %s: %w", outDir, err)
	}
	return GenerateMarkdownReport(result, filepath.Join(outDir, "DISSECT_REPORT.md"))
}

// StepFile returns the path to a step's JSON file on disk.
func (tw *TeardownWriter) StepFile(name string) string {
	tw.mu.Lock()
	step, ok := tw.steps[name]
	tw.mu.Unlock()

	if !ok {
		return ""
	}

	return filepath.Join(tw.baseDir, step.File)
}

// HasStep returns true if a step has been flushed.
func (tw *TeardownWriter) HasStep(name string) bool {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	_, ok := tw.steps[name]
	return ok
}

// sanitizeStepName converts a step name to a safe filename component.
func sanitizeStepName(name string) string {
	safe := make([]byte, 0, len(name))
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			safe = append(safe, byte(c))
		case c == ' ', c == '-', c == '_':
			safe = append(safe, '_')
		}
	}

	if len(safe) == 0 {
		return "step"
	}

	return string(safe)
}

// newUUIDv7 generates a UUIDv7 (time-ordered, ms precision).
func newUUIDv7() string {
	now := time.Now().UnixMilli()

	var uuid [16]byte

	// 48-bit timestamp (ms since epoch)
	uuid[0] = byte(now >> 40)
	uuid[1] = byte(now >> 32)
	uuid[2] = byte(now >> 24)
	uuid[3] = byte(now >> 16)
	uuid[4] = byte(now >> 8)
	uuid[5] = byte(now)

	// Random bits for uniqueness
	rnd := make([]byte, 10)
	_, _ = rand.Read(rnd)
	copy(uuid[6:], rnd)

	// Set version (7) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x70
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// ReconstructFromDir loads a teardown manifest and all step results,
// populating a DissectResult. This is the "backward" path — loading
// previously flushed results from disk back into memory on demand.
func ReconstructFromDir(dir string) (*DissectResult, error) {
	manifestPath := filepath.Join(dir, "manifest.json")

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	var manifest TeardownManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	// Load the metadata result (contains path, detection, analyses log, errors)
	metaPath := filepath.Join(dir, "metadata.json")

	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var result DissectResult
	if err := json.Unmarshal(metaData, &result); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}

	// Load each step result back into the DissectResult
	tw := &TeardownWriter{
		baseDir: dir,
		id:      manifest.ID,
		steps:   manifest.Steps,
	}

	loadStep(tw, "apk_info", &result.APKInfo)
	loadStep(tw, "apk_verify", &result.APKVerify)
	loadStep(tw, "apk_cert", &result.APKCert)
	loadStep(tw, "manifest_info", &result.ManifestInfo)
	loadStep(tw, "manifest_analysis", &result.ManifestAnalysis)
	loadStep(tw, "secret_scan", &result.Secrets)
	loadStep(tw, "dex_analysis", &result.DEXAnalysis)
	loadStep(tw, "kotlin_detection", &result.KotlinAnalysis)
	loadStep(tw, "native_analysis", &result.NativeAnalysis)
	loadStep(tw, "framework_detection", &result.FrameworkAnalysis)
	loadStep(tw, "network_analysis", &result.NetworkAnalysis)
	loadStep(tw, "resource_analysis", &result.ResourceAnalysis)
	loadStep(tw, "obfuscation_detection", &result.ObfuscationAnalysis)
	loadStep(tw, "protobuf_analysis", &result.ProtobufAnalysis)
	loadStep(tw, "telemetry_detection", &result.TelemetryAnalysis)
	loadStep(tw, "tools_status", &result.ToolsStatus)
	loadStep(tw, "frida_scripts", &result.FridaScripts)

	return &result, nil
}

// reloadSummaryStepsForPrompt reloads the small, summary-level ATS step results
// that GenerateAIPrompt (and the workspace report) consume, from the live
// teardown back into r. In ATS mode each step is flushed to disk and its field
// nil'd to bound RAM, so without this the generated prompt reads nil and falsely
// reports "No native libraries detected" / "No Kotlin metadata detected" /
// "No permissions" on apps that clearly have them. It deliberately SKIPS the
// heavy dex_analysis (tens of MB of class/string tables) and other bulk steps —
// the prompt needs counts/flags (native libs, kotlin, permissions, components,
// signing, secrets presence), not the full tables — so RAM stays bounded.
func (r *DissectResult) reloadSummaryStepsForPrompt() {
	tw := r.teardown
	if tw == nil {
		return
	}
	loadStep(tw, "apk_info", &r.APKInfo)
	loadStep(tw, "apk_verify", &r.APKVerify)
	loadStep(tw, "apk_cert", &r.APKCert)
	loadStep(tw, "manifest_info", &r.ManifestInfo)
	loadStep(tw, "native_analysis", &r.NativeAnalysis)
	loadStep(tw, "kotlin_detection", &r.KotlinAnalysis)
	// NOTE: secret_scan is intentionally NOT reloaded — the prompt would dump
	// its findings verbatim, and until the high-entropy noise is fixed (see
	// docs/ISSUES.md "secrets scanner signal-to-noise") that floods the prompt
	// with thousands of false positives. The secrets section degrades to
	// generic guidance when r.Secrets is nil, which is the better default.
}

// loadStep is a generic helper that loads a step result from disk if it exists.
func loadStep[T any](tw *TeardownWriter, name string, target *T) {
	if !tw.HasStep(name) {
		return
	}

	var v T
	if err := tw.Load(name, &v); err == nil {
		*target = v
	}
}
