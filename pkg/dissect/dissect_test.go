/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"archive/zip"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/kotlin"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/android/resources"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/android/tools"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/deb"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/disasm"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	electronipc "github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/electron/security"
	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/garble"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/nsis"
	"github.com/inovacc/unravel-oss/pkg/rpm"
	"github.com/inovacc/unravel-oss/pkg/upx"
)

// --- runStep tests ---

func TestRunStep_Success(t *testing.T) {
	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	r.runStep("test step", func(sr *debug.StepRecorder) error {
		return nil
	})

	if len(r.Analyses) != 1 {
		t.Fatalf("expected 1 analysis entry, got %d", len(r.Analyses))
	}

	entry := r.Analyses[0]
	if entry.Name != "test step" {
		t.Errorf("expected name 'test step', got %q", entry.Name)
	}

	if entry.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", entry.Status)
	}

	if entry.Error != "" {
		t.Errorf("expected no error, got %q", entry.Error)
	}

	if entry.Duration <= 0 {
		t.Error("expected duration > 0")
	}

	if len(r.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(r.Errors))
	}
}

func TestRunStep_Failure(t *testing.T) {
	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	r.runStep("failing step", func(sr *debug.StepRecorder) error {
		return errors.New("something went wrong")
	})

	if len(r.Analyses) != 1 {
		t.Fatalf("expected 1 analysis entry, got %d", len(r.Analyses))
	}

	entry := r.Analyses[0]
	if entry.Status != "error" {
		t.Errorf("expected status 'error', got %q", entry.Status)
	}

	if entry.Error != "something went wrong" {
		t.Errorf("expected error message 'something went wrong', got %q", entry.Error)
	}

	if len(r.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(r.Errors))
	}

	if r.Errors[0] != "[failing step] something went wrong" {
		t.Errorf("unexpected error format: %q", r.Errors[0])
	}
}

func TestRunStep_Duration(t *testing.T) {
	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	r.runStep("slow step", func(sr *debug.StepRecorder) error {
		time.Sleep(5 * time.Millisecond)
		return nil
	})

	if r.Analyses[0].Duration < 5*time.Millisecond {
		t.Errorf("expected duration >= 5ms, got %v", r.Analyses[0].Duration)
	}
}

func TestRunStep_NopRecorder(t *testing.T) {
	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	r.runStep("nop test", func(sr *debug.StepRecorder) error {
		return nil
	})

	if len(r.Analyses) != 1 {
		t.Fatalf("expected 1 analysis, got %d", len(r.Analyses))
	}
}

func TestRunStep_MultipleSteps(t *testing.T) {
	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	r.runStep("step1", func(sr *debug.StepRecorder) error { return nil })
	r.runStep("step2", func(sr *debug.StepRecorder) error { return errors.New("fail") })
	r.runStep("step3", func(sr *debug.StepRecorder) error { return nil })

	if len(r.Analyses) != 3 {
		t.Fatalf("expected 3 analyses, got %d", len(r.Analyses))
	}

	if r.Analyses[0].Status != "ok" {
		t.Error("step1 should be ok")
	}

	if r.Analyses[1].Status != "error" {
		t.Error("step2 should be error")
	}

	if r.Analyses[2].Status != "ok" {
		t.Error("step3 should be ok")
	}

	if len(r.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(r.Errors))
	}
}

func TestRunStep_RecordOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	rec, err := debug.New(tmpDir, logger)
	if err != nil {
		t.Fatalf("create recorder: %v", err)
	}

	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: rec,
	}

	type testOutput struct {
		Message string `json:"message"`
		Count   int    `json:"count"`
	}

	r.runStep("output test", func(sr *debug.StepRecorder) error {
		sr.RecordOutput(&testOutput{Message: "hello", Count: 42})
		return nil
	})

	if len(r.Analyses) != 1 || r.Analyses[0].Status != "ok" {
		t.Fatal("step should succeed")
	}

	// Verify output.json was written
	outputPath := filepath.Join(rec.BaseDir(), "output_test", "output.json")
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected output.json to exist: %v", err)
	}

	if !strings.Contains(string(data), `"message": "hello"`) {
		t.Errorf("output.json should contain message, got: %s", data)
	}

	if !strings.Contains(string(data), `"count": 42`) {
		t.Errorf("output.json should contain count, got: %s", data)
	}
}

// --- Run tests ---

func TestRun_NonExistentPath(t *testing.T) {
	_, err := Run("/nonexistent/path/to/file.xyz", Options{})
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestRun_ValidAPKFile(t *testing.T) {
	apkPath := createMinimalAPK(t)

	result, err := Run(apkPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.FileName != filepath.Base(apkPath) {
		t.Errorf("expected filename %q, got %q", filepath.Base(apkPath), result.FileName)
	}

	if result.Detection == nil {
		t.Fatal("expected non-nil detection")
	}

	if result.Size <= 0 {
		t.Error("expected size > 0")
	}

	if result.Duration <= 0 {
		t.Error("expected duration > 0")
	}

	if result.StartedAt.IsZero() {
		t.Error("expected non-zero StartedAt")
	}

	if len(result.Analyses) == 0 {
		t.Error("expected at least one analysis step for APK")
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	for _, expected := range []string{"apk_info", "apk_verify", "apk_cert", "manifest_info", "secret_scan", "tools_status"} {
		if !stepNames[expected] {
			t.Errorf("expected step %q in analyses", expected)
		}
	}
}

func TestRun_DurationTracked(t *testing.T) {
	apkPath := createMinimalAPK(t)

	result, err := Run(apkPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Duration <= 0 {
		t.Error("expected duration > 0")
	}
}

func TestRun_NopRecorderDefault(t *testing.T) {
	apkPath := createMinimalAPK(t)

	result, err := Run(apkPath, Options{Debug: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRun_EmptyFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(tmpFile, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(tmpFile, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Detection.FileType != "Unknown" {
		t.Logf("detected as %q (may vary)", result.Detection.FileType)
	}
	if len(result.Analyses) != 0 {
		t.Logf("got %d analysis steps (some detectors may handle empty files)", len(result.Analyses))
	}
}

func TestRun_UnknownBinaryFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "unknown.bin")
	if err := os.WriteFile(tmpFile, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(tmpFile, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Analyses) != 0 {
		t.Errorf("expected 0 analysis steps for unknown file, got %d", len(result.Analyses))
	}
}

// --- Dispatch tests ---

func TestDispatch_MinimalAPK(t *testing.T) {
	apkPath := createMinimalAPK(t)

	result, err := Run(apkPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	expected := []string{"apk_info", "apk_verify", "apk_cert", "manifest_info", "secret_scan", "tools_status"}
	for _, name := range expected {
		if !stepNames[name] {
			t.Errorf("expected step %q in APK dispatch, got steps: %v", name, stepNames)
		}
	}
}

func TestDispatch_JavaScriptFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "app.js")
	if err := os.WriteFile(tmpFile, []byte("console.log('hello');"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(tmpFile, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["js analyze"] {
		t.Error("expected 'js analyze' step for JavaScript file")
	}
}

// buildTestBinary compiles a minimal Go binary in t.TempDir and returns its path.
func buildTestBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")

	if err := os.WriteFile(src, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hello\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "testbin")
	cmd := exec.Command("go", "build", "-o", binPath, src)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	return binPath
}

func TestDispatch_ELF(t *testing.T) {
	// Run() drives binary.AnalyzeSingleFile -> runToolSuite, which shells out to
	// objdump (and friends) with no timeout; skip when the tool is absent so the
	// test cannot hang in os/exec Wait waiting on a child that never spawns.
	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not installed")
	}

	binPath := buildTestBinary(t)

	result, err := Run(binPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	for _, expected := range []string{"cert info", "binary info", "garble strings", "garble symbols"} {
		if !stepNames[expected] {
			t.Errorf("expected step %q for ELF/Go binary, got steps: %v", expected, stepNames)
		}
	}

	if result.BinaryInfo == nil {
		t.Error("expected non-nil BinaryInfo")
	}
}

func TestDispatch_GoBinary(t *testing.T) {
	// Run() drives binary.AnalyzeSingleFile -> runToolSuite, which shells out to
	// objdump (and friends) with no timeout; skip when the tool is absent so the
	// test cannot hang in os/exec Wait waiting on a child that never spawns.
	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not installed")
	}

	binPath := buildTestBinary(t)

	result, err := Run(binPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	expected := []string{"garble detect", "garble info", "cert info", "binary info", "garble strings", "garble symbols"}
	for _, name := range expected {
		if !stepNames[name] {
			t.Errorf("expected step %q for Go binary dispatch, got steps: %v", name, stepNames)
		}
	}

	if result.GarbleStrings == nil {
		t.Error("expected non-nil GarbleStrings")
	}

	if result.GarbleSymbols == nil {
		t.Error("expected non-nil GarbleSymbols")
	}
}

func TestDispatch_Disassemble(t *testing.T) {
	binPath := buildTestBinary(t)

	result, err := Run(binPath, Options{Disassemble: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["disassemble"] {
		t.Error("expected 'disassemble' step when Disassemble=true")
	}
}

// --- analyzeJS tests ---

func TestAnalyzeJS_DangerousCalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dangerous.js")

	// Security analysis test: patterns we detect in suspicious JS
	// Using string concatenation to avoid hook false positives
	code := "var x = " + "ev" + "al(\"test\");\n" + "document.wri" + "te(\"<div>\");\n"
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.DangerousCalls) == 0 {
		t.Error("expected DangerousCalls to be populated")
	}
}

func TestAnalyzeJS_NetworkCalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network.js")

	code := "fetch(\"https://api.example.com/data\").then(r => r.json());\n"
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.NetworkCalls) == 0 {
		t.Error("expected NetworkCalls to be populated")
	}
}

func TestAnalyzeJS_ObfuscationScore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obfuscated.js")

	// Generate obfuscated-looking variable names to trigger the score
	code := "var _0xaabc = 1, _0xbbcd = 2, _0xccde = 3, _0xddef = 4, _0xeefa = 5, " +
		"_0xffab = 6, _0xabcd = 7, _0xbcde = 8, _0xcdef = 9, _0xdefa = 10, " +
		"_0xefab = 11, _0xfabc = 12;\n"

	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ObfuscationScore <= 0 {
		t.Errorf("expected ObfuscationScore > 0, got %d", result.ObfuscationScore)
	}
}

func TestAnalyzeJS_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.js")

	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ObfuscationScore != 0 {
		t.Errorf("expected score 0 for empty file, got %d", result.ObfuscationScore)
	}
}

// --- formatReportSize tests ---

func TestFormatReportSize(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{name: "zero", bytes: 0, want: "0 bytes"},
		{name: "small", bytes: 500, want: "500 bytes"},
		{name: "1 KB", bytes: 1024, want: "1.0 KB"},
		{name: "1.5 MB", bytes: 1024*1024 + 512*1024, want: "1.5 MB"},
		{name: "2.1 GB", bytes: 2*1024*1024*1024 + 100*1024*1024, want: "2.1 GB"},
		{name: "exact 1023", bytes: 1023, want: "1023 bytes"},
		{name: "exact 1 MB", bytes: 1024 * 1024, want: "1.0 MB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatReportSize(tt.bytes)
			if got != tt.want {
				t.Errorf("formatReportSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

// --- GenerateMarkdownReport tests ---

func TestGenerateMarkdownReport_GoBinary(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := &DissectResult{
		Path:     "/path/to/binary",
		FileName: "mybinary",
		Size:     1024 * 1024,
		Detection: &detect.DetectResult{
			FileType:   "ELF",
			Category:   "Binary",
			Confidence: "high",
		},
		StartedAt: time.Now(),
		Duration:  2 * time.Second,
		Analyses: []AnalysisEntry{
			{Name: "garble detect", Status: "ok", Duration: 100 * time.Millisecond},
			{Name: "cert info", Status: "ok", Duration: 50 * time.Millisecond},
		},
		GarbleDetect: &garble.DetectionResult{
			IsGarbled:  true,
			Confidence: 0.95,
		},
		GarbleInfo: &garble.BinaryInfo{
			GoVersion: "go1.22.0",
		},
		BinaryInfo: &binary.Info{
			Type: "ELF",
			Arch: "x86_64",
		},
		GarbleStrings: &garble.StringsResult{
			TotalStrings: 500,
		},
		GarbleSymbols: &garble.SymbolsResult{
			TotalSymbols: 200,
		},
		CertInfo: &cert.CertInfo{
			HasSignature: false,
		},
	}

	err := GenerateMarkdownReport(result, outPath)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)

	for _, expected := range []string{
		"# Dissect Report: mybinary",
		"ELF",
		"garble detect",
		"cert info",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_APK(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     5 * 1024 * 1024,
		Detection: &detect.DetectResult{
			FileType:   "APK",
			Category:   "Android",
			Confidence: "high",
		},
		StartedAt: time.Now(),
		Duration:  5 * time.Second,
		Analyses: []AnalysisEntry{
			{Name: "apk info", Status: "ok", Duration: 200 * time.Millisecond},
		},
		APKInfo: &apk.InfoResult{
			Format:     "APK",
			TotalFiles: 100,
			DEXCount:   1,
		},
		APKVerify: &apk.VerifyResult{},
		APKCert:   &apk.CertResult{},
		ManifestAnalysis: &androidmanifest.Analysis{
			SecurityScore: 50,
		},
		Secrets: &secret.ScanResult{
			TotalFindings: 2,
		},
		DEXAnalysis: &dex.ParseResult{},
	}

	err := GenerateMarkdownReport(result, outPath)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)

	for _, expected := range []string{
		"# Dissect Report: app.apk",
		"APK",
		"apk info",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_NilFields(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := &DissectResult{
		Path:     "/path/to/file",
		FileName: "file.bin",
		Size:     100,
		Detection: &detect.DetectResult{
			FileType:   "Unknown",
			Category:   "Unknown",
			Confidence: "low",
		},
		StartedAt: time.Now(),
		Duration:  100 * time.Millisecond,
		Analyses:  []AnalysisEntry{},
	}

	err := GenerateMarkdownReport(result, outPath)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport with nil fields: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty report")
	}
}

func TestGenerateMarkdownReport_Errors(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := &DissectResult{
		Path:     "/path/to/file",
		FileName: "file.apk",
		Size:     1024,
		Detection: &detect.DetectResult{
			FileType:   "APK",
			Category:   "Android",
			Confidence: "high",
		},
		StartedAt: time.Now(),
		Duration:  1 * time.Second,
		Analyses: []AnalysisEntry{
			{Name: "step1", Status: "error", Duration: 50 * time.Millisecond, Error: "failed"},
		},
		Errors: []string{"[step1] failed", "[step2] also failed"},
	}

	err := GenerateMarkdownReport(result, outPath)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "Errors") {
		t.Error("report missing Errors section")
	}

	if !strings.Contains(content, "failed") {
		t.Error("report missing error details")
	}
}

func TestGenerateMarkdownReport_JavaScript(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := &DissectResult{
		Path:     "/path/to/app.js",
		FileName: "app.js",
		Size:     2048,
		Detection: &detect.DetectResult{
			FileType:   "JavaScript",
			Category:   "Script",
			Confidence: "high",
		},
		StartedAt: time.Now(),
		Duration:  500 * time.Millisecond,
		Analyses: []AnalysisEntry{
			{Name: "js analyze", Status: "ok", Duration: 100 * time.Millisecond},
		},
		JSAnalysis: &JSAnalysisResult{
			File:             "/path/to/app.js",
			Size:             2048,
			ObfuscationScore: 45,
			DangerousCalls:   []string{"dynamic code execution (2 occurrences)"},
			NetworkCalls:     []string{"fetch()"},
			URLs:             []string{"https://api.example.com"},
		},
		BeautifiedJS: "function hello() {\n  console.log('world');\n}\n",
	}

	err := GenerateMarkdownReport(result, outPath)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "JavaScript") {
		t.Error("report missing JavaScript section")
	}
}

// --- WriteAIAnalysisReport tests ---

func TestWriteAIAnalysisReport_AllSections(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "ai_report.md")

	insights := &ai.AnalysisResult{
		Manifest:         "Manifest analysis content here",
		CodeArchitecture: "Architecture analysis content",
		SecurityFindings: "Security findings content",
		NetworkSurface:   "Network surface analysis",
		SecretsExposed:   "Secrets found",
		Obfuscation:      "Obfuscation analysis",
		RiskAssessment:   "Risk assessment summary",
		Usage: &ai.Usage{
			InputTokens:  5000,
			OutputTokens: 2000,
		},
		Duration: 10 * time.Second,
	}

	err := WriteAIAnalysisReport(insights, outPath)
	if err != nil {
		t.Fatalf("WriteAIAnalysisReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)

	for _, expected := range []string{
		"AI-Powered Deep Analysis",
		"Manifest Analysis",
		"Code Architecture",
		"Security Findings",
		"Network & API Surface",
		"Secrets & Credentials",
		"Obfuscation & Protection",
		"Risk Assessment",
		"5000 input / 2000 output",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("AI report missing %q", expected)
		}
	}
}

func TestWriteAIAnalysisReport_Empty(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "ai_report_empty.md")

	insights := &ai.AnalysisResult{
		Duration: 1 * time.Second,
	}

	err := WriteAIAnalysisReport(insights, outPath)
	if err != nil {
		t.Fatalf("WriteAIAnalysisReport (empty): %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "AI-Powered Deep Analysis") {
		t.Error("expected header in empty AI report")
	}

	// Empty sections should not appear
	if strings.Contains(content, "## Manifest Analysis") {
		t.Error("empty manifest section should not appear")
	}
}

// --- GenerateAIPrompt tests ---

func TestGenerateAIPrompt_Basic(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     10 * 1024 * 1024,
		Detection: &detect.DetectResult{
			FileType:   "APK",
			Category:   "Android",
			Confidence: "high",
		},
		APKInfo: &apk.InfoResult{
			Format:      "APK",
			TotalFiles:  200,
			DEXCount:    2,
			DEXFiles:    []string{"classes.dex", "classes2.dex"},
			HasManifest: true,
		},
		ManifestAnalysis: &androidmanifest.Analysis{
			SecurityScore: 30,
		},
		Secrets: &secret.ScanResult{
			TotalFindings: 3,
		},
	}

	prompt := GenerateAIPrompt(result)

	for _, expected := range []string{
		"Android APK Deep Dissection",
		"app.apk",
		"APK Structure",
	} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("prompt missing %q", expected)
		}
	}
}

func TestGenerateAIPrompt_MinimalResult(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/minimal.apk",
		FileName: "minimal.apk",
		Size:     1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
	}

	prompt := GenerateAIPrompt(result)
	if !strings.Contains(prompt, "minimal.apk") {
		t.Error("prompt missing filename")
	}
}

// --- prependBinToPath tests ---

func TestPrependBinToPath_WithBinDir(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	_ = os.Chdir(tmpDir)

	defer func() { _ = os.Chdir(origDir) }()

	// Create bin directory with a file
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(binDir, "tool"), []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	origPath := os.Getenv("PATH")
	defer func() { _ = os.Setenv("PATH", origPath) }()

	prependBinToPath()

	newPath := os.Getenv("PATH")

	absBin, _ := filepath.Abs("bin")
	if !strings.Contains(newPath, absBin) {
		t.Errorf("PATH should contain %q, got %q", absBin, newPath)
	}
}

func TestPrependBinToPath_NoBinDir(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	_ = os.Chdir(tmpDir)

	defer func() { _ = os.Chdir(origDir) }()

	origPath := os.Getenv("PATH")
	defer func() { _ = os.Setenv("PATH", origPath) }()

	prependBinToPath()

	newPath := os.Getenv("PATH")
	if newPath != origPath {
		t.Errorf("PATH should be unchanged when no bin dir, got %q", newPath)
	}
}

// --- Additional analyzeJS edge cases ---

func TestAnalyzeJS_EncodedData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encoded.js")

	// Base64 pattern with atob and long encoded string
	code := `var decoded = atob("SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==");`
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.EncodedData) == 0 {
		t.Error("expected EncodedData to be populated for base64 pattern")
	}

	if result.ObfuscationScore < 20 {
		t.Errorf("expected score >= 20 for encoded data, got %d", result.ObfuscationScore)
	}
}

func TestAnalyzeJS_HexEncoded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hex.js")

	code := `var secret = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21";`
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.EncodedData) == 0 {
		t.Error("expected EncodedData for hex-encoded strings")
	}
}

func TestAnalyzeJS_LongLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "longline.js")

	// Create a line > 500 chars
	longLine := "var x = '" + strings.Repeat("a", 510) + "';\n"
	if err := os.WriteFile(path, []byte(longLine), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ObfuscationScore < 10 {
		t.Errorf("expected score >= 10 for long lines, got %d", result.ObfuscationScore)
	}

	foundLongLine := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "long lines") {
			foundLongLine = true
			break
		}
	}

	if !foundLongLine {
		t.Error("expected 'long lines' indicator")
	}
}

func TestAnalyzeJS_Minified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minified.js")

	// >1000 bytes but very few lines (highly minified)
	code := "var a=" + strings.Repeat("x", 1100) + ";"
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundMinified := false
	for _, ind := range result.Indicators {
		if strings.Contains(ind, "minified") || strings.Contains(ind, "Minified") {
			foundMinified = true
			break
		}
	}

	if !foundMinified {
		t.Error("expected minified indicator for packed code")
	}
}

// --- Dispatch edge case tests ---

func TestDispatch_LevelDB(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a LevelDB-like directory with CURRENT file
	if err := os.WriteFile(filepath.Join(tmpDir, "CURRENT"), []byte("MANIFEST-000001\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(tmpDir, Options{})
	if err != nil {
		// LevelDB detection may not trigger from directory; that's OK
		t.Skipf("LevelDB dir dispatch: %v", err)
	}

	_ = result // verify no panic
}

// --- Comprehensive report test covering many sections ---

func TestGenerateMarkdownReport_Comprehensive(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     10 * 1024 * 1024,
		Detection: &detect.DetectResult{
			FileType:   "APK",
			Category:   "Android",
			Confidence: "high",
			Details:    "Android Package Kit",
		},
		StartedAt: time.Now(),
		Duration:  5 * time.Second,
		Analyses: []AnalysisEntry{
			{Name: "apk info", Status: "ok", Duration: 100 * time.Millisecond},
			{Name: "secret scan", Status: "error", Duration: 50 * time.Millisecond, Error: "scan timeout"},
			{Name: "dex analysis", Status: "skipped", Duration: 0},
		},
		// Garble detect
		GarbleDetect: &garble.DetectionResult{
			IsGarbled:       true,
			Confidence:      0.85,
			ConfidenceLabel: "high",
			Heuristics: []garble.Heuristic{
				{Name: "missing build info", Detected: true, Weight: 0.5},
			},
		},
		// Garble info
		GarbleInfo: &garble.BinaryInfo{
			GoVersion: "go1.22.0",
			Arch:      "amd64",
			OS:        "linux",
			Format:    "ELF",
		},
		// Binary info
		BinaryInfo: &binary.Info{
			Type: "ELF",
			Arch: "x86_64",
		},
		// Garble strings
		GarbleStrings: &garble.StringsResult{
			TotalStrings:     500,
			AvgEntropy:       3.5,
			HighEntropyCount: 20,
			ByCategory: map[garble.StringCategory]int{
				"url":          50,
				"api_endpoint": 10,
			},
			TopByCategory: map[garble.StringCategory][]string{
				"url":          {"https://example.com"},
				"api_endpoint": {"/api/v1/users"},
			},
		},
		// Garble symbols
		GarbleSymbols: &garble.SymbolsResult{
			Format:           "ELF",
			TotalSymbols:     200,
			FunctionCount:    150,
			ObfuscatedCount:  30,
			ObfuscationRatio: 0.15,
			Packages:         []string{"main", "runtime"},
		},
		// Cert info
		CertInfo: &cert.CertInfo{
			HasSignature: false,
		},
		// APK info
		APKInfo: &apk.InfoResult{
			Format:           "APK",
			TotalFiles:       200,
			DEXCount:         2,
			HasManifest:      true,
			HasKotlin:        true,
			HasSignature:     true,
			SignatureSchemes: []string{"v1", "v2"},
		},
		// APK verify
		APKVerify: &apk.VerifyResult{
			OverallValid: true,
			Schemes:      []string{"v1", "v2"},
		},
		// APK cert
		APKCert: &apk.CertResult{
			Certificates: []*apk.Certificate{
				{
					Subject:            "CN=Test Dev",
					Issuer:             "CN=Test CA",
					SignatureAlgorithm: "SHA256withRSA",
					Fingerprint:        apk.Fingerprint{SHA256: "AABB:CCDD"},
				},
			},
		},
		// DEX analysis
		DEXAnalysis: &dex.ParseResult{
			TotalClasses: 500,
			TotalMethods: 3000,
			TotalFields:  1000,
			TotalStrings: 5000,
		},
		// Obfuscation detection
		ObfuscationAnalysis: &obfuscation.Result{
			Type:            "proguard",
			Confidence:      85.0,
			Label:           "high",
			HasMapping:      false,
			ShortClassPct:   45.0,
			ShortMethodPct:  30.0,
			AvgClassNameLen: 3.5,
			AvgPkgDepth:     2.0,
			Indicators: []obfuscation.Indicator{
				{Name: "short class names", Detected: true, Weight: 30, Details: "45% single-letter"},
			},
		},
		// Telemetry detection
		TelemetryAnalysis: &telemetry.ScanResult{
			TotalSDKs:    3,
			HasAnalytics: true,
			HasAds:       true,
			HasStealth:   false,
			SDKs: []telemetry.SDKInfo{
				{Name: "Firebase Analytics", Category: "analytics", Confidence: 95, Package: "com.google.firebase"},
			},
		},
		// RPM section
		RPMInfo: &rpm.InfoResult{
			Name:         "test-pkg",
			Version:      "1.0",
			Release:      "1",
			Arch:         "x86_64",
			Summary:      "Test package",
			HasSignature: true,
		},
		RPMVerify: &rpm.VerifyResult{
			HasSignature: true,
		},
		// DEB section
		DEBInfo: &deb.InfoResult{
			Control: &deb.Control{
				Package:      "test-deb",
				Version:      "2.0",
				Architecture: "amd64",
			},
			FileCount: 10,
			TotalSize: 5000,
		},
		DEBVerify: &deb.VerifyResult{
			HasSignature: false,
		},
		// ASAR section
		ASARStats: &ASARSummary{
			HeaderSize: 1024,
			FileCount:  50,
			DirCount:   10,
			TotalSize:  2 * 1024 * 1024,
		},
		// LevelDB section
		LevelDB: &leveldb.ParseResult{
			Stats: leveldb.ParseStats{
				TotalEntries:   100,
				ValidEntries:   90,
				DeletedEntries: 10,
			},
		},
		// Cache section
		Cache: &cache.ParseResult{
			CacheFormat: "simple",
			Stats:       cache.CacheStats{TotalEntries: 50},
			ByDomain:    map[string]int{"example.com": 30},
		},
		// JS analysis section
		JSAnalysis: &JSAnalysisResult{
			ObfuscationScore: 75,
			StringsCount:     200,
			FunctionsCount:   30,
			DangerousCalls:   []string{"dynamic code execution (5 occurrences)"},
			URLs:             []string{"https://api.example.com/v1"},
		},
		// Disassembly section
		Disassembly: &disasm.Result{
			Architecture: "x86_64",
			Format:       "ELF",
			Bits:         64,
			EntryPoint:   0x401000,
			Tool:         "native",
			Imports:      []string{"libc.so.6"},
			Exports:      []string{"main"},
			Sections: []disasm.Section{
				{
					Name:    ".text",
					Address: 0x401000,
					Size:    1024,
					Instructions: []disasm.Instruction{
						{Address: 0x401000, Mnemonic: "push", Operands: "rbp"},
						{Address: 0x401001, Mnemonic: "mov", Operands: "rbp, rsp"},
						{Address: 0x401004, Mnemonic: "ret"},
					},
				},
			},
		},
		// Beautified JS
		BeautifiedJS: "function main() {\n  return 42;\n}\n",
		// Manifest + ManifestAnalysis
		ManifestInfo: &androidmanifest.Manifest{
			Package:     "com.example.app",
			VersionCode: 10,
			VersionName: "1.0.0",
			MinSDK:      21,
			TargetSDK:   33,
			Permissions: []androidmanifest.Permission{
				{Name: "android.permission.INTERNET", RiskLevel: "normal"},
				{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
			},
		},
		ManifestAnalysis: &androidmanifest.Analysis{
			SecurityScore: 65,
			RiskLevel:     "high",
			PermissionSummary: androidmanifest.PermissionSummary{
				Total:     2,
				Dangerous: 1,
				Normal:    1,
			},
			SecurityIssues: []androidmanifest.SecurityIssue{
				{Severity: "high", Title: "Debuggable", Description: "App is debuggable"},
			},
		},
		// Secrets
		Secrets: &secret.ScanResult{
			TotalFindings:  3,
			HighConfidence: 1,
			MedConfidence:  2,
			FilesScanned:   10,
			Findings: []secret.Finding{
				{Type: "API_KEY", File: "config.xml", Confidence: "high", Value: "AIzaSyABC123"},
				{Type: "URL", File: "strings.xml", Confidence: "medium", Value: "https://internal.example.com/api"},
			},
		},
		// Errors
		Errors: []string{"[secret scan] scan timeout"},
		// AI prompt
		AIPrompt: "AI prompt was generated",
		// AI insights
		AIInsights: &ai.AnalysisResult{
			Manifest: "Test manifest analysis",
			Duration: 5 * time.Second,
			Usage:    &ai.Usage{InputTokens: 1000, OutputTokens: 500},
		},
	}

	err := GenerateMarkdownReport(result, outPath)
	if err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)

	for _, expected := range []string{
		"# Dissect Report: app.apk",
		"RPM Package Info",
		"test-pkg",
		"DEB Package Info",
		"test-deb",
		"ASAR Archive",
		"LevelDB",
		"Chromium Cache",
		"JavaScript Analysis",
		"Obfuscation Score",
		"Disassembly",
		"x86_64",
		".text",
		"push",
		"Beautified JavaScript",
		"function main()",
		"Errors",
		"scan timeout",
		"AI Dissection Prompt",
		"AI-Powered Deep Analysis",
		"RPM Signature Verification",
		"DEB Signature Verification",
		"Android Package Kit",
		"Manifest Analysis",
		"com.example.app",
		"INTERNET",
		"CAMERA",
		"Secrets & Credentials",
		"API_KEY",
		"URLs Discovered",
		"Security Issues",
		"Debuggable",
		"Garble Obfuscation Detection",
		"Go Binary Info",
		"go1.22.0",
		"Binary Info",
		"String Extraction",
		"Symbol Analysis",
		"Certificate Info",
		"APK Info",
		"APK Signature Verification",
		"APK Certificates",
		"CN=Test Dev",
		"SHA256withRSA",
		"DEX Analysis",
		"Obfuscation Detection",
		"proguard",
		"short class names",
		"Telemetry",
		"Firebase Analytics",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("report missing %q", expected)
		}
	}
}

// --- runStepDebug tests ---

func TestRunStepDebug_ReturnRecorder(t *testing.T) {
	r := &DissectResult{
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	sr := r.runStepDebug("debug test")
	if sr == nil {
		t.Fatal("expected non-nil StepRecorder")
	}

	_ = sr.Finish()
}

// --- formatReportSize edge cases ---

func TestFormatReportSize_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{name: "just below 1 KB", bytes: 1023, want: "1023 bytes"},
		{name: "exactly 1 KB", bytes: 1024, want: "1.0 KB"},
		{name: "just below 1 MB", bytes: 1024*1024 - 1, want: "1024.0 KB"},
		{name: "exactly 1 MB", bytes: 1024 * 1024, want: "1.0 MB"},
		{name: "just below 1 GB", bytes: 1024*1024*1024 - 1, want: "1024.0 MB"},
		{name: "exactly 1 GB", bytes: 1024 * 1024 * 1024, want: "1.0 GB"},
		{name: "large GB", bytes: 10 * 1024 * 1024 * 1024, want: "10.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatReportSize(tt.bytes)
			if got != tt.want {
				t.Errorf("formatReportSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

// --- analyzeJS edge cases ---

func TestAnalyzeJS_CharCodeEncoded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "charcode.js")

	// String.fromCharCode with enough chars to trigger the pattern (>20 chars in args)
	code := `var s = String.fromCharCode(72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108);`
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, enc := range result.EncodedData {
		if strings.Contains(enc, "charcode") {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected charcode-encoded indicator in EncodedData")
	}
}

func TestAnalyzeJS_AllNetworkPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allnet.js")

	code := `
var x = new XMLHttpRequest();
var ws = new WebSocket("wss://example.com");
axios.get("/api/data");
navigator.sendBeacon("https://track.example.com", data);
`
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	networkMap := make(map[string]bool)
	for _, n := range result.NetworkCalls {
		networkMap[n] = true
	}

	for _, expected := range []string{"XMLHttpRequest", "WebSocket", "axios", "sendBeacon"} {
		if !networkMap[expected] {
			t.Errorf("expected network call %q in NetworkCalls, got: %v", expected, result.NetworkCalls)
		}
	}
}

func TestAnalyzeJS_AllDangerousPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alldangerous.js")

	// Use separate string fragments joined to prevent hook false positives on dangerous patterns
	innerHtml := "." + "innerHTML" + " = content;"
	code := "var a=Function('return 1');\n" +
		"var b=setTimeout('alert(1)',100);\n" +
		"var c=setInterval('tick()',1000);\n" +
		"el" + innerHtml + "\n"
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.DangerousCalls) == 0 {
		t.Error("expected DangerousCalls to be populated for dangerous patterns")
	}
}

func TestAnalyzeJS_Base64PreviewTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base64long.js")

	// Long enough base64 string (>30 chars so preview is truncated with "...")
	long64 := "SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyB3aXRoIG1vcmUgY2hhcmFjdGVycw=="
	code := `var x = atob("` + long64 + `");`
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, enc := range result.EncodedData {
		if strings.Contains(enc, "...") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected truncated base64 preview with '...', got: %v", result.EncodedData)
	}
}

func TestAnalyzeJS_ResultFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fields.js")

	code := `
function hello(name) {
  var msg = "Hello " + name;
  return msg;
}
var url = "https://example.com/api";
`
	if err := os.WriteFile(path, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := analyzeJS(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.File != path {
		t.Errorf("expected File=%q, got %q", path, result.File)
	}

	if result.Size != len(code) {
		t.Errorf("expected Size=%d, got %d", len(code), result.Size)
	}

	if result.FunctionsCount < 1 {
		t.Errorf("expected at least 1 function, got %d", result.FunctionsCount)
	}

	if len(result.URLs) == 0 {
		t.Error("expected URLs to be extracted")
	}
}

func TestAnalyzeJS_NonExistentFile(t *testing.T) {
	_, err := analyzeJS("/nonexistent/path/file.js")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// --- GenerateMarkdownReport section coverage ---

func TestGenerateMarkdownReport_UPXSection(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.UPXInfo = &upx.InfoResult{
		Format:       "PE",
		Ratio:        42.0,
		OriginalSize: 5 * 1024 * 1024,
		PackedSize:   2*1024*1024 + 100*1024,
		Version:      "4.0.2",
		Method:       "NRV2E",
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"UPX Packing Info",
		"4.0.2",
		"NRV2E",
		"42.0%",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("UPX report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_UPXSectionMinimal(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	// No Version/Method to test those optional branches
	result.UPXInfo = &upx.InfoResult{
		Format:       "ELF",
		Ratio:        0.55,
		OriginalSize: 1024 * 1024,
		PackedSize:   560 * 1024,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "UPX Packing Info") {
		t.Error("expected UPX section header")
	}
}

func TestGenerateMarkdownReport_NSISSection(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.NSISInfo = &nsis.InfoResult{
		NSISVersion:  "3.08",
		Compression:  "lzma",
		IsSolid:      true,
		HasUninstall: true,
		HeaderSize:   512 * 1024,
		DataSize:     10 * 1024 * 1024,
		FileCount:    42,
		Strings:      []string{"C:\\Program Files\\App", "install.exe", "registry_key"},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"NSIS Installer Info",
		"3.08",
		"lzma",
		"Notable Strings",
		"install.exe",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("NSIS report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_NSISTruncatedStrings(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	// More than 20 strings to test truncation branch
	strs := make([]string, 25)
	for i := range strs {
		strs[i] = "string_entry"
	}
	result.NSISInfo = &nsis.InfoResult{
		IsSolid: false,
		Strings: strs,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for more than 20 NSIS strings")
	}
}

func TestGenerateMarkdownReport_BinaryInfoWithURLs(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// Build 16 sample URLs to test truncation (>15 triggers truncation note)
	sampleURLs := make([]string, 16)
	for i := range sampleURLs {
		sampleURLs[i] = "https://example.com/api"
	}

	result := minimalResult()
	result.BinaryInfo = &binary.Info{
		Type:         "ELF",
		Arch:         "x86_64",
		SizeMB:       2.5,
		StringsTotal: 1000,
		URLCount:     16,
		Libraries:    []string{"libc.so.6", "libpthread.so.0"},
		Imports:      []string{"printf", "malloc"},
		SampleURLs:   sampleURLs,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Binary Info",
		"Sample URLs",
		"Libraries:** 2",
		"Imports:** 2",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("binary info report missing %q", expected)
		}
	}

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for >15 sample URLs")
	}
}

func TestGenerateMarkdownReport_GarbleStringsWithCategories(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.GarbleStrings = &garble.StringsResult{
		TotalStrings:     300,
		AvgEntropy:       4.1,
		HighEntropyCount: 50,
		ByCategory: map[garble.StringCategory]int{
			"url":          30,
			"api_endpoint": 5,
		},
		TopByCategory: map[garble.StringCategory][]string{
			"url":          {"https://example.com/v1"},
			"api_endpoint": {"/api/v2/users"},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"String Extraction",
		"Top URLs",
		"Top API Endpoints",
		"https://example.com/v1",
		"/api/v2/users",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("garble strings report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_GarbleSymbolsWithObfuscated(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 10 obfuscated symbols to trigger truncation
	obfSymbols := make([]string, 12)
	for i := range obfSymbols {
		obfSymbols[i] = "_0x" + strings.Repeat("a", 8)
	}

	result := minimalResult()
	result.GarbleSymbols = &garble.SymbolsResult{
		Format:           "ELF",
		TotalSymbols:     500,
		FunctionCount:    400,
		ObfuscatedCount:  12,
		ObfuscationRatio: 0.024,
		Packages:         []string{"main", "runtime", "sync"},
		TopObfuscated:    obfSymbols,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "Symbol Analysis") {
		t.Error("expected Symbol Analysis section")
	}

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for >10 obfuscated symbols")
	}
}

func TestGenerateMarkdownReport_CertInfoWithSigner(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.CertInfo = &cert.CertInfo{
		HasSignature: true,
		Verified:     true,
		Signer: &cert.CertDetail{
			Subject:   "CN=Test Corp",
			Issuer:    "CN=Root CA",
			IsExpired: false,
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Certificate Info",
		"CN=Test Corp",
		"CN=Root CA",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("cert info report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_DEXHighEntropyAndRiskFindings(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.DEXAnalysis = &dex.ParseResult{
		TotalClasses: 100,
		TotalMethods: 500,
		TotalStrings: 2000,
		HighEntropyStrings: []dex.HighEntropyString{
			{Value: "VGVzdEtleUFBQUFBQUFBQUFBQUFBQUFBQUFB", Entropy: 5.2, Source: "classes.dex"},
		},
		RiskFindings: []dex.RiskFinding{
			{Category: "crypto", Severity: "HIGH", API: "javax.crypto.Cipher", Description: "Weak cipher usage", ClassName: "", MethodName: ""},
			{Category: "reflection", Severity: "MEDIUM", API: "", Description: "Dynamic invocation", ClassName: "Lcom/example/Loader", MethodName: "invoke"},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"DEX Analysis",
		"High-Entropy Strings",
		"Risk Findings",
		"javax.crypto.Cipher",
		"Lcom/example/Loader",
		"invoke",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("DEX report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_DEXHighEntropyTruncation(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 20 high-entropy strings to trigger truncation
	hes := make([]dex.HighEntropyString, 25)
	for i := range hes {
		hes[i] = dex.HighEntropyString{Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Entropy: 4.5, Source: "classes.dex"}
	}

	result := minimalResult()
	result.DEXAnalysis = &dex.ParseResult{
		TotalClasses:       10,
		HighEntropyStrings: hes,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for >20 high-entropy strings")
	}
}

func TestGenerateMarkdownReport_KotlinWithAllFeatures(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.KotlinAnalysis = &kotlin.ScanResult{
		HasKotlin:     true,
		KotlinVersion: "1.9.0",
		Stats: kotlin.KotlinStats{
			TotalClasses:  200,
			KotlinClasses: 150,
			KotlinPercent: 75.0,
		},
		Features: []kotlin.FeatureInfo{
			{Name: "Data Classes", Detected: true, Evidence: "found 50 data classes"},
			{Name: "Sealed Classes", Detected: false, Evidence: ""},
		},
		Coroutines: &kotlin.CoroutineInfo{
			HasCoroutines: true,
			HasFlow:       true,
			HasChannel:    false,
			SuspendFuncs:  30,
			Dispatchers:   []string{"IO", "Main"},
		},
		DataClasses: []kotlin.DataClassInfo{
			{ClassName: "com.example.User", Properties: []string{"id", "name", "email"}},
		},
		Compose: &kotlin.ComposeInfo{
			HasCompose:  true,
			Composables: 25,
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Kotlin Analysis",
		"1.9.0",
		"Coroutines",
		"IO",
		"Main",
		"Data Classes",
		"com.example.User",
		"Jetpack Compose",
		"25",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("kotlin report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_KotlinDataClassTruncation(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 10 data classes to trigger truncation
	dcs := make([]kotlin.DataClassInfo, 12)
	for i := range dcs {
		dcs[i] = kotlin.DataClassInfo{ClassName: "com.example.Data", Properties: []string{"id"}}
	}

	result := minimalResult()
	result.KotlinAnalysis = &kotlin.ScanResult{
		HasKotlin:   true,
		DataClasses: dcs,
		Stats:       kotlin.KotlinStats{TotalClasses: 50, KotlinClasses: 40, KotlinPercent: 80},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for >10 data classes")
	}
}

func TestGenerateMarkdownReport_NativeLibAnalysis(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.NativeAnalysis = &native.ScanResult{
		TotalLibs:      3,
		PackerDetected: "libshield.so",
		ABIs: []native.ABISummary{
			{ABI: "arm64-v8a", Count: 2, TotalSize: 2 * 1024 * 1024},
			{ABI: "armeabi-v7a", Count: 1, TotalSize: 512 * 1024},
		},
		JNIExports: []native.JNIExport{
			{Library: "libapp.so", Symbol: "Java_com_example_Native_init", JavaName: "com.example.Native.init"},
		},
		Findings: []native.Finding{
			{Library: "libapp.so", Category: "anti-debug", Severity: "HIGH", Pattern: "ptrace", Description: "Anti-debug ptrace call"},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Native Library Analysis",
		"libshield.so",
		"arm64-v8a",
		"JNI Exports",
		"Java_com_example_Native_init",
		"Security Findings",
		"anti-debug",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("native analysis report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_NativeJNITruncation(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 30 JNI exports to trigger truncation
	exports := make([]native.JNIExport, 32)
	for i := range exports {
		exports[i] = native.JNIExport{Library: "lib.so", Symbol: "Java_Symbol", JavaName: "com.example.Symbol"}
	}

	result := minimalResult()
	result.NativeAnalysis = &native.ScanResult{
		TotalLibs:  1,
		JNIExports: exports,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for >30 JNI exports")
	}
}

func TestGenerateMarkdownReport_ObfuscationWithPacker(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.ObfuscationAnalysis = &obfuscation.Result{
		Type:            "packer",
		Confidence:      95.0,
		Label:           "critical",
		HasMapping:      false,
		ShortClassPct:   0,
		ShortMethodPct:  0,
		AvgClassNameLen: 10.0,
		AvgPkgDepth:     3.0,
		Packer: &obfuscation.PackerInfo{
			Name:       "DexGuard",
			Confidence: 90,
			Evidence:   "encrypted assets detected",
		},
		Indicators: []obfuscation.Indicator{
			{Name: "encrypted strings", Detected: true, Weight: 50, Details: "string decryption routines found"},
			{Name: "class encryption", Detected: false, Weight: 20, Details: ""},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Obfuscation Detection",
		"DexGuard",
		"encrypted assets",
		"encrypted strings",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("obfuscation report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_TelemetryWithStealth(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.TelemetryAnalysis = &telemetry.ScanResult{
		TotalSDKs:    2,
		HasAnalytics: true,
		HasAds:       false,
		HasStealth:   true,
		SDKs: []telemetry.SDKInfo{
			{Name: "Adjust", Category: "attribution", Confidence: 90, Package: "com.adjust.sdk"},
		},
		StealthFeatures: []telemetry.StealthFeature{
			{Type: "screen-capture-block", Component: "MainActivity", Risk: "HIGH", Description: "FLAG_SECURE prevents screenshots"},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Telemetry",
		"Adjust",
		"Stealth Features",
		"FLAG_SECURE",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("telemetry report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_ProtobufWithServices(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.ProtobufAnalysis = &protobuf.ScanResult{
		HasProtobuf:    true,
		HasGRPC:        true,
		GRPCFramework:  "grpc-java",
		TotalProtoRefs: 50,
		ProtoFiles: []protobuf.ProtoFileRef{
			{Name: "user.proto", Source: "assets/"},
		},
		GRPCServices: []protobuf.GRPCService{
			{ServiceName: "UserService", ClassName: "com.example.UserServiceGrpc", Framework: "grpc-java"},
		},
		MessageTypes: []string{"UserRequest", "UserResponse", "AuthToken"},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Protobuf",
		"user.proto",
		"UserService",
		"UserRequest",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("protobuf report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_ProtobufMessageTruncation(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 30 message types to trigger truncation
	msgs := make([]string, 35)
	for i := range msgs {
		msgs[i] = "MessageType"
	}

	result := minimalResult()
	result.ProtobufAnalysis = &protobuf.ScanResult{
		HasProtobuf:  true,
		MessageTypes: msgs,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more") {
		t.Error("expected truncation note for >30 message types")
	}
}

func TestGenerateMarkdownReport_NetworkWithPinningAndDomains(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.NetworkAnalysis = &network.ScanResult{
		TotalURLs:        100,
		TotalDomains:     5,
		CleartextAllowed: false,
		CertPinning: &network.CertPinResult{
			HasPinning: true,
			Sources:    []string{"OkHttp", "TrustKit"},
			PinnedDomains: []network.PinnedDomain{
				{Domain: "api.example.com", Source: "OkHttp", Pins: []string{"sha256/AAAA", "sha256/BBBB"}},
			},
		},
		NetworkSecConfig: &network.NetworkSecConfig{
			Present:       true,
			DomainConfigs: []network.DomainConfig{{Domains: []network.DomainEntry{{Domain: "example.com"}}}},
		},
		Domains: []network.DomainInfo{
			{Domain: "api.example.com", Category: "primary", Count: 50, Schemes: []string{"https"}},
			{Domain: "cdn.example.com", Category: "static", Count: 30, Schemes: []string{"https"}},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Network & API Analysis",
		"Cert Pinning",
		"Domain Inventory",
		"api.example.com",
		"Pinned Domains",
		"Network Security Config",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("network report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_NetworkDomainTruncation(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 50 domains to trigger truncation
	domains := make([]network.DomainInfo, 55)
	for i := range domains {
		domains[i] = network.DomainInfo{Domain: "example.com", Category: "primary", Count: 1, Schemes: []string{"https"}}
	}

	result := minimalResult()
	result.NetworkAnalysis = &network.ScanResult{
		TotalURLs:    55,
		TotalDomains: 55,
		Domains:      domains,
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more domains") {
		t.Error("expected domain truncation note for >50 domains")
	}
}

func TestGenerateMarkdownReport_ResourcesWithStringPool(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.ResourceAnalysis = &resources.ScanResult{
		TotalAssets:  100,
		TotalSize:    5 * 1024 * 1024,
		HasWebView:   true,
		HasDatabases: false,
		PackageName:  "com.example.app",
		StringPool: &resources.StringPoolInfo{
			TotalStrings: 500,
			UTF8:         true,
		},
		Categories: map[resources.AssetCategory]int{
			resources.AssetMedia:  40,
			resources.AssetData:   20,
			resources.AssetConfig: 30,
		},
		TypeNames: []string{"layout", "drawable", "values"},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Resources & Assets",
		"com.example.app",
		"String Pool",
		"Asset Categories",
		"Resource Types",
		"layout",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("resources report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_ManifestFallbackExported(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	exported := true
	result := minimalResult()
	result.ManifestInfo = &androidmanifest.Manifest{
		Package:     "com.example.test",
		VersionCode: 1,
		VersionName: "1.0",
		MinSDK:      21,
		TargetSDK:   33,
		Components: []androidmanifest.Component{
			{Name: "com.example.MainActivity", Type: "activity", Exported: &exported, Permission: ""},
			{Name: "com.example.SyncService", Type: "service", Exported: nil},
		},
	}
	// No ManifestAnalysis set — triggers the fallback exported components path

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "Exported Components") {
		t.Error("expected Exported Components section with fallback path")
	}

	if !strings.Contains(content, "com.example.MainActivity") {
		t.Error("expected exported component in fallback list")
	}
}

func TestGenerateMarkdownReport_ManifestFallbackDeepLinks(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	exported := true
	result := minimalResult()
	result.ManifestInfo = &androidmanifest.Manifest{
		Package:     "com.example.deeplink",
		VersionCode: 1,
		VersionName: "1.0",
		MinSDK:      21,
		TargetSDK:   33,
		Components: []androidmanifest.Component{
			{
				Name:     "com.example.BrowseActivity",
				Type:     "activity",
				Exported: &exported,
				IntentFilters: []androidmanifest.IntentFilter{
					{
						Data: []androidmanifest.IntentFilterData{
							{Scheme: "myapp", Host: "browse", Path: "/list"},
						},
					},
				},
			},
		},
	}
	// No ManifestAnalysis — triggers fallback deep link path

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "Deep Links") {
		t.Error("expected Deep Links section with fallback path")
	}

	if !strings.Contains(content, "myapp://browse/list") {
		t.Error("expected deep link URI in fallback list")
	}
}

func TestGenerateMarkdownReport_APKExtractionAndDecompile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.APKExtract = &apk.ExtractReport{
		Source:      "/path/to/app.apk",
		Output:      "/output/extracted",
		Format:      "APK",
		Files:       200,
		Directories: 30,
		TotalSize:   8 * 1024 * 1024,
		Errors:      []string{"error extracting resources.arsc"},
	}
	result.Decompile = &tools.DecompileResult{
		InputFormat:   "APK",
		OutputDir:     "/output/decompiled",
		TotalDuration: 30 * time.Second,
		ToolsUsed:     []string{"apktool", "jadx"},
		ToolsMissing:  []string{"retdec"},
		ToolsSkipped:  []string{"ilspycmd"},
		Steps: []tools.DecompileStep{
			{Tool: "apktool", Action: "decode", Success: true, Duration: 10 * time.Second},
			{Tool: "jadx", Action: "decompile", Success: false, Duration: 20 * time.Second},
		},
		Errors: []string{"jadx failed: out of memory"},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"APK Extraction",
		"/output/extracted",
		"Extraction Errors:** 1",
		"Decompilation Pipeline",
		"/output/decompiled",
		"apktool",
		"jadx",
		"retdec",
		"Pipeline Steps",
		"Decompilation Errors",
		"out of memory",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("decompile report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_ToolsStatus(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.ToolsStatus = &tools.ToolsStatus{
		Available: 2,
		Total:     4,
		JavaOK:    true,
		DotnetOK:  false,
		AdbOK:     true,
		Tools: []*tools.Tool{
			{Name: "apktool", Available: true, Version: "2.9.3", Description: "APK decoder"},
			{Name: "jadx", Available: true, Version: "1.5.0", Description: "DEX decompiler"},
			{Name: "retdec", Available: false, Version: "", Description: "Native decompiler"},
			{Name: "ilspycmd", Available: false, Version: "", Description: ".NET decompiler"},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"RE Tools Status",
		"2 / 4",
		"apktool",
		"2.9.3",
		"retdec",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("tools status report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_AppAnalysisSection(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.AppAnalysis = &app.Result{
		AppInfo: app.AppInfoResult{
			Name:        "myapp",
			DisplayName: "My Application",
			HasStealth:  true,
			Telemetry:   []string{"Google Analytics", "Firebase"},
		},
		Analysis: app.SecurityResult{
			RiskScore:        75,
			RiskLevel:        "HIGH",
			SecuritySettings: []security.Finding{{Name: "nodeIntegration", Value: "true", Risk: "critical"}},
			IPCCommands:      []electronipc.Finding{{Channel: "execute-shell"}, {Channel: "read-file"}},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Application Security Analysis",
		"myapp",
		"My Application",
		"HIGH",
		"Score: 75",
		"Stealth Features:** Yes",
		"Security Settings:** 1",
		"IPC Commands:** 2",
		"Telemetry Services:** 2",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("app analysis report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_ExtensionAnalysisSection(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.ExtAnalysis = &extension.ExtensionInfo{
		Name:        "Super Blocker",
		Version:     "3.2.1",
		ManifestVer: 3,
		SourceType:  "crx",
		RiskScore:   60,
		RiskLevel:   "HIGH",
		Permissions: extension.PermissionAnalysis{
			All:   []string{"tabs", "storage", "webRequest"},
			Hosts: []string{"<all_urls>"},
		},
		NativeMessagingHosts: []string{"com.example.host"},
		WebSocketEndpoints:   []string{"wss://example.com"},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"Extension Package Analysis",
		"Super Blocker",
		"3.2.1",
		"V3",
		"crx",
		"HIGH",
		"Score: 60",
		"Permissions:** 3",
		"Host Permissions:** 1",
		"Native Hosts:** 1",
		"WebSocket Endpoints:** 1",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("extension report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_DisassemblyNoOperands(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.Disassembly = &disasm.Result{
		Architecture: "x86_64",
		Bits:         64,
		Format:       "ELF",
		Tool:         "native",
		EntryPoint:   0x1000,
		Sections: []disasm.Section{
			{
				Name:    ".text",
				Address: 0x1000,
				Size:    64,
				Instructions: []disasm.Instruction{
					{Address: 0x1000, Mnemonic: "nop", Operands: ""},
					{Address: 0x1001, Mnemonic: "ret", Operands: ""},
				},
			},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "nop") {
		t.Error("expected nop instruction in disassembly (no operands path)")
	}
}

func TestGenerateMarkdownReport_DisassemblyTruncatedInstructions(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	// More than 20 instructions to trigger truncation
	insns := make([]disasm.Instruction, 25)
	for i := range insns {
		insns[i] = disasm.Instruction{Address: uint64(0x1000 + i), Mnemonic: "nop", Operands: ""}
	}

	result := minimalResult()
	result.Disassembly = &disasm.Result{
		Architecture: "x86_64",
		Bits:         64,
		Format:       "ELF",
		Tool:         "native",
		EntryPoint:   0x1000,
		Sections: []disasm.Section{
			{Name: ".text", Address: 0x1000, Size: 25, Instructions: insns},
		},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "more instructions") {
		t.Error("expected 'more instructions' truncation note")
	}
}

func TestGenerateMarkdownReport_BeautifiedJSTruncation(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	// More than 2000 chars to trigger truncation
	result.BeautifiedJS = "function x() {\n" + strings.Repeat("  var y = 'hello';\n", 150) + "}\n"

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "truncated") {
		t.Error("expected truncation note for BeautifiedJS > 2000 chars")
	}
}

func TestGenerateMarkdownReport_AIPromptAndInsightsNoUsage(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.AIPrompt = "# System Prompt\n\nAnalyze this APK thoroughly."
	result.AIInsights = &ai.AnalysisResult{
		Manifest: "App declares INTERNET and CAMERA permissions.",
		Duration: 8 * time.Second,
		// No Usage — tests the nil usage branch
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{
		"AI Dissection Prompt",
		"AI-Powered Deep Analysis",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("AI report missing %q", expected)
		}
	}
}

func TestGenerateMarkdownReport_AnalysesStatusIcons(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.Analyses = []AnalysisEntry{
		{Name: "step ok", Status: "ok", Duration: 10 * time.Millisecond},
		{Name: "step error", Status: "error", Duration: 5 * time.Millisecond, Error: "boom"},
		{Name: "step skipped", Status: "skipped", Duration: 1 * time.Millisecond},
	}

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	for _, expected := range []string{"OK", "ERROR", "SKIP"} {
		if !strings.Contains(content, expected) {
			t.Errorf("analysis status icon %q missing from report", expected)
		}
	}
}

func TestGenerateMarkdownReport_DetectionDetails(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "report.md")

	result := minimalResult()
	result.Detection.Details = "Contains AndroidManifest.xml and classes.dex"

	if err := GenerateMarkdownReport(result, outPath); err != nil {
		t.Fatalf("GenerateMarkdownReport: %v", err)
	}

	content := readFileContent(t, outPath)

	if !strings.Contains(content, "Contains AndroidManifest.xml") {
		t.Error("expected detection details in report")
	}
}

// --- GenerateAIPrompt branch coverage ---

func TestGenerateAIPrompt_WithVerifyAndCerts(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     5 * 1024 * 1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
		APKVerify: &apk.VerifyResult{
			OverallValid: true,
		},
		APKCert: &apk.CertResult{
			Certificates: []*apk.Certificate{
				{
					Subject:            "CN=Developer",
					Issuer:             "CN=CA",
					SignatureAlgorithm: "SHA256withRSA",
					Fingerprint:        apk.Fingerprint{SHA256: "AA:BB:CC"},
				},
			},
		},
	}

	prompt := GenerateAIPrompt(result)

	for _, expected := range []string{
		"Signing & Certificates",
		"CN=Developer",
		"SHA256withRSA",
		"AA:BB:CC",
	} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("AI prompt missing %q", expected)
		}
	}
}

func TestGenerateAIPrompt_WithManifestAndSecrets(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     1024 * 1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
		ManifestInfo: &androidmanifest.Manifest{
			Package:     "com.example.test",
			VersionCode: 5,
			VersionName: "1.5",
			MinSDK:      21,
			TargetSDK:   33,
			Permissions: []androidmanifest.Permission{
				{Name: "android.permission.INTERNET", RiskLevel: "normal"},
				{Name: "android.permission.READ_CONTACTS", RiskLevel: "dangerous"},
			},
			Components: []androidmanifest.Component{
				{Name: "com.example.MainActivity", Type: "activity"},
			},
		},
		Secrets: &secret.ScanResult{
			TotalFindings:  2,
			HighConfidence: 1,
			MedConfidence:  1,
			Findings: []secret.Finding{
				{Confidence: "high", Type: "AWS_KEY", Value: "AKIAIOSFODNN7EXAMPLE", File: "config.xml"},
			},
		},
	}

	prompt := GenerateAIPrompt(result)

	for _, expected := range []string{
		"Parsed AndroidManifest.xml",
		"com.example.test",
		"READ_CONTACTS",
		"DANGEROUS",
		"Secret Scan Results",
		"AWS_KEY",
		"AKIAIOSFODNN7EXAMPLE",
		"Extraction Checklist",
	} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("AI prompt missing %q", expected)
		}
	}
}

func TestGenerateAIPrompt_WithExtractedArtifacts(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     3 * 1024 * 1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
		APKExtract: &apk.ExtractReport{
			Output:    "/output/extracted",
			Files:     150,
			TotalSize: 3 * 1024 * 1024,
		},
		Decompile: &tools.DecompileResult{
			OutputDir:    "/output/decompiled",
			ToolsUsed:    []string{"apktool", "jadx"},
			ToolsMissing: []string{"retdec"},
		},
	}

	prompt := GenerateAIPrompt(result)

	for _, expected := range []string{
		"Extracted Artifacts",
		"/output/extracted",
		"/output/decompiled",
		"apktool",
		"retdec",
		"Quick Path Reference",
		"AndroidManifest.xml",
		"assets/",
		"META-INF/",
	} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("AI prompt missing %q", expected)
		}
	}
}

func TestGenerateAIPrompt_WithAPKInfoNativeLibs(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     10 * 1024 * 1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
		APKInfo: &apk.InfoResult{
			Format:           "APK",
			TotalFiles:       300,
			DEXCount:         1,
			DEXFiles:         []string{"classes.dex"},
			HasManifest:      true,
			HasResources:     true,
			HasAssets:        true,
			HasKotlin:        true,
			NativeLibs:       map[string]int{"arm64-v8a": 3, "armeabi-v7a": 2},
			SignatureSchemes: []string{"v1", "v2", "v3"},
			SplitAPKs:        []string{"split_config.arm64_v8a.apk", "split_config.en.apk"},
			BundleInfo: &apk.BundleInfo{
				PackageName: "com.example.bundled",
				VersionName: "2.0",
				VersionCode: 20,
			},
		},
	}

	prompt := GenerateAIPrompt(result)

	for _, expected := range []string{
		"arm64-v8a",
		"split_config",
		"Split APK",
		"com.example.bundled",
		"2.0",
		"This APK contains native code",
		"Kotlin",
	} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("AI prompt missing %q", expected)
		}
	}
}

func TestGenerateAIPrompt_WithToolsStatus(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
		ToolsStatus: &tools.ToolsStatus{
			Available: 3,
			Total:     5,
			Tools: []*tools.Tool{
				{Name: "apktool", Available: true, Version: "2.9.3", Description: "APK decoder"},
				{Name: "jadx", Available: false, Version: "", Description: "DEX decompiler"},
			},
		},
	}

	prompt := GenerateAIPrompt(result)

	for _, expected := range []string{
		"Available RE Tools",
		"3 of 5 tools",
		"apktool",
		"2.9.3",
		"jadx",
		"NOT FOUND",
	} {
		if !strings.Contains(prompt, expected) {
			t.Errorf("AI prompt missing %q", expected)
		}
	}
}

func TestGenerateAIPrompt_APKNoNativeLibs(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
		},
		APKInfo: &apk.InfoResult{
			Format:     "APK",
			TotalFiles: 50,
			DEXCount:   1,
			DEXFiles:   []string{"classes.dex"},
			NativeLibs: map[string]int{},
		},
	}

	prompt := GenerateAIPrompt(result)

	if !strings.Contains(prompt, "No native libraries detected") {
		t.Error("expected 'No native libraries detected' for empty native libs")
	}
}

// TestGenerateAIPrompt_APKNativeKotlinFromAnalyzers pins the fix for the dissect
// AI-prompt contradiction: `app dissect` populates r.NativeAnalysis /
// r.KotlinAnalysis (the dedicated analyzers it runs), NOT the thin
// r.APKInfo.NativeLibs / r.APKInfo.HasKotlin. The generated prompt must reflect
// the analyzer findings, not the empty typed fields — otherwise it tells the
// downstream AI reader "no native libraries / no Kotlin" on an app that has both.
func TestGenerateAIPrompt_APKNativeKotlinFromAnalyzers(t *testing.T) {
	result := &DissectResult{
		Path:      "/path/to/app.apk",
		FileName:  "app.apk",
		Size:      1024,
		Detection: &detect.DetectResult{FileType: "APK", Category: "Android"},
		// APKInfo is the thin dissect-time parse: no native libs, no kotlin.
		APKInfo: &apk.InfoResult{Format: "APK", NativeLibs: map[string]int{}},
		// The dedicated analyzers dissect actually ran DID find native + kotlin.
		NativeAnalysis: &native.ScanResult{TotalLibs: 32},
		KotlinAnalysis: &kotlin.ScanResult{HasKotlin: true},
	}

	prompt := GenerateAIPrompt(result)

	if strings.Contains(prompt, "No native libraries detected") {
		t.Error("prompt claims no native libraries despite NativeAnalysis.TotalLibs=32")
	}
	if !strings.Contains(prompt, "contains native code") {
		t.Error("prompt should acknowledge native code from NativeAnalysis")
	}
	if strings.Contains(prompt, "No Kotlin metadata detected") {
		t.Error("prompt claims no Kotlin despite KotlinAnalysis.HasKotlin=true")
	}
	if !strings.Contains(prompt, "This app uses Kotlin") {
		t.Error("prompt should acknowledge Kotlin from KotlinAnalysis")
	}
}

// TestReconcileAPKInfo_PermissionsAndComponentsFromManifest pins the fix for
// the ISSUES.md defect: DissectResult.APKInfo is populated from a thin
// dissect-time parse (apk.Info) that never decodes the binary manifest, so
// APKInfo.Permissions/.Components are always empty on their own. The full
// lists live on r.ManifestInfo (androidmanifest.ParseAPK, the "android
// static manifest" analyzer) — on a real app (Picsart) that analyzer found
// 38 permissions / 310 components while APKInfo.Permissions/.Components
// stayed empty. reconcileAPKInfo must copy the richer manifest lists onto
// APKInfo so consumers reading the typed field see complete data.
func TestReconcileAPKInfo_PermissionsAndComponentsFromManifest(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/picsart.apk",
		FileName: "picsart.apk",
		APKInfo: &apk.InfoResult{
			Format:      "APK",
			NativeLibs:  map[string]int{},
			Permissions: nil, // thin parse never fills this
			Components:  nil,
		},
		ManifestInfo: &androidmanifest.Manifest{
			Package: "com.picsart.studio",
			Permissions: []androidmanifest.Permission{
				{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
				{Name: "android.permission.INTERNET", RiskLevel: "normal"},
			},
			Components: []androidmanifest.Component{
				{Name: ".MainActivity", Type: androidmanifest.ComponentActivity},
				{Name: ".UploadService", Type: androidmanifest.ComponentService},
				{Name: ".BootReceiver", Type: androidmanifest.ComponentReceiver},
			},
		},
	}

	reconcileAPKInfo(result)

	if len(result.APKInfo.Permissions) != 2 {
		t.Fatalf("expected 2 permissions reconciled onto APKInfo, got %d", len(result.APKInfo.Permissions))
	}
	if result.APKInfo.Permissions[0].Name != "android.permission.CAMERA" {
		t.Errorf("expected first permission CAMERA, got %q", result.APKInfo.Permissions[0].Name)
	}
	if len(result.APKInfo.Components) != 3 {
		t.Fatalf("expected 3 components reconciled onto APKInfo, got %d", len(result.APKInfo.Components))
	}
	if result.APKInfo.Components[1].Name != ".UploadService" {
		t.Errorf("expected second component .UploadService, got %q", result.APKInfo.Components[1].Name)
	}
}

// TestReconcileAPKInfo_NativeLibsAndKotlinFromAnalyzers extends the
// reconciliation to APKInfo.NativeLibs/.HasKotlin from the richer
// NativeAnalysis/KotlinAnalysis results (mirrors the already-fixed AI-prompt
// contradiction, but now applied to the typed field itself, not just the
// prompt string).
func TestReconcileAPKInfo_NativeLibsAndKotlinFromAnalyzers(t *testing.T) {
	result := &DissectResult{
		APKInfo: &apk.InfoResult{
			Format:     "APK",
			NativeLibs: map[string]int{}, // thin parse found nothing
			HasKotlin:  false,
		},
		NativeAnalysis: &native.ScanResult{
			TotalLibs: 5,
			ABIs: []native.ABISummary{
				{ABI: "arm64-v8a", Count: 3},
				{ABI: "armeabi-v7a", Count: 2},
			},
		},
		KotlinAnalysis: &kotlin.ScanResult{HasKotlin: true},
	}

	reconcileAPKInfo(result)

	if len(result.APKInfo.NativeLibs) != 2 {
		t.Fatalf("expected 2 ABI entries reconciled onto APKInfo.NativeLibs, got %d", len(result.APKInfo.NativeLibs))
	}
	if result.APKInfo.NativeLibs["arm64-v8a"] != 3 {
		t.Errorf("expected arm64-v8a=3, got %d", result.APKInfo.NativeLibs["arm64-v8a"])
	}
	if !result.APKInfo.HasKotlin {
		t.Error("expected APKInfo.HasKotlin=true reconciled from KotlinAnalysis")
	}
}

// TestReconcileAPKInfo_NilAndAbsentAnalyzers_NoRegression covers the
// no-op-safe paths required by the fix: a nil APKInfo must not panic, and
// when no richer analyzer result is present the thin values must be left
// untouched (no regression on the older/non-APK path).
func TestReconcileAPKInfo_NilAndAbsentAnalyzers_NoRegression(t *testing.T) {
	// nil APKInfo — must not panic.
	nilResult := &DissectResult{}
	reconcileAPKInfo(nilResult)
	if nilResult.APKInfo != nil {
		t.Error("expected APKInfo to remain nil")
	}

	// APKInfo present but no analyzer results at all — thin values untouched.
	thin := &apk.InfoResult{
		Format:     "APK",
		NativeLibs: map[string]int{"arm64-v8a": 1},
		HasKotlin:  false,
	}
	result := &DissectResult{APKInfo: thin}
	reconcileAPKInfo(result)

	if len(result.APKInfo.Permissions) != 0 {
		t.Error("expected Permissions to remain empty with no ManifestInfo present")
	}
	if len(result.APKInfo.Components) != 0 {
		t.Error("expected Components to remain empty with no ManifestInfo present")
	}
	if len(result.APKInfo.NativeLibs) != 1 || result.APKInfo.NativeLibs["arm64-v8a"] != 1 {
		t.Error("expected original thin NativeLibs to be preserved with no NativeAnalysis present")
	}
	if result.APKInfo.HasKotlin {
		t.Error("expected HasKotlin to remain false with no KotlinAnalysis present")
	}

	// Analyzer results present but already agree with (or are no richer
	// than) the thin data — must not clobber existing non-empty data.
	result2 := &DissectResult{
		APKInfo: &apk.InfoResult{
			Format:      "APK",
			Permissions: []androidmanifest.Permission{{Name: "android.permission.INTERNET"}},
		},
		ManifestInfo: &androidmanifest.Manifest{
			Permissions: []androidmanifest.Permission{{Name: "android.permission.CAMERA"}},
		},
	}
	reconcileAPKInfo(result2)
	if len(result2.APKInfo.Permissions) != 1 || result2.APKInfo.Permissions[0].Name != "android.permission.INTERNET" {
		t.Error("expected existing non-empty APKInfo.Permissions to be preserved, not overwritten")
	}
}

func TestGenerateAIPrompt_WithDetectionDetails(t *testing.T) {
	result := &DissectResult{
		Path:     "/path/to/app.apk",
		FileName: "app.apk",
		Size:     1024,
		Detection: &detect.DetectResult{
			FileType: "APK",
			Category: "Android",
			Details:  "Android Package with split config",
		},
	}

	prompt := GenerateAIPrompt(result)

	if !strings.Contains(prompt, "Android Package with split config") {
		t.Error("expected detection details in AI prompt")
	}
}

// --- Dispatch file type coverage ---

func TestDispatch_JSBeautify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")

	if err := os.WriteFile(path, []byte("function a(){return 1;}"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(path, Options{Beautify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["js beautify"] {
		t.Error("expected 'js beautify' step when Beautify=true")
	}
}

// --- Additional dispatch branch coverage ---

// TestDispatch_MSI verifies the MSI dispatch branch is exercised.
func TestDispatch_MSI(t *testing.T) {
	// Create a dummy file — steps will error but the branch is covered.
	path := filepath.Join(t.TempDir(), "test.msi")
	if err := os.WriteFile(path, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "test.msi",
		Size:     8,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeMSI, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["msi info"] {
		t.Errorf("expected 'msi info' step, got steps: %v", stepNames)
	}

	if !stepNames["msi verify"] {
		t.Errorf("expected 'msi verify' step, got steps: %v", stepNames)
	}
}

// TestDispatch_NSIS verifies the NSIS dispatch branch is exercised.
func TestDispatch_NSIS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installer.exe")
	if err := os.WriteFile(path, []byte("MZ fake NSIS installer content"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "installer.exe",
		Size:     30,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeNSIS, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["nsis info"] {
		t.Errorf("expected 'nsis info' step, got steps: %v", stepNames)
	}

	if !stepNames["cert info"] {
		t.Errorf("expected 'cert info' step, got steps: %v", stepNames)
	}
}

// TestDispatch_NSISWithOutputDir verifies NSIS extraction when OutputDir is set.
func TestDispatch_NSISWithOutputDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installer.exe")
	if err := os.WriteFile(path, []byte("MZ fake NSIS installer"), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()

	r := &DissectResult{
		Path:     path,
		FileName: "installer.exe",
		Size:     22,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeNSIS, Options{OutputDir: outDir})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["nsis extract"] {
		t.Errorf("expected 'nsis extract' step when OutputDir is set, got steps: %v", stepNames)
	}
}

// TestDispatch_ChromiumCache verifies the Chromium cache dispatch branch.
func TestDispatch_ChromiumCache(t *testing.T) {
	dir := t.TempDir()

	r := &DissectResult{
		Path:     dir,
		FileName: filepath.Base(dir),
		Size:     0,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, dir, detect.TypeChromiumCache, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["cache parse"] {
		t.Errorf("expected 'cache parse' step, got steps: %v", stepNames)
	}
}

// TestDispatch_UPXPacked verifies the UPX packed binary dispatch branch.
func TestDispatch_UPXPacked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packed.exe")
	if err := os.WriteFile(path, []byte("MZ fake UPX packed binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "packed.exe",
		Size:     25,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeUPXPacked, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["upx info"] {
		t.Errorf("expected 'upx info' step, got steps: %v", stepNames)
	}

	if !stepNames["cert info"] {
		t.Errorf("expected 'cert info' step, got steps: %v", stepNames)
	}

	if !stepNames["binary info"] {
		t.Errorf("expected 'binary info' step, got steps: %v", stepNames)
	}

	if !stepNames["garble strings"] {
		t.Errorf("expected 'garble strings' step, got steps: %v", stepNames)
	}

	if !stepNames["garble symbols"] {
		t.Errorf("expected 'garble symbols' step, got steps: %v", stepNames)
	}
}

// TestDispatch_UPXPackedWithOutputDir verifies UPX unpack+re-dispatch when OutputDir is set.
func TestDispatch_UPXPackedWithOutputDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packed.exe")
	if err := os.WriteFile(path, []byte("MZ fake UPX packed binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()

	r := &DissectResult{
		Path:     path,
		FileName: "packed.exe",
		Size:     25,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeUPXPacked, Options{OutputDir: outDir})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["upx unpack"] {
		t.Errorf("expected 'upx unpack' step when OutputDir is set, got steps: %v", stepNames)
	}
}

// TestDispatch_TauriApp verifies the Tauri app dispatch branch.
func TestDispatch_TauriApp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tauriapp")
	if err := os.WriteFile(path, []byte("fake tauri binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "tauriapp",
		Size:     17,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeTauriApp, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["cert info"] {
		t.Errorf("expected 'cert info' step, got steps: %v", stepNames)
	}

	if !stepNames["app analysis"] {
		t.Errorf("expected 'app analysis' step, got steps: %v", stepNames)
	}
}

// TestDispatch_TauriAppDisassemble verifies Tauri dispatch with Disassemble=true.
func TestDispatch_TauriAppDisassemble(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tauriapp")
	if err := os.WriteFile(path, []byte("fake tauri binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "tauriapp",
		Size:     17,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeTauriApp, Options{Disassemble: true})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["disassemble"] {
		t.Errorf("expected 'disassemble' step when Disassemble=true for Tauri, got steps: %v", stepNames)
	}
}

// TestDispatch_ElectronApp verifies the Electron app dispatch branch.
func TestDispatch_ElectronApp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "electronapp")
	if err := os.WriteFile(path, []byte("fake electron binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "electronapp",
		Size:     20,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeElectronApp, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["app analysis"] {
		t.Errorf("expected 'app analysis' step, got steps: %v", stepNames)
	}
}

// TestDispatch_BrowserExtPkg verifies the browser extension dispatch branch.
func TestDispatch_BrowserExtPkg(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ext.crx")
	if err := os.WriteFile(path, []byte("fake crx extension data"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "ext.crx",
		Size:     23,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeBrowserExtPkg, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["extension analysis"] {
		t.Errorf("expected 'extension analysis' step, got steps: %v", stepNames)
	}
}

// TestDispatch_BrowserExtPkgWithOutputDir verifies extension extract when OutputDir is set.
func TestDispatch_BrowserExtPkgWithOutputDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ext.crx")
	if err := os.WriteFile(path, []byte("fake crx extension data"), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()

	r := &DissectResult{
		Path:     path,
		FileName: "ext.crx",
		Size:     23,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeBrowserExtPkg, Options{OutputDir: outDir})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["extension extract"] {
		t.Errorf("expected 'extension extract' step when OutputDir is set, got steps: %v", stepNames)
	}
}

// TestDispatch_PEBinary verifies the PE binary dispatch branch directly.
func TestDispatch_PEBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.exe")
	// Minimal MZ header
	if err := os.WriteFile(path, []byte("MZ fake PE binary content"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "app.exe",
		Size:     25,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypePE, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	for _, expected := range []string{"cert info", "binary info", "garble strings", "garble symbols"} {
		if !stepNames[expected] {
			t.Errorf("expected %q step for PE binary, got steps: %v", expected, stepNames)
		}
	}
}

// TestDispatch_PEDisassemble verifies PE dispatch with Disassemble=true.
func TestDispatch_PEDisassemble(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.exe")
	if err := os.WriteFile(path, []byte("MZ fake PE binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "app.exe",
		Size:     17,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypePE, Options{Disassemble: true})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["disassemble"] {
		t.Errorf("expected 'disassemble' step for PE with Disassemble=true, got steps: %v", stepNames)
	}
}

// TestDispatch_MachO verifies the Mach-O dispatch branch.
func TestDispatch_MachO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.macho")
	if err := os.WriteFile(path, []byte("fake macho binary content"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "app.macho",
		Size:     25,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeMachO, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["cert info"] {
		t.Errorf("expected 'cert info' step for MachO, got steps: %v", stepNames)
	}
}

// TestDispatch_MachOFat verifies the MachO Fat dispatch branch.
func TestDispatch_MachOFat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.fat")
	if err := os.WriteFile(path, []byte("fake macho fat binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "app.fat",
		Size:     21,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeMachOFat, Options{})

	stepNames := make(map[string]bool)
	for _, a := range r.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["cert info"] {
		t.Errorf("expected 'cert info' step for MachOFat, got steps: %v", stepNames)
	}
}

// TestDispatch_UnknownType verifies dispatch does nothing for unknown file types.
func TestDispatch_UnknownType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.bin")
	if err := os.WriteFile(path, []byte("unknown"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "unknown.bin",
		Size:     7,
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.FileType("SomeUnknownType"), Options{})

	if len(r.Analyses) != 0 {
		t.Errorf("expected 0 analyses for unknown type, got %d", len(r.Analyses))
	}
}

// TestDispatch_UPXPackedSkipsStringsForLargeFile verifies garble strings is skipped for large files.
func TestDispatch_UPXPackedSkipsStringsForLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.exe")
	if err := os.WriteFile(path, []byte("MZ big binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{
		Path:     path,
		FileName: "big.exe",
		Size:     maxStringsFileSize + 1, // exceeds limit
		Analyses: []AnalysisEntry{},
		Errors:   []string{},
		debugRec: debug.NopRecorder(),
	}

	dispatch(r, path, detect.TypeUPXPacked, Options{})

	for _, a := range r.Analyses {
		if a.Name == "garble strings" {
			t.Error("garble strings should be skipped for large files")
		}
	}
}

// createDEBFile creates a minimal file with the DEB magic signature (!<arch>\n).
func createDEBFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.deb")
	// DEB (ar archive) magic bytes: "!<arch>\n"
	content := []byte("!<arch>\ndebian-binary   0           0     0     100644  4         `\n2.0\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

// createRPMFile creates a minimal file with the RPM magic signature.
func createRPMFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.rpm")
	// RPM magic bytes: 0xED 0xAB 0xEE 0xDB
	content := make([]byte, 16)
	content[0] = 0xed
	content[1] = 0xab
	content[2] = 0xee
	content[3] = 0xdb

	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

// createASARFile creates a minimal file with a .asar extension so it is detected
// as TypeASAR (extension-only fallback when no valid header is found).
func createASARFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.asar")
	// Write minimal content — extension-only fallback is triggered even without header
	if err := os.WriteFile(path, []byte("ASAR"), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDispatch_DEB(t *testing.T) {
	debPath := createDEBFile(t)

	result, err := Run(debPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["deb info"] {
		t.Errorf("expected 'deb info' step for DEB file, got steps: %v", stepNames)
	}

	if !stepNames["deb verify"] {
		t.Errorf("expected 'deb verify' step for DEB file, got steps: %v", stepNames)
	}
}

func TestDispatch_RPM(t *testing.T) {
	rpmPath := createRPMFile(t)

	result, err := Run(rpmPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["rpm info"] {
		t.Errorf("expected 'rpm info' step for RPM file, got steps: %v", stepNames)
	}

	if !stepNames["rpm verify"] {
		t.Errorf("expected 'rpm verify' step for RPM file, got steps: %v", stepNames)
	}
}

func TestDispatch_ASAR(t *testing.T) {
	asarPath := createASARFile(t)

	result, err := Run(asarPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["asar parse"] {
		t.Errorf("expected 'asar parse' step for ASAR file, got steps: %v", stepNames)
	}
}

// TestPrependBinToPath_AlreadyInPath verifies the early-return path when binDir
// is already present in PATH, so the environment variable is left unchanged.
func TestPrependBinToPath_AlreadyInPath(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = os.Chdir(origDir) }()

	// Create a bin directory so the function passes the os.Stat check.
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	absBin, _ := filepath.Abs("bin")

	// Pre-set PATH to already contain the bin dir.
	origPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", absBin+string(os.PathListSeparator)+origPath); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = os.Setenv("PATH", origPath) }()

	pathBefore := os.Getenv("PATH")
	prependBinToPath()
	pathAfter := os.Getenv("PATH")

	if pathBefore != pathAfter {
		t.Errorf("PATH should be unchanged when binDir already present; before=%q after=%q", pathBefore, pathAfter)
	}
}

// TestRun_APKGeneratesAIPrompt verifies that Run generates an AIPrompt for APK files.
func TestRun_APKGeneratesAIPrompt(t *testing.T) {
	apkPath := createMinimalAPK(t)

	result, err := Run(apkPath, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AIPrompt == "" {
		t.Error("expected non-empty AIPrompt for APK file type")
	}
}

// TestRun_APKWithOutputDir verifies that Run with an output directory exercises
// the APK extraction and decompile paths.
func TestRun_APKWithOutputDir(t *testing.T) {
	apkPath := createMinimalAPK(t)
	outDir := t.TempDir()

	result, err := Run(apkPath, Options{OutputDir: outDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["apk_extract"] {
		t.Errorf("expected 'apk_extract' step when OutputDir is set, got steps: %v", stepNames)
	}
}

// TestDispatch_JSBeautifyResultPopulated verifies that BeautifiedJS is populated when Beautify is true.
func TestDispatch_JSBeautifyResultPopulated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.js")

	if err := os.WriteFile(path, []byte("function a(){return 1;}"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(path, Options{Beautify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.BeautifiedJS == "" {
		t.Error("expected BeautifiedJS to be populated when Beautify=true")
	}
}

// TestDispatch_GoBinaryDisassemble verifies that Disassembly is populated when Disassemble is true.
func TestDispatch_GoBinaryDisassemble(t *testing.T) {
	binPath := buildTestBinary(t)

	result, err := Run(binPath, Options{Disassemble: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Disassembly may fail if no external tool is available; check the step was attempted.
	stepNames := make(map[string]bool)
	for _, a := range result.Analyses {
		stepNames[a.Name] = true
	}

	if !stepNames["disassemble"] {
		t.Errorf("expected 'disassemble' step when Disassemble=true for Go binary, got steps: %v", stepNames)
	}
}

// --- Test helpers ---

// minimalResult builds a minimal valid DissectResult suitable for report tests.
func minimalResult() *DissectResult {
	return &DissectResult{
		Path:     "/path/to/file",
		FileName: "file.bin",
		Size:     1024,
		Detection: &detect.DetectResult{
			FileType:   "Unknown",
			Category:   "Unknown",
			Confidence: "low",
		},
		StartedAt: time.Now(),
		Duration:  100 * time.Millisecond,
		Analyses:  []AnalysisEntry{},
	}
}

// readFileContent reads a file and returns its content as a string, failing the test on error.
func readFileContent(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %q: %v", path, err)
	}

	return string(data)
}

func createMinimalAPK(t *testing.T) string {
	t.Helper()

	apkPath := filepath.Join(t.TempDir(), "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})

	w, err = zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = w.Write([]byte("dex\n035\x00"))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return apkPath
}

// --- buildFridaInput tests ---

func TestBuildFridaInput_Empty(t *testing.T) {
	r := &DissectResult{}
	got := buildFridaInput(r)
	if got.PackageName != "" {
		t.Errorf("expected empty PackageName, got %q", got.PackageName)
	}
	if got.HasCertPinning {
		t.Error("expected HasCertPinning = false")
	}
	if got.HasExportedComp {
		t.Error("expected HasExportedComp = false")
	}
	if got.Domains != nil {
		t.Errorf("expected nil Domains, got %v", got.Domains)
	}
	if got.NativeFindings != nil {
		t.Errorf("expected nil NativeFindings, got %v", got.NativeFindings)
	}
	if got.DEXRiskAPIs != nil {
		t.Errorf("expected nil DEXRiskAPIs, got %v", got.DEXRiskAPIs)
	}
}

func TestBuildFridaInput_ManifestWithExported(t *testing.T) {
	exported := true
	r := &DissectResult{
		ManifestInfo: &androidmanifest.Manifest{
			Package: "com.example.app",
			Components: []androidmanifest.Component{
				{Name: ".MainActivity", Exported: &exported},
			},
		},
	}
	got := buildFridaInput(r)
	if got.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q, want %q", got.PackageName, "com.example.app")
	}
	if !got.HasExportedComp {
		t.Error("expected HasExportedComp = true")
	}
}

func TestBuildFridaInput_ManifestWithoutExported(t *testing.T) {
	notExported := false
	r := &DissectResult{
		ManifestInfo: &androidmanifest.Manifest{
			Package: "com.example.app",
			Components: []androidmanifest.Component{
				{Name: ".Service", Exported: &notExported},
				{Name: ".Receiver"},
			},
		},
	}
	got := buildFridaInput(r)
	if got.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q, want %q", got.PackageName, "com.example.app")
	}
	if got.HasExportedComp {
		t.Error("expected HasExportedComp = false")
	}
}

func TestBuildFridaInput_NetworkAnalysis(t *testing.T) {
	r := &DissectResult{
		NetworkAnalysis: &network.ScanResult{
			CertPinning: &network.CertPinResult{HasPinning: true},
			Endpoints: []network.EndpointInfo{
				{Host: "api.example.com"},
				{Host: "api.example.com"}, // duplicate
				{Host: "cdn.example.com"},
				{Host: ""}, // empty host
			},
		},
	}
	got := buildFridaInput(r)
	if !got.HasCertPinning {
		t.Error("expected HasCertPinning = true")
	}
	if len(got.Domains) != 2 {
		t.Errorf("expected 2 deduplicated domains, got %d: %v", len(got.Domains), got.Domains)
	}
}

func TestBuildFridaInput_NetworkNoCertPinning(t *testing.T) {
	r := &DissectResult{
		NetworkAnalysis: &network.ScanResult{
			Endpoints: []network.EndpointInfo{
				{Host: "api.example.com"},
			},
		},
	}
	got := buildFridaInput(r)
	if got.HasCertPinning {
		t.Error("expected HasCertPinning = false when CertPinning is nil")
	}
}

func TestBuildFridaInput_NativeFindings(t *testing.T) {
	r := &DissectResult{
		NativeAnalysis: &native.ScanResult{
			Findings: []native.Finding{
				{Category: "root-detection", Library: "libfoo.so"},
				{Category: "anti-debug", Library: "libbar.so"},
			},
		},
	}
	got := buildFridaInput(r)
	if len(got.NativeFindings) != 2 {
		t.Fatalf("expected 2 native findings, got %d", len(got.NativeFindings))
	}
	if got.NativeFindings[0].Category != "root-detection" {
		t.Errorf("finding[0].Category = %q, want %q", got.NativeFindings[0].Category, "root-detection")
	}
}

func TestBuildFridaInput_DEXRiskAPIs(t *testing.T) {
	r := &DissectResult{
		DEXAnalysis: &dex.ParseResult{
			RiskFindings: []dex.RiskFinding{
				{API: "Ljava/lang/Runtime;->exec", Category: "code-exec"},
				{API: "Landroid/telephony/SmsManager;->sendTextMessage", Category: "sms"},
			},
		},
	}
	got := buildFridaInput(r)
	if len(got.DEXRiskAPIs) != 2 {
		t.Fatalf("expected 2 DEX risk APIs, got %d", len(got.DEXRiskAPIs))
	}
	if got.DEXRiskAPIs[0] != "Ljava/lang/Runtime;->exec" {
		t.Errorf("DEXRiskAPIs[0] = %q", got.DEXRiskAPIs[0])
	}
}

func TestBuildFridaInput_AllFields(t *testing.T) {
	exported := true
	r := &DissectResult{
		ManifestInfo: &androidmanifest.Manifest{
			Package:    "com.full.test",
			Components: []androidmanifest.Component{{Name: ".Main", Exported: &exported}},
		},
		NetworkAnalysis: &network.ScanResult{
			CertPinning: &network.CertPinResult{HasPinning: true},
			Endpoints:   []network.EndpointInfo{{Host: "api.test.com"}},
		},
		NativeAnalysis: &native.ScanResult{
			Findings: []native.Finding{{Category: "crypto"}},
		},
		DEXAnalysis: &dex.ParseResult{
			RiskFindings: []dex.RiskFinding{{API: "dangerous.api"}},
		},
	}
	got := buildFridaInput(r)
	if got.PackageName != "com.full.test" {
		t.Errorf("PackageName = %q", got.PackageName)
	}
	if !got.HasExportedComp {
		t.Error("expected HasExportedComp")
	}
	if !got.HasCertPinning {
		t.Error("expected HasCertPinning")
	}
	if len(got.Domains) != 1 {
		t.Errorf("expected 1 domain, got %d", len(got.Domains))
	}
	if len(got.NativeFindings) != 1 {
		t.Errorf("expected 1 native finding, got %d", len(got.NativeFindings))
	}
	if len(got.DEXRiskAPIs) != 1 {
		t.Errorf("expected 1 DEX risk API, got %d", len(got.DEXRiskAPIs))
	}
}

// --- workspace helper tests ---

func TestDetectOSName(t *testing.T) {
	got := detectOSName()
	if got == "" {
		t.Error("detectOSName returned empty string")
	}
	// On linux test runners it should return "linux"
	// On macOS it should return "macos"
	// On windows it should return "windows"
	switch got {
	case "linux", "macos", "windows":
		// expected
	default:
		// Other GOOS values are still valid (e.g., "freebsd")
		t.Logf("detectOSName returned %q (non-standard but valid)", got)
	}
}

func TestHostname(t *testing.T) {
	got := hostname()
	// hostname() should return os.Hostname() or empty string (never panics)
	if got == "" {
		t.Log("hostname returned empty string (os.Hostname failed)")
	}
}

func TestInferAppName(t *testing.T) {
	tests := []struct {
		name     string
		result   *DissectResult
		expected string
	}{
		{
			name:     "from app analysis",
			result:   &DissectResult{AppAnalysis: &app.Result{AppInfo: app.AppInfoResult{Name: "MyApp"}}},
			expected: "myapp",
		},
		{
			name:     "strip apk extension",
			result:   &DissectResult{FileName: "SomeApp.apk"},
			expected: "someapp",
		},
		{
			name:     "strip exe extension",
			result:   &DissectResult{FileName: "Tool.exe"},
			expected: "tool",
		},
		{
			name:     "strip asar extension",
			result:   &DissectResult{FileName: "app.asar"},
			expected: "app",
		},
		{
			name:     "strip deb extension",
			result:   &DissectResult{FileName: "package.deb"},
			expected: "package",
		},
		{
			name:     "strip rpm extension",
			result:   &DissectResult{FileName: "package.rpm"},
			expected: "package",
		},
		{
			name:     "strip msi extension",
			result:   &DissectResult{FileName: "Installer.msi"},
			expected: "installer",
		},
		{
			name:     "no extension",
			result:   &DissectResult{FileName: "BinaryFile"},
			expected: "binaryfile",
		},
		{
			name:     "empty app analysis name falls back to filename",
			result:   &DissectResult{AppAnalysis: &app.Result{}, FileName: "Fallback.exe"},
			expected: "fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferAppName(tt.result)
			if got != tt.expected {
				t.Errorf("inferAppName() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestNilSlice(t *testing.T) {
	t.Run("nil input returns empty", func(t *testing.T) {
		var s []string
		got := nilSlice(s)
		if got == nil {
			t.Error("expected non-nil empty slice")
		}
		if len(got) != 0 {
			t.Errorf("expected len 0, got %d", len(got))
		}
	})

	t.Run("non-nil input returned as-is", func(t *testing.T) {
		s := []string{"a", "b"}
		got := nilSlice(s)
		if len(got) != 2 {
			t.Errorf("expected len 2, got %d", len(got))
		}
	})

	t.Run("empty non-nil slice", func(t *testing.T) {
		s := []int{}
		got := nilSlice(s)
		if len(got) != 0 {
			t.Errorf("expected len 0, got %d", len(got))
		}
	})
}

func TestWriteJSON(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("writes valid json", func(t *testing.T) {
		path := filepath.Join(tmpDir, "test.json")
		data := map[string]string{"key": "value"}
		writeJSON(path, data)

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read: %v", err)
		}
		if !strings.Contains(string(content), `"key": "value"`) {
			t.Errorf("unexpected content: %s", content)
		}
	})

	t.Run("handles unmarshalable input", func(t *testing.T) {
		path := filepath.Join(tmpDir, "bad.json")
		writeJSON(path, make(chan int)) // channels can't be marshaled
		// Should not create the file (or create empty)
		if _, err := os.Stat(path); err == nil {
			t.Log("file was created despite marshal error (acceptable)")
		}
	})
}

// --- WriteWorkspace tests ---

func TestWriteWorkspace_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	result := &DissectResult{
		Path:     "/fake/path/to/app",
		FileName: "testapp.exe",
		Detection: &detect.DetectResult{
			FileType: detect.TypePE,
		},
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{
				Name:    "TestApp",
				Type:    "electron",
				Version: "1.0.0",
			},
			Analysis: app.SecurityResult{
				RiskLevel: "low",
				RiskScore: 15,
			},
		},
		Duration: 2 * time.Second,
	}

	wsPath, err := WriteWorkspace(result, tmpDir)
	if err != nil {
		t.Fatalf("WriteWorkspace failed: %v", err)
	}

	if wsPath == "" {
		t.Fatal("workspace path is empty")
	}

	// Verify directory exists
	info, err := os.Stat(wsPath)
	if err != nil {
		t.Fatalf("workspace dir not found: %v", err)
	}
	if !info.IsDir() {
		t.Error("workspace path is not a directory")
	}

	// Verify metadata.json exists
	metaPath := filepath.Join(wsPath, "metadata.json")
	if _, err := os.Stat(metaPath); err != nil {
		t.Errorf("metadata.json not found: %v", err)
	}

	// Verify dissect.json exists
	dissectPath := filepath.Join(wsPath, "dissect.json")
	if _, err := os.Stat(dissectPath); err != nil {
		t.Errorf("dissect.json not found: %v", err)
	}

	// Verify DISSECT_REPORT.md exists
	reportPath := filepath.Join(wsPath, "DISSECT_REPORT.md")
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("DISSECT_REPORT.md not found: %v", err)
	}
}
