/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// TestRenderReport_CacheHit_RegeneratesWithCurrentSource verifies BUG-06 / D-06:
// rendering the report from a "cached" result (i.e. one whose result.Path was
// stamped by a prior invocation against pathA) MUST re-render with the
// current invocation's source path when SourcePath is freshly stamped before
// renderReport is called.
//
// This mirrors what dissect.Run() does for cache-hit responses: it stamps
// cached.SourcePath = absPath before returning. Then WriteWorkspace passes
// that to renderReport, which always re-emits the **Source:** header.
func TestRenderReport_CacheHit_RegeneratesWithCurrentSource(t *testing.T) {
	pathA := filepath.Join(os.TempDir(), "discord-cached-input")
	pathB := filepath.Join(os.TempDir(), "whatsapp-current-input")

	// Simulate a result that came back from cache: its Path field carries
	// pathA (the cached prior input), but the orchestrator stamps
	// SourcePath = pathB before calling renderReport.
	cached := &DissectResult{
		Path:      pathA,
		FileName:  filepath.Base(pathA),
		Detection: &detect.DetectResult{FileType: detect.TypeUWPApp, Category: detect.CategoryArchive},
		StartedAt: time.Now(),
	}

	out := t.TempDir()
	if err := renderReport(out, pathB, cached); err != nil {
		t.Fatalf("renderReport: %v", err)
	}

	reportPath := filepath.Join(out, "DISSECT_REPORT.md")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	body := string(data)

	// **Source:** must point to the CURRENT call (pathB), not pathA.
	wantSrc := "**Source:** `" + pathB + "`"
	if !strings.Contains(body, wantSrc) {
		t.Errorf("report header missing current Source line\n  want: %q\n  body excerpt:\n%s",
			wantSrc, head(body, 400))
	}
	// And the cached path MUST NOT appear as the source line.
	badSrc := "**Source:** `" + pathA + "`"
	if strings.Contains(body, badSrc) {
		t.Errorf("report header leaks cached source path: %q", badSrc)
	}
	// SourcePath must have been stamped onto the result by renderReport so a
	// subsequent JSON serialisation also reflects the current invocation.
	if cached.SourcePath != pathB {
		t.Errorf("renderReport did not stamp SourcePath: got %q want %q", cached.SourcePath, pathB)
	}
}

// TestManifest_OutputDirLabel verifies the teardown manifest persists the
// output dir basename in the new `output_dir_label` field. The label is
// derived from the parent of the teardown writer's UUID dir, which matches
// the caller-supplied -o destination.
func TestManifest_OutputDirLabel(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "whatsapp")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}

	tw, err := NewTeardownWriterAt(parent)
	if err != nil {
		t.Fatalf("NewTeardownWriterAt: %v", err)
	}
	if err := tw.WriteManifest("C:/some/source/path"); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	manifestPath := filepath.Join(tw.Dir(), "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m TeardownManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if m.OutputDirLabel != "whatsapp" {
		t.Errorf("OutputDirLabel = %q, want %q", m.OutputDirLabel, "whatsapp")
	}
	// JSON tag must serialise as `output_dir_label`.
	if !strings.Contains(string(data), `"output_dir_label"`) {
		t.Errorf("manifest.json missing output_dir_label key:\n%s", string(data))
	}
}

// TestRenderReport_TitleFromCurrentInput verifies DSC-06 / 13-06 closure for
// the report title and legacy **Path:** field. A "cached" result claiming app
// A (via Path / FileName) must, after renderReport with currentSource pointing
// at app B, produce a report whose title and Path: line both reflect B.
func TestRenderReport_TitleFromCurrentInput(t *testing.T) {
	pathA := filepath.Join(os.TempDir(), "discord-app-A")
	pathB := filepath.Join(os.TempDir(), "whatsapp-app-B")

	cached := &DissectResult{
		Path:      pathA,
		FileName:  filepath.Base(pathA),
		Detection: &detect.DetectResult{FileType: detect.TypeUWPApp, Category: detect.CategoryArchive},
		StartedAt: time.Now(),
	}

	out := t.TempDir()
	if err := renderReport(out, pathB, cached); err != nil {
		t.Fatalf("renderReport: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(out, "DISSECT_REPORT.md"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	s := string(body)

	wantTitle := "# Dissect Report: " + filepath.Base(pathB)
	if !strings.Contains(s, wantTitle) {
		t.Errorf("title missing current input basename\n  want: %q\n  body excerpt:\n%s",
			wantTitle, head(s, 400))
	}

	badTitle := "# Dissect Report: " + filepath.Base(pathA)
	if strings.Contains(s, badTitle) {
		t.Errorf("title leaks cached input basename: %q", badTitle)
	}

	wantPath := "**Path:** `" + pathB + "`"
	if !strings.Contains(s, wantPath) {
		t.Errorf("Path: line does not reflect current input\n  want: %q", wantPath)
	}

	badPath := "**Path:** `" + pathA + "`"
	if strings.Contains(s, badPath) {
		t.Errorf("Path: line leaks cached input: %q", badPath)
	}
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
