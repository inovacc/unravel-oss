/*
Copyright (c) 2026 Security Research
*/

package knowledge

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// TestExtractFramework_WebView2InstallDirFallback (CLSR-03 / P61):
// when no earlier branch fires but appDir contains AppxManifest.xml +
// WebView2Loader.dll, extractFramework must return "webview2".
func TestExtractFramework_WebView2InstallDirFallback(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("..", "inject", "webview2", "testdata", "uwp-installed-dir"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	got := extractFramework(&dissect.DissectResult{}, abs)
	if got != "webview2" {
		t.Fatalf("extractFramework=%q; want %q", got, "webview2")
	}
}

// TestExtractFramework_EmptyAppDir_NoChange ensures empty appDir preserves
// the historical empty-string return when no other branch matches.
func TestExtractFramework_EmptyAppDir_NoChange(t *testing.T) {
	got := extractFramework(&dissect.DissectResult{}, "")
	if got != "" {
		t.Fatalf("extractFramework(empty)=%q; want %q", got, "")
	}
}

// TestExtractFramework_ElectronUnchanged (Ripple Risk A3 verification):
// when Detection.FileType signals asar/electron, the existing branch must
// fire — webview2 fallback never reached, regardless of appDir.
func TestExtractFramework_ElectronUnchanged(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "inject", "webview2", "testdata", "uwp-installed-dir"))
	dr := &dissect.DissectResult{
		Detection: &detect.DetectResult{FileType: "asar"},
	}
	got := extractFramework(dr, abs)
	if got != "electron" {
		t.Fatalf("extractFramework(asar, uwp-dir)=%q; want %q (electron path must precede webview2 fallback)", got, "electron")
	}
}

// TestKnowledgeJSON_FrameworkFieldOnly_Diff (D-10 / W4): asserts that the
// only top-level JSON field whose value differs between the no-fallback and
// fallback paths is `framework`. Built in-memory from two KnowledgeResult
// instances (no on-disk golden churn — the existing
// cmd/testdata/knowledge.golden.json is a synthetic D-10 fixture for the
// heatmap pipeline, not for extractFramework).
func TestKnowledgeJSON_FrameworkFieldOnly_Diff(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("..", "inject", "webview2", "testdata", "uwp-installed-dir"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}

	// Pre-fix shape: extractFramework with empty appDir => "".
	pre := KnowledgeResult{
		SourcePath: "/fixture/path",
		Framework:  extractFramework(&dissect.DissectResult{}, ""),
	}
	// Post-fix shape: extractFramework with UWP appDir => "webview2".
	post := KnowledgeResult{
		SourcePath: "/fixture/path",
		Framework:  extractFramework(&dissect.DissectResult{}, abs),
	}
	if pre.Framework != "" || post.Framework != "webview2" {
		t.Fatalf("setup error: pre=%q post=%q", pre.Framework, post.Framework)
	}

	preBytes, _ := json.Marshal(pre)
	postBytes, _ := json.Marshal(post)

	var preMap, postMap map[string]any
	if err := json.Unmarshal(preBytes, &preMap); err != nil {
		t.Fatalf("unmarshal pre: %v", err)
	}
	if err := json.Unmarshal(postBytes, &postMap); err != nil {
		t.Fatalf("unmarshal post: %v", err)
	}

	// Walk every top-level key from both maps; assert only `framework` differs.
	seen := map[string]struct{}{}
	for k := range preMap {
		seen[k] = struct{}{}
	}
	for k := range postMap {
		seen[k] = struct{}{}
	}
	for k := range seen {
		preVal, _ := json.Marshal(preMap[k])
		postVal, _ := json.Marshal(postMap[k])
		if string(preVal) != string(postVal) {
			if k != "framework" {
				t.Errorf("D-10 breach: field %q differs (pre=%s post=%s) — only `framework` should diff",
					k, string(preVal), string(postVal))
			}
		}
	}
}
