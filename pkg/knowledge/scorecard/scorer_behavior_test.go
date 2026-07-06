/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/disasm"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func TestBehaviorScorer(t *testing.T) {
	cases := []struct {
		name        string
		r           *dissect.DissectResult
		want        int
		wantMissing bool
	}{
		{"nil", nil, 0, true},
		{"empty", &dissect.DissectResult{}, 0, true},
		{"one_scenario", &dissect.DissectResult{
			Disassembly: &disasm.Result{},
		}, 10, true},
		{"three_scenarios", &dissect.DissectResult{
			Disassembly:  &disasm.Result{},
			WebView2Info: &webview2.Result{},
			FridaScripts: &frida.GenerateResult{},
		}, 30, true},
		{"refresh_floor_85", &dissect.DissectResult{
			Disassembly: &disasm.Result{},
			CertInfo:    &cert.CertInfo{},
		}, 85, true},
		{"webview_plus_cert_floor", &dissect.DissectResult{
			WebView2Info: &webview2.Result{},
			CertInfo:     &cert.CertInfo{},
		}, 85, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := behaviorScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
			missing := false
			for _, e := range got.Evidence {
				if e.Kind == "missing" && e.Source == "runtime" {
					missing = true
				}
			}
			if missing != tc.wantMissing {
				t.Errorf("missing = %v, want %v", missing, tc.wantMissing)
			}
		})
	}
}

// TestBehaviorScorer_UWP exercises the SCRG-05 install-dir branch — Capabilities
// + URLs + UI scenario hints with typed-field Citations.
func TestBehaviorScorer_UWP(t *testing.T) {
	const manifest = "C:/install/whatsapp/AppxManifest.xml"
	const jsFile = "C:/install/whatsapp/main.js"
	r := &dissect.DissectResult{
		SourcePath: "C:/install/whatsapp",
		MSIXInfo: &msix.InfoResult{
			ManifestPath: manifest,
			Capabilities: []string{"internetClient", "microphone", "webcam", "appCaptureSettings"},
			URLs:         []string{"https://web.whatsapp.com/"},
			Files: []msix.FileEntry{
				{Name: "App.xaml"},
				{Name: "Assets/StoreLogo.png"},
			},
		},
		JSAnalysis: &dissect.JSAnalysisResult{
			File: jsFile,
			URLs: []string{"https://api.example.com/login"},
		},
	}
	got := behaviorScorer{}.Score(r, nil)
	// Curve: caps 4*5=20 (cap 30) + JS-URL 10 + MSIX-URL 10 + UI-hint 10 = 50.
	if got.Score != 50 {
		t.Errorf("Score = %d, want 50", got.Score)
	}
	// W5 — typed-field Citation assertions: NEVER r.SourcePath.
	saw := struct{ caps, jsURL, msxURL, uiHint bool }{}
	for _, e := range got.Evidence {
		if e.Citation == nil {
			continue
		}
		if e.Citation.File == r.SourcePath {
			t.Errorf("Citation.File == r.SourcePath in evidence path=%s — must be typed-field path", e.Path)
		}
		switch {
		case strings.HasPrefix(e.Path, "MSIXInfo.Capabilities") && e.Citation.File == manifest:
			saw.caps = true
		case e.Path == "JSAnalysis.URLs" && e.Citation.File == jsFile:
			saw.jsURL = true
		case e.Path == "MSIXInfo.URLs" && e.Citation.File == manifest:
			saw.msxURL = true
		case strings.Contains(e.Path, "ui-scenario-hint") && e.Citation.File == "App.xaml":
			saw.uiHint = true
		}
	}
	if !saw.caps {
		t.Error("missing Capabilities evidence with manifest path Citation")
	}
	if !saw.jsURL {
		t.Error("missing JSAnalysis.URLs evidence with JS-file Citation")
	}
	if !saw.msxURL {
		t.Error("missing MSIXInfo.URLs evidence with manifest path Citation")
	}
	if !saw.uiHint {
		t.Error("missing ui-scenario-hint evidence with App.xaml Citation")
	}
}

// TestBehaviorScorer_UWP_NilSafe verifies nil/empty MSIXInfo doesn't panic.
func TestBehaviorScorer_UWP_NilSafe(t *testing.T) {
	r := &dissect.DissectResult{
		MSIXInfo: &msix.InfoResult{}, // all-empty
	}
	got := behaviorScorer{}.Score(r, nil)
	if got.Score != 0 {
		t.Errorf("Score = %d, want 0 (no signal)", got.Score)
	}
}

// TestBehavior_CitationFile_NotSourcePath — W5 explicit per-scorer assertion.
func TestBehavior_CitationFile_NotSourcePath(t *testing.T) {
	const src = "C:/install/whatsapp"
	r := &dissect.DissectResult{
		SourcePath: src,
		MSIXInfo: &msix.InfoResult{
			ManifestPath: "C:/install/whatsapp/AppxManifest.xml",
			Capabilities: []string{"internetClient"},
		},
	}
	got := behaviorScorer{}.Score(r, nil)
	for _, e := range got.Evidence {
		if e.Citation == nil {
			continue
		}
		if e.Citation.File == src {
			t.Fatalf("W5 violation: behavior scorer Citation.File == r.SourcePath (%q)", src)
		}
	}
}
