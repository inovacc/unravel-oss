/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	dotnetdecompile "github.com/inovacc/unravel-oss/pkg/dotnet/decompile"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/sourcemap"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func TestSourceLayerScorer(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		{"nil", nil, 0},
		{"empty", &dissect.DissectResult{}, 0},
		{"web_only", &dissect.DissectResult{
			BeautifiedJS: "x",
		}, 50}, // +30 web +20 js = 50 (BeautifiedJS triggers both)
		{"web_plus_cache", &dissect.DissectResult{
			BeautifiedJS: "x",
			Cache:        &cache.ParseResult{},
		}, 70},
		{"all_features_caps_at_90", &dissect.DissectResult{
			BeautifiedJS:    "x",
			ASARFiles:       []asar.ExtractedFile{{Path: "y"}},
			WebView2Info:    &webview2.Result{Profiles: []webview2.ProfileInfo{{Name: "p"}}},
			DotNetDecompile: &dotnetdecompile.Result{},
			SourceMapInfo:   &sourcemap.ParseResult{},
		}, 90},
		{"spec_floor_via_cert", &dissect.DissectResult{
			BeautifiedJS: "x", // 50 raw
			CertInfo:     &cert.CertInfo{},
		}, 90}, // floor lifts 50 -> 90
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceLayerScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
		})
	}
}

// TestSourceLayerScorer_UWPInstallDir exercises the SCRG-02 UWP branch.
// Mixed entries (.html/.js/.json/.css/.dll) + JSAnalysis present + decompiled
// .NET assembly => score >= 80; per-file Citation.File never equals
// r.SourcePath. Skips .NET branch silently when DotNetDecompile is nil.
func TestSourceLayerScorer_UWPInstallDir(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "C:/Program Files/WindowsApps/some.app",
		MSIXInfo: &msix.InfoResult{
			Files: []msix.FileEntry{
				{Name: "App/index.html", Size: 1024},
				{Name: "App/app.js", Size: 4096},
				{Name: "App/styles.css", Size: 200},
				{Name: "App/config.json", Size: 50},
				{Name: "App/Native.dll", Size: 8192},
			},
		},
		JSAnalysis: &dissect.JSAnalysisResult{File: "App/app.js"},
		DotNetDecompile: &dotnetdecompile.Result{
			Assemblies: []dotnetdecompile.AssemblyResult{
				{Name: "Lib", Path: "App/Lib.dll", OutDir: "decompiled/Lib", Decompiled: true},
			},
		},
	}
	got := sourceLayerScorer{}.Score(r, nil)
	if got.Score < 80 {
		t.Errorf("UWP install-dir Score = %d, want >= 80", got.Score)
	}
	if len(got.Evidence) == 0 {
		t.Fatal("UWP install-dir Evidence empty")
	}
	for i, ev := range got.Evidence {
		if ev.Citation == nil {
			t.Errorf("Evidence[%d].Citation is nil", i)
			continue
		}
		if ev.Citation.File == r.SourcePath {
			t.Errorf("Evidence[%d].Citation.File leaked r.SourcePath", i)
		}
	}
	// .NET nil-safe: same setup minus DotNetDecompile must not panic and
	// still produce signal from MSIX/JS branches.
	r2 := *r
	r2.DotNetDecompile = nil
	got2 := sourceLayerScorer{}.Score(&r2, nil)
	if got2.Score == 0 {
		t.Errorf("nil DotNetDecompile dropped UWP score to 0; should still emit MSIX/JS signal")
	}
}
