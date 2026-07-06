package dissect

import (
	"encoding/json"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

// TestCacheEntryStale pins the cache-staleness invariant for the
// TypeUWPApp / TypeMSIX arm of the dissect cache-freshness gate.
//
// Regression target (.planning/debug/83-vald01-half-a-storage-zero.md +
// 83-05-REVIEW.md CR-01): a pre-Phase-83 cached DissectResult for a UWP/MSIX
// directory has a valid MSIXInfo.PackageName (packaging always extracted
// fine) but WebView2Info == nil, because the Phase-83 on-disk WebView2/UWP
// capture did not yet exist when the entry was written. Such an entry MUST
// be treated as stale so analyzer dispatch re-runs.
//
// CR-01 one-time semantics: the gate must NOT loop forever on the common
// honest-empty case. The post-83 producer (analyze_uwp.go) ALWAYS stamps a
// non-nil WebView2Info with Analyzed=true — even when zero EBWebView
// profiles exist (D-08 honest-empty). A post-83 entry of that exact shape
// MUST be NOT stale on the 2nd+ run (no perpetual thrash), while a pre-83
// entry (WebView2Info==nil) IS stale exactly once.
//
// Deterministic by construction: no dissect.Run, no live app, no rescan, no
// filesystem fixtures — *DissectResult literals fed to cacheEntryStale.
func TestCacheEntryStale(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cached *DissectResult
		want   bool
	}{
		{
			name: "UWP pre-83 entry: valid PackageName but WebView2Info nil -> stale",
			cached: &DissectResult{
				Detection:    &detect.DetectResult{FileType: detect.TypeUWPApp},
				MSIXInfo:     &msix.InfoResult{PackageName: "MSTeams_8wekyb3d8bbwe"},
				WebView2Info: nil,
			},
			want: true,
		},
		{
			name: "MSIX pre-83 entry: valid PackageName but WebView2Info nil -> stale",
			cached: &DissectResult{
				Detection:    &detect.DetectResult{FileType: detect.TypeMSIX},
				MSIXInfo:     &msix.InfoResult{PackageName: "MSTeams_8wekyb3d8bbwe"},
				WebView2Info: nil,
			},
			want: true,
		},
		{
			name: "CR-01: post-83 honest-empty (producer shape, Analyzed=true, zero profiles) -> NOT stale",
			cached: &DissectResult{
				Detection: &detect.DetectResult{FileType: detect.TypeUWPApp},
				MSIXInfo:  &msix.InfoResult{PackageName: "SomeNonWebView2App_8wekyb3d8bbwe"},
				// EXACTLY what analyze_uwp.go writes for the honest-empty
				// D-08 path: &webview2.Result{Analyzed: true}.
				WebView2Info: &webview2.Result{Analyzed: true},
			},
			want: false,
		},
		{
			name: "CR-01: pre-sentinel non-nil WebView2Info (Analyzed=false) -> stale (re-dispatch once)",
			cached: &DissectResult{
				Detection: &detect.DetectResult{FileType: detect.TypeUWPApp},
				MSIXInfo:  &msix.InfoResult{PackageName: "MSTeams_8wekyb3d8bbwe"},
				// A non-nil result from a pre-sentinel build (no Analyzed
				// field set). Must be re-dispatched exactly once.
				WebView2Info: &webview2.Result{},
			},
			want: true,
		},
		{
			name: "post-83 populated entry: Analyzed=true with profiles -> NOT stale",
			cached: &DissectResult{
				Detection: &detect.DetectResult{FileType: detect.TypeMSIX},
				MSIXInfo:  &msix.InfoResult{PackageName: "MSTeams_8wekyb3d8bbwe"},
				WebView2Info: &webview2.Result{
					Analyzed:   true,
					IsWebView2: true,
					Profiles:   []webview2.ProfileInfo{{}},
				},
			},
			want: false,
		},
		{
			name: "Precedent parity: MSIXInfo nil -> still stale (original gate preserved)",
			cached: &DissectResult{
				Detection: &detect.DetectResult{FileType: detect.TypeMSIX},
				MSIXInfo:  nil,
			},
			want: true,
		},
		{
			name: "Precedent parity: empty PackageName -> still stale (original gate preserved)",
			cached: &DissectResult{
				Detection:    &detect.DetectResult{FileType: detect.TypeUWPApp},
				MSIXInfo:     &msix.InfoResult{PackageName: ""},
				WebView2Info: &webview2.Result{Analyzed: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cacheEntryStale(tt.cached); got != tt.want {
				t.Fatalf("cacheEntryStale() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCacheEntryStale_IdempotenceRoundTrip pins the producer/predicate
// contract end-to-end through a JSON round-trip (the exact transform
// loadCachedResult applies). It proves the CR-01 one-time semantics:
//
//	run-1: pre-83 entry (WebView2Info==nil)            -> stale (re-dispatch)
//	the producer then stamps the honest-empty sentinel -> &Result{Analyzed:true}
//	persisted + reloaded via JSON (cache round-trip)   -> still Analyzed=true
//	run-2: post-83 honest-empty entry                  -> NOT stale (no loop)
//
// This is the case WR-01 flagged as untested: the prior suite fed a
// hand-built &webview2.Result{} the real producer never emitted.
func TestCacheEntryStale_IdempotenceRoundTrip(t *testing.T) {
	t.Parallel()

	// run-1: pre-83 shape — must be stale (forces one re-dispatch).
	preRun := &DissectResult{
		Detection:    &detect.DetectResult{FileType: detect.TypeUWPApp},
		MSIXInfo:     &msix.InfoResult{PackageName: "NonWebView2App_8wekyb3d8bbwe"},
		WebView2Info: nil,
	}
	if !cacheEntryStale(preRun) {
		t.Fatal("run-1 pre-83 (WebView2Info==nil) must be stale")
	}

	// Producer (analyze_uwp.go honest-empty branch) stamps this exact value
	// when no EBWebView tree resolves. Build it the way the producer does.
	produced := &DissectResult{
		Detection:    &detect.DetectResult{FileType: detect.TypeUWPApp},
		MSIXInfo:     &msix.InfoResult{PackageName: "NonWebView2App_8wekyb3d8bbwe"},
		WebView2Info: &webview2.Result{Analyzed: true},
	}

	// Round-trip through JSON — exactly what cacheResult writes and
	// loadCachedResult reads back. The sentinel must survive marshal/unmarshal
	// (Analyzed has json:"analyzed,omitempty"; true is preserved).
	blob, err := json.Marshal(produced)
	if err != nil {
		t.Fatalf("marshal produced result: %v", err)
	}
	var reloaded DissectResult
	if err := json.Unmarshal(blob, &reloaded); err != nil {
		t.Fatalf("unmarshal reloaded result: %v", err)
	}
	if reloaded.WebView2Info == nil || !reloaded.WebView2Info.Analyzed {
		t.Fatalf("Analyzed sentinel lost across JSON round-trip: %+v", reloaded.WebView2Info)
	}

	// run-2: the reloaded post-83 honest-empty entry must NOT be stale.
	// This is the anti-thrash guarantee — without the CR-01 fix this loops.
	if cacheEntryStale(&reloaded) {
		t.Fatal("run-2 post-83 honest-empty (Analyzed=true, zero profiles) must NOT be stale (CR-01 anti-thrash)")
	}
}
