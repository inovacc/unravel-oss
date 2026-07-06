/*
Copyright (c) 2026 Security Research
*/

// P58 Task 58-02 — per-scorer citation attachment tests.
//
// Asserts that every non-missing Evidence emitted by each of the 12 scorers
// carries a non-nil Citation. Missing-kind Evidence stays uncited (lenient
// rule, see citations.go).
//
// state_machines and behavior scorers emit ONLY missing-kind Evidence today
// (decision 9 — static state-machine extraction is its own future phase),
// so the lenient rule auto-passes them without a per-scorer assertion here.
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	elecapp "github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	ipcfind "github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

// assertNonMissingCited iterates Evidence and fails if any non-missing entry
// lacks a Citation.
func assertNonMissingCited(t *testing.T, evs []Evidence, dim string) {
	t.Helper()
	for i, e := range evs {
		if e.Kind == "missing" {
			continue
		}
		if e.Citation == nil {
			t.Errorf("[%s] Evidence[%d] kind=%q has nil Citation: %+v", dim, i, e.Kind, e)
			continue
		}
		if e.Citation.File == "" {
			t.Errorf("[%s] Evidence[%d] Citation.File empty: %+v", dim, i, e)
		}
	}
}

func TestScorerIdentity_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x.msix",
		Detection:  &detect.DetectResult{},
		MSIXInfo:   &msix.InfoResult{PackageName: "x"},
		CertInfo:   &cert.CertInfo{},
	}
	got := identityScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "identity")
	if len(got.Evidence) == 0 {
		t.Fatalf("expected evidence")
	}
}

func TestScorerFilesystem_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x.msix",
		MSIXInfo:   &msix.InfoResult{FileCount: 200, HasSignature: true},
		ASARFiles:  []asar.ExtractedFile{{Path: "y"}},
	}
	got := filesystemScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "filesystem")
	if len(got.Evidence) == 0 {
		t.Fatalf("expected evidence")
	}
}

func TestScorerBinarySurface_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x",
		AppAnalysis: &elecapp.Result{
			Binaries: []binary.Info{{Name: "a", ProductName: "p", StringsTotal: 1}},
		},
	}
	got := binarySurfaceScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "binary_surface")
	if len(got.Evidence) == 0 {
		t.Fatalf("expected evidence")
	}
}

func TestScorerSourceLayer_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath:   "/tmp/app/x",
		BeautifiedJS: "x",
		ASARFiles:    []asar.ExtractedFile{{Path: "y"}},
		WebView2Info: &webview2.Result{Profiles: []webview2.ProfileInfo{{Name: "p"}}},
		Cache:        &cache.ParseResult{},
	}
	got := sourceLayerScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "source_layer")
}

func TestScorerIPC_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x",
		AppAnalysis: &elecapp.Result{
			Analysis: elecapp.SecurityResult{IPCCommands: mkIPC(31)},
		},
	}
	got := ipcScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "ipc")
}

func TestScorerAPI_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x",
		JSAnalysis: &dissect.JSAnalysisResult{URLs: []string{"https://a", "https://b"}},
	}
	// JSAnalysis non-nil + 2 URLs → hits=2 (still <=10), Path "JSAnalysis.URLs..." emitted only when hits > 0
	got := apiScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "api")
}

// ipcfind imported for completeness; no usage here is fine.
var _ = ipcfind.Finding{}

func TestScorerStorage_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x",
		WebView2Info: &webview2.Result{
			IsWebView2: true,
			Profiles:   []webview2.ProfileInfo{{Name: "p"}},
		},
		LevelDB: &leveldb.ParseResult{},
		Cache:   &cache.ParseResult{},
	}
	got := storageScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "storage")
}

func TestScorerCrypto_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "/tmp/app/x",
		JSAnalysis: &dissect.JSAnalysisResult{Indicators: []string{"aes", "webcrypto"}},
		Secrets:    &secret.ScanResult{TotalFindings: 60},
	}
	got := cryptoScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "crypto")
}

func TestScorerWire_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath:       "/tmp/app/x",
		ProtobufAnalysis: &protobuf.ScanResult{},
		JSAnalysis:       &dissect.JSAnalysisResult{URLs: []string{"wss://x", "wss://y"}},
	}
	got := wireScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "wire")
}

func TestScorerAuth_AttachesCitations(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath:   "/tmp/app/x",
		Secrets:      &secret.ScanResult{TotalFindings: 1},
		WebView2Info: &webview2.Result{Profiles: []webview2.ProfileInfo{{Name: "p"}}},
		JSAnalysis:   &dissect.JSAnalysisResult{URLs: []string{"https://x/oauth/token"}},
	}
	got := authScorer{}.Score(r, nil)
	assertNonMissingCited(t, got.Evidence, "auth")
}

// state_machines and behavior emit only missing-kind Evidence today —
// auto-pass under the lenient rule (decision 9). No non-missing Evidence is
// produced by these scorers in P58, so there is nothing to cite. This test
// pins that contract: any Evidence they emit must be missing-kind.
func TestScorerStateMachines_OnlyMissingEvidence(t *testing.T) {
	r := &dissect.DissectResult{SourcePath: "/tmp/app/x"}
	got := stateMachinesScorer{}.Score(r, nil)
	for i, e := range got.Evidence {
		if e.Kind != "missing" {
			t.Errorf("Evidence[%d] kind=%q (expected missing-only): %+v", i, e.Kind, e)
		}
	}
}

func TestScorerBehavior_OnlyMissingEvidence(t *testing.T) {
	r := &dissect.DissectResult{SourcePath: "/tmp/app/x"}
	got := behaviorScorer{}.Score(r, nil)
	for i, e := range got.Evidence {
		if e.Kind != "missing" {
			t.Errorf("Evidence[%d] kind=%q (expected missing-only): %+v", i, e.Kind, e)
		}
	}
}
