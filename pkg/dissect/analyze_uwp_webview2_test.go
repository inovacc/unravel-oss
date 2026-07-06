/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"
)

// TestWireEBWebView_RecoveredCSSSurfaced is the Task-4 target: recovered
// HTTP-cache CSS must be surfaced onto DissectResult as a clean-room artifact.
func TestWireEBWebView_RecoveredCSSSurfaced(t *testing.T) {
	r := &DissectResult{}
	res := &webview2.Result{Analyzed: true}
	res.RecoveredCSS = []any{analyze.RecoveredCSSEntry{
		Path: "body.css", Source: "@media screen{.x{display:flex;color:rgba(0,0,0,.5)}}",
	}}
	wireEBWebViewJSAndSecrets(r, res, nil)
	if r.RecoveredCSS == nil || r.RecoveredCSS.Files == 0 {
		t.Fatal("recovered CSS not surfaced onto DissectResult")
	}
}

// TestWireEBWebView_NoCSSHonestEmpty asserts honest-empty: no CSS input must
// leave r.RecoveredCSS nil (no synthesis).
func TestWireEBWebView_NoCSSHonestEmpty(t *testing.T) {
	r := &DissectResult{}
	wireEBWebViewJSAndSecrets(r, &webview2.Result{Analyzed: true}, nil)
	if r.RecoveredCSS != nil {
		t.Fatal("synthesized RecoveredCSS with no input")
	}
}

// TestUWPWebView2Dispatch is the Wave-0 Nyquist target for 83-02 half-A:
// once analyze_uwp dispatches the resolved install-dir into webview2.Analyze
// (A1 spike VERDICT: INSTALL_DIR_RESOLVES — no UDFOverride), dissecting an
// installed-MSIX dir whose PFN LocalCache holds an EBWebView/WV2Profile_*
// subtree must populate r.WebView2Info with non-empty Profiles, and the
// UNCHANGED scorer_storage.go must then credit storage > 0.
//
// The udf resolver keys on %LOCALAPPDATA%\Packages\<PFN>\LocalCache
// (discover.go:149), so the test redirects LOCALAPPDATA to a temp root.
func TestUWPWebView2Dispatch(t *testing.T) {
	// Minimal installed-MSIX fixture: an install dir carrying AppxManifest.xml
	// (triggers udf.uwpPackageFamilyName branch 2) plus the EBWebView profile
	// subtree the resolver walks for under %LOCALAPPDATA%\Packages\<PFN>\LocalCache.
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)

	installDir := filepath.Join(root, "5319275A.WhatsAppDesktop_2.2615.101.0_x64__cv1g1gvanyjgm")
	// Real Chromium/WebView2 EBWebView layout: profile dirs are "Default",
	// "Profile N", "Guest Profile", "System Profile" (udf.isProfileDirName).
	ebProfile := filepath.Join(root, "Packages", "5319275A.WhatsAppDesktop_cv1g1gvanyjgm",
		"LocalCache", "EBWebView", "Default")
	leveldbDir := filepath.Join(ebProfile, "Local Storage", "leveldb")
	for _, d := range []string{installDir, ebProfile, leveldbDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(installDir, "AppxManifest.xml"),
		[]byte("<Package/>"), 0o644); err != nil {
		t.Fatalf("write AppxManifest.xml: %v", err)
	}
	// Minimal LevelDB markers so the on-disk profile is real evidence.
	if err := os.WriteFile(filepath.Join(leveldbDir, "CURRENT"),
		[]byte("MANIFEST-000001\n"), 0o644); err != nil {
		t.Fatalf("write CURRENT: %v", err)
	}
	if err := os.WriteFile(filepath.Join(leveldbDir, "000003.log"),
		[]byte("leveldb-log-marker"), 0o644); err != nil {
		t.Fatalf("write 000003.log: %v", err)
	}

	r := &DissectResult{debugRec: debug.NopRecorder()}
	analyzeUWP(r, installDir, Options{})

	if r.WebView2Info == nil {
		t.Fatalf("WebView2Info nil: dispatch did not populate from real EBWebView tree")
	}
	if len(r.WebView2Info.Profiles) == 0 {
		t.Fatalf("WebView2Info.Profiles empty: resolver did not reach EBWebView/WV2Profile_Default")
	}

	// The "non-empty Profiles => storage > 0" credit is proven by the
	// UNCHANGED pkg/knowledge/scorecard scorer_storage_test.go
	// (TestStorageScorer_UWPInstallDir) — asserting it here would create a
	// dissect <- scorecard import cycle (scorecard imports dissect). This
	// test owns the missing link: the dispatch actually POPULATES Profiles
	// from real on-disk evidence (asserted above).

	t.Run("honest empty when no EBWebView", func(t *testing.T) {
		emptyRoot := t.TempDir()
		t.Setenv("LOCALAPPDATA", emptyRoot)
		emptyInstall := filepath.Join(emptyRoot, "5319275A.WhatsAppDesktop_2.2615.101.0_x64__cv1g1gvanyjgm")
		if err := os.MkdirAll(emptyInstall, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", emptyInstall, err)
		}
		if err := os.WriteFile(filepath.Join(emptyInstall, "AppxManifest.xml"),
			[]byte("<Package/>"), 0o644); err != nil {
			t.Fatalf("write AppxManifest.xml: %v", err)
		}
		er := &DissectResult{debugRec: debug.NopRecorder()}
		analyzeUWP(er, emptyInstall, Options{}) // must not panic
		if er.WebView2Info != nil && len(er.WebView2Info.Profiles) > 0 {
			t.Fatalf("fabricated WebView2Info with no on-disk EBWebView tree")
		}
		// No EBWebView JS/secrets present => the analysis pass must not
		// synthesize JSAnalysis/Secrets (no-fabrication structural invariant).
		if er.JSAnalysis != nil {
			t.Fatalf("fabricated JSAnalysis with no EBWebView JS on disk")
		}
		if er.Secrets != nil {
			t.Fatalf("fabricated Secrets with no EBWebView tree on disk")
		}
	})
}

// TestUWPWebView2LevelDBExtract is the 84-03 Wave-3 target: once analyze_uwp
// parses the resolved EBWebView Local Storage / IndexedDB LevelDB into
// r.LevelDB, dissecting an installed-MSIX dir whose EBWebView profile carries
// a real Local Storage/leveldb subtree must populate r.LevelDB with parsed
// entries — the upstream wiring that lets scorer_storage.go credit parsed
// schema/keys (not shallow profile-path presence). When no LevelDB is on
// disk, r.LevelDB must stay nil (honest-empty, never synthesized).
func TestUWPWebView2LevelDBExtract(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)

	installDir := filepath.Join(root, "5319275A.WhatsAppDesktop_2.2615.101.0_x64__cv1g1gvanyjgm")
	ebProfile := filepath.Join(root, "Packages", "5319275A.WhatsAppDesktop_cv1g1gvanyjgm",
		"LocalCache", "EBWebView", "Default")
	lsDir := filepath.Join(ebProfile, "Local Storage", "leveldb")
	for _, d := range []string{installDir, lsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(installDir, "AppxManifest.xml"),
		[]byte("<Package/>"), 0o644); err != nil {
		t.Fatalf("write AppxManifest.xml: %v", err)
	}
	// A real LevelDB log entry with a recognizable key so the parse yields
	// a non-empty schema (key enumeration). LevelDB log record framing:
	// 7-byte block header (crc32[4] + len[2] + type[1]) then payload.
	writeLevelDBLog(t, filepath.Join(lsDir, "000003.log"))
	if err := os.WriteFile(filepath.Join(lsDir, "CURRENT"),
		[]byte("MANIFEST-000001\n"), 0o644); err != nil {
		t.Fatalf("write CURRENT: %v", err)
	}

	r := &DissectResult{debugRec: debug.NopRecorder()}
	analyzeUWP(r, installDir, Options{})

	if r.WebView2Info == nil || len(r.WebView2Info.Profiles) == 0 {
		t.Fatalf("WebView2Info not populated from real EBWebView tree")
	}
	if r.LevelDB == nil {
		t.Fatalf("r.LevelDB nil: parsed EBWebView Local Storage LevelDB not wired into r.LevelDB")
	}
	if r.LevelDB.Stats.LogFiles == 0 && len(r.LevelDB.Entries) == 0 {
		t.Errorf("r.LevelDB carries no parsed log/entries: %+v", r.LevelDB.Stats)
	}

	t.Run("nil when no LevelDB on disk", func(t *testing.T) {
		emptyRoot := t.TempDir()
		t.Setenv("LOCALAPPDATA", emptyRoot)
		emptyInstall := filepath.Join(emptyRoot, "5319275A.WhatsAppDesktop_2.2615.101.0_x64__cv1g1gvanyjgm")
		if err := os.MkdirAll(emptyInstall, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", emptyInstall, err)
		}
		if err := os.WriteFile(filepath.Join(emptyInstall, "AppxManifest.xml"),
			[]byte("<Package/>"), 0o644); err != nil {
			t.Fatalf("write AppxManifest.xml: %v", err)
		}
		er := &DissectResult{debugRec: debug.NopRecorder()}
		analyzeUWP(er, emptyInstall, Options{})
		if er.LevelDB != nil {
			t.Fatalf("fabricated r.LevelDB with no LevelDB on disk: %+v", er.LevelDB)
		}
	})
}

// writeLevelDBLog writes a minimal valid LevelDB log file containing one
// PUT record (sequence header + one key/value) so leveldb.ParseDirectory
// yields a non-empty parse result.
func writeLevelDBLog(t *testing.T, path string) {
	t.Helper()
	// LevelDB write batch: seq[8] + count[4] + (tag=1 PUT, klen, key, vlen, val)
	batch := []byte{
		1, 0, 0, 0, 0, 0, 0, 0, // sequence number
		1, 0, 0, 0, // record count
		1,                // ValueType kTypeValue (PUT)
		3, 'k', 'e', 'y', // key (varint len=3)
		5, 'v', 'a', 'l', 'u', 'e', // value (varint len=5)
	}
	crc := make([]byte, 4) // parser tolerates crc; left zero
	length := []byte{byte(len(batch)), byte(len(batch) >> 8)}
	recType := []byte{1} // kFullType
	rec := append(append(append(append([]byte{}, crc...), length...), recType...), batch...)
	if err := os.WriteFile(path, rec, 0o644); err != nil {
		t.Fatalf("write leveldb log %s: %v", path, err)
	}
}

var v8CodeCacheHeader = []byte{0xde, 0xc0, 0x17, 0xc0, 0x00, 0x00, 0x00, 0x00}

// TestUWPWebView2JSExtract is the 84-02 Wave-2 target: once analyze_uwp
// feeds recovered EBWebView Code Cache / Service Worker JS source through
// analyzeJS and runs the secrets scan over the resolved profile path,
// dissecting an installed-MSIX dir whose EBWebView profile carries cached
// JS must populate r.JSAnalysis (and r.Secrets when a credential is present)
// — the upstream wiring that lets the UNCHANGED scorer_crypto.go /
// scorer_source_layer.go fire on real signal.
func TestUWPWebView2JSExtract(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)

	installDir := filepath.Join(root, "5319275A.WhatsAppDesktop_2.2615.101.0_x64__cv1g1gvanyjgm")
	ebProfile := filepath.Join(root, "Packages", "5319275A.WhatsAppDesktop_cv1g1gvanyjgm",
		"LocalCache", "EBWebView", "Default")
	ccDir := filepath.Join(ebProfile, "Code Cache", "js", "00")
	swDir := filepath.Join(ebProfile, "Service Worker", "ScriptCache")
	for _, d := range []string{installDir, ccDir, swDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(installDir, "AppxManifest.xml"),
		[]byte("<Package/>"), 0o644); err != nil {
		t.Fatalf("write AppxManifest.xml: %v", err)
	}
	// Real-signal-shaped JS source with a crypto ref + an embedded secret.
	jsSrc := "async function e(){const k=await crypto.subtle.importKey('raw',x);" +
		"const aws_secret_access_key='AKIAIOSFODNN7EXAMPLE';" +
		"return fetch('https://web.whatsapp.com/api',{headers:{a:aws_secret_access_key}})}"
	ccBlob := append(append([]byte{}, v8CodeCacheHeader...), []byte(jsSrc)...)
	if err := os.WriteFile(filepath.Join(ccDir, "0_abcdef01"), ccBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	swSrc := "self.addEventListener('install',e=>{new WebSocket('wss://w.whatsapp.com')})"
	swBlob := append(append([]byte{}, v8CodeCacheHeader...), []byte(swSrc)...)
	if err := os.WriteFile(filepath.Join(swDir, "1_112233"), swBlob, 0o600); err != nil {
		t.Fatal(err)
	}

	r := &DissectResult{debugRec: debug.NopRecorder()}
	analyzeUWP(r, installDir, Options{})

	if r.WebView2Info == nil || len(r.WebView2Info.Profiles) == 0 {
		t.Fatalf("WebView2Info not populated from real EBWebView tree")
	}
	if r.JSAnalysis == nil {
		t.Fatalf("r.JSAnalysis nil: recovered EBWebView JS not wired into JSAnalysis")
	}
	// JSAnalysis must reflect the recovered source (network call markers).
	if len(r.JSAnalysis.NetworkCalls) == 0 {
		t.Errorf("JSAnalysis.NetworkCalls empty: recovered JS source not analyzed")
	}
	if r.Secrets == nil || r.Secrets.TotalFindings == 0 {
		t.Fatalf("r.Secrets not populated: secrets scan not run over resolved EBWebView profile")
	}
}

func TestApplyPulledJS_SetsJSAnalysis(t *testing.T) {
	r := &DissectResult{}
	ApplyPulledJS(r, "// recovered-from: https://x/a.js\nfunction a(){return 1}\nconst b=()=>2;\n")
	if r.JSAnalysis == nil || r.JSAnalysis.Size == 0 {
		t.Fatalf("JSAnalysis not set from pulled JS: %+v", r.JSAnalysis)
	}
}

func TestApplyPulledCSS_SetsRecoveredCSS(t *testing.T) {
	r := &DissectResult{}
	ApplyPulledCSS(r, []CSSEntry{
		{Path: "https://x/s.css", Source: "@media screen{.x{display:flex}}"},
		{Path: "https://x/s.css", Source: ".y{color:red}"},
	})
	if r.RecoveredCSS == nil || r.RecoveredCSS.Files != 2 {
		t.Fatalf("RecoveredCSS not set/counted: %+v", r.RecoveredCSS)
	}
	if len(r.RecoveredCSS.Origins) != 1 {
		t.Fatalf("origins not deduped: %+v", r.RecoveredCSS.Origins)
	}
}

func TestApplyPulled_HonestEmpty(t *testing.T) {
	r := &DissectResult{}
	ApplyPulledJS(r, "")
	ApplyPulledCSS(r, nil)
	if r.JSAnalysis != nil || r.RecoveredCSS != nil {
		t.Fatal("synthesized output from empty input")
	}
}
