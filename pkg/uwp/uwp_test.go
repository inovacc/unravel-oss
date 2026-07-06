/*
Copyright (c) 2026 Security Research
*/

package uwp_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/uwp"
	_ "github.com/inovacc/unravel-oss/pkg/uwp/runtime" // wire orchestrator
)

const minimalManifest = `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Demo" Version="1.0.0.0" Publisher="CN=Demo"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/>
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient"/>
  </Capabilities>
</Package>`

const rescapManifest = `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Demo" Version="1.0.0.0" Publisher="CN=Demo"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/>
  </Dependencies>
  <Capabilities>
    <rescap:Capability Name="runFullTrust"/>
  </Capabilities>
</Package>`

func writeManifestDir(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "AppxManifest.xml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeMSIXArchive(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "sample.msix")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("AppxManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(body))
	_ = zw.Close()
	_ = f.Close()
	return p
}

func TestUWPAnalyze_AlreadyExtracted(t *testing.T) {
	dir := writeManifestDir(t, minimalManifest)
	res, err := uwp.Analyze(dir, uwp.Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !res.IsUWP {
		t.Errorf("IsUWP should be true; res=%+v", res)
	}
	if res.Manifest == nil {
		t.Error("Manifest summary nil")
	}
}

func TestUWPAnalyze_MSIXArchive(t *testing.T) {
	p := writeMSIXArchive(t, minimalManifest)
	res, err := uwp.Analyze(p, uwp.Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !res.IsUWP {
		t.Errorf("IsUWP should be true after MSIX extract; res.Errors=%v", res.Errors)
	}
}

func TestUWPAnalyze_RescapCritical(t *testing.T) {
	dir := writeManifestDir(t, rescapManifest)
	res, err := uwp.Analyze(dir, uwp.Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Score == nil {
		t.Fatal("Score nil")
	}
	if res.Score.Level != "critical" {
		t.Errorf("Level = %q, want critical", res.Score.Level)
	}
}

func TestUWPAnalyze_DPAPIFlagOnly(t *testing.T) {
	dir := writeManifestDir(t, minimalManifest)
	// Build a fake DPAPI blob inside LocalState/.
	ls := filepath.Join(dir, "LocalState")
	if err := os.MkdirAll(ls, 0o755); err != nil {
		t.Fatal(err)
	}
	blob := append([]byte{}, uwp.DPAPIMagic...)
	blob = append(blob, []byte("encrypted-payload-stub")...)
	if err := os.WriteFile(filepath.Join(ls, "secret.dat"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := uwp.Analyze(dir, uwp.Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.DPAPIBlobs) != 1 {
		t.Fatalf("expected 1 DPAPI blob, got %d (errors=%v)", len(res.DPAPIBlobs), res.Errors)
	}
	if len(res.DPAPIBlobs[0].Bytes) != len(uwp.DPAPIMagic) {
		t.Errorf("recorded blob bytes len = %d, want %d (header only — D-18)",
			len(res.DPAPIBlobs[0].Bytes), len(uwp.DPAPIMagic))
	}
}

func TestUWPAnalyze_RejectsTraversalPath(t *testing.T) {
	_, err := uwp.Analyze("../etc/passwd", uwp.Options{})
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestUWPAnalyze_RubricOverride(t *testing.T) {
	dir := writeManifestDir(t, minimalManifest)
	rubricPath := filepath.Join(t.TempDir(), "capabilities.yaml")
	yaml := `weights:
  internetClient: 99
buckets:
  - {name: low, max: 10}
  - {name: medium, max: 30}
  - {name: high, max: 70}
  - {name: critical, max: 100}
`
	if err := os.WriteFile(rubricPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := uwp.Analyze(dir, uwp.Options{RubricPath: rubricPath})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Score == nil {
		t.Fatal("Score nil")
	}
	// 99 is well above the default internetClient weight; ensure the
	// override pushed the base score above the default.
	if res.Score.Base < 50 {
		t.Errorf("Base score = %d, want >= 50 with override weight=99", res.Score.Base)
	}
}
