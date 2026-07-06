/*
Copyright (c) 2026 Security Research
*/

package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleManifestConfirmed = `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Sample" Version="1.0.0.0" Publisher="CN=Sample"/>
  <Properties>
    <DisplayName>Sample</DisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/>
  </Dependencies>
</Package>`

const sampleManifestUAPOnly = `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="X" Version="1.0.0.0" Publisher="CN=X"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/>
  </Dependencies>
</Package>`

const sampleManifestFoundationOnly = `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Version="1.0.0.0" Publisher="CN=X"/>
</Package>`

func TestDetectUWPFromManifest_Confirmed(t *testing.T) {
	got, err := DetectFromManifestBytes([]byte(sampleManifestConfirmed))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].Name != "UWP" {
		t.Errorf("Name = %q", got[0].Name)
	}
	if got[0].Source != "appx-manifest" {
		t.Errorf("Source = %q", got[0].Source)
	}
	if got[0].Confidence != "confirmed" {
		t.Errorf("Confidence = %q, want confirmed", got[0].Confidence)
	}
	hasUap, hasUniversal := false, false
	for _, e := range got[0].Evidence {
		if strings.Contains(e, "xmlns:uap") {
			hasUap = true
		}
		if strings.Contains(e, "Windows.Universal") {
			hasUniversal = true
		}
	}
	if !hasUap || !hasUniversal {
		t.Errorf("Evidence missing expected tokens: %v", got[0].Evidence)
	}
}

func TestDetectUWPFromManifest_UAPHigh(t *testing.T) {
	got, err := DetectFromManifestBytes([]byte(sampleManifestUAPOnly))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].Confidence != "high" {
		t.Errorf("Confidence = %q, want high", got[0].Confidence)
	}
}

func TestDetectUWPFromManifest_NoUap(t *testing.T) {
	got, err := DetectFromManifestBytes([]byte(sampleManifestFoundationOnly))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestDetectUWPFromManifest_Malformed(t *testing.T) {
	got, err := DetectFromManifestBytes([]byte("<Package"))
	if err == nil {
		t.Error("want error for malformed XML, got nil")
	}
	if got != nil {
		t.Errorf("want nil result on error, got %v", got)
	}
}

func TestDetectUWPFromManifest_Empty(t *testing.T) {
	got, err := DetectFromManifestBytes(nil)
	if err == nil {
		t.Error("want error for empty input")
	}
	if got != nil {
		t.Errorf("want nil result, got %v", got)
	}
}

func TestDetectFromManifest_PathTraversalRejected(t *testing.T) {
	if _, err := DetectFromManifest("../etc/passwd"); err == nil {
		t.Error("want error rejecting traversal path, got nil")
	}
}

func TestDetectFromManifest_FileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "AppxManifest.xml")
	if err := os.WriteFile(p, []byte(sampleManifestConfirmed), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := DetectFromManifest(p)
	if err != nil {
		t.Fatalf("DetectFromManifest: %v", err)
	}
	if len(got) != 1 || got[0].Confidence != "confirmed" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestDetectFromManifest_RejectsDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := DetectFromManifest(dir); err == nil {
		t.Error("want error when path is a directory")
	}
}

func TestDetectFromManifest_RejectsMissing(t *testing.T) {
	if _, err := DetectFromManifest(filepath.Join(t.TempDir(), "nope.xml")); err == nil {
		t.Error("want error for missing file")
	}
}
