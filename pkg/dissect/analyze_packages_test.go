/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// TestUWPScaffolds_Populated verifies BUG-08 / D-08: after writeUWPScaffolds
// runs against a UWP analysis result, all 3 sibling scaffolds
// (communication/endpoints.json, security/config.json, telemetry/services.json)
// exist with non-empty JSON content reflecting the manifest + score data.
func TestUWPScaffolds_Populated(t *testing.T) {
	out := t.TempDir()

	u := &uwp.Result{
		IsUWP: true,
		Manifest: &uwp.ManifestSummary{
			PFN: "5319275A.WhatsAppDesktop_cv1g1gvanyjgm",
			Identity: uwp.IdentityInfo{
				Name:      "5319275A.WhatsAppDesktop",
				Publisher: "CN=...",
				Version:   "2.2615.101.0",
			},
			Capabilities: []uwp.CapabilityRef{
				{Name: "internetClient", Namespace: "", Index: 0},
				{Name: "internetClientServer", Namespace: "", Index: 1},
				{Name: "graphicsCaptureWithoutBorder", Namespace: "uap6", Index: 2},
				{Name: "broadFileSystemAccess", Namespace: "rescap", Index: 3},
				{Name: "telemetry", Namespace: "rescap", Index: 4},
			},
			EntryPoints: []uwp.EntryPoint{
				{Id: "App", Executable: "WhatsApp.exe", EntryPoint: "WhatsApp.App"},
			},
		},
		Score: &uwp.Score{Value: 95, Level: "critical", Base: 80, Multiplier: 1.0},
		DPAPIBlobs: []uwp.DPAPIBlob{
			{Path: "C:/.../LocalCache/Microsoft/MSTeams/EBWebView/Default/Login Data"},
		},
	}

	if err := writeUWPScaffolds(out, u); err != nil {
		t.Fatalf("writeUWPScaffolds: %v", err)
	}

	// communication/endpoints.json
	commsPath := filepath.Join(out, "communication", "endpoints.json")
	checkNonEmptyJSON(t, commsPath)
	var comms UWPCommunicationReport
	if data, err := os.ReadFile(commsPath); err == nil {
		_ = json.Unmarshal(data, &comms)
	}
	if comms.PFN != "5319275A.WhatsAppDesktop_cv1g1gvanyjgm" {
		t.Errorf("communication PFN = %q, want WhatsApp PFN", comms.PFN)
	}
	if len(comms.Endpoints) == 0 {
		t.Error("communication endpoints empty (expected internetClient/internetClientServer)")
	}
	if len(comms.EntryPoints) != 1 {
		t.Errorf("communication entry_points len = %d, want 1", len(comms.EntryPoints))
	}

	// security/config.json
	secPath := filepath.Join(out, "security", "config.json")
	checkNonEmptyJSON(t, secPath)
	var sec UWPSecurityReport
	if data, err := os.ReadFile(secPath); err == nil {
		_ = json.Unmarshal(data, &sec)
	}
	if sec.Score == nil || sec.Score.Level != "critical" {
		t.Errorf("security score not populated: %+v", sec.Score)
	}
	if len(sec.Capabilities) != 5 {
		t.Errorf("security capabilities len = %d, want 5", len(sec.Capabilities))
	}
	if sec.DPAPIBlobCount != 1 {
		t.Errorf("DPAPIBlobCount = %d, want 1", sec.DPAPIBlobCount)
	}
	if len(sec.DPAPIFlags) != 1 {
		t.Errorf("DPAPIFlags len = %d, want 1", len(sec.DPAPIFlags))
	}

	// telemetry/services.json
	telPath := filepath.Join(out, "telemetry", "services.json")
	checkNonEmptyJSON(t, telPath)
	var tel UWPTelemetryReport
	if data, err := os.ReadFile(telPath); err == nil {
		_ = json.Unmarshal(data, &tel)
	}
	// `telemetry` (rescap) and `broadFileSystemAccess` should both surface.
	if len(tel.Services) < 2 {
		t.Errorf("telemetry services len = %d, want >= 2 (rescap + telemetry-substring)", len(tel.Services))
	}
}

func checkNonEmptyJSON(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected scaffold file %s: %v", path, err)
	}
	if info.Size() < 2 { // must have at least `{}`
		t.Fatalf("scaffold file %s is empty (size=%d)", path, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("scaffold %s is not valid JSON: %v", path, err)
	}
}
