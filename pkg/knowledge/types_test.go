package knowledge

import (
	"encoding/json"
	"testing"
	"time"
)

func TestKnowledgeResultRoundTrip(t *testing.T) {
	now := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	orig := KnowledgeResult{
		AppName:    "TestApp",
		Framework:  "Electron",
		Version:    "29.1.0",
		AnalyzedAt: now,
		Duration:   5 * time.Second,
		SourcePath: "/tmp/testapp",
		UI: &UIKnowledge{
			Framework: "React",
			Version:   "18.2.0",
			IsSPA:     true,
			Routes: []AppRoute{
				{Path: "/", Component: "Home"},
				{Path: "/login", Component: "Login"},
			},
			Components:   []string{"Header", "Footer"},
			CSSFramework: "tailwind",
			BuildTool:    "vite",
		},
		Communication: &CommunicationKnowledge{
			Endpoints: []Endpoint{
				{URL: "https://api.example.com/v1", Methods: []string{"GET", "POST"}, Purpose: "main API", AuthType: "bearer"},
			},
			Protocols:          []string{"https", "wss"},
			DataFormats:        []string{"json"},
			CertificatePinning: true,
		},
		Auth: &AuthKnowledge{
			Methods: []AuthMethod{
				{Type: "oauth2", HeaderName: "Authorization"},
			},
			TokenStorage: "localStorage",
			MFA:          true,
		},
		IPC: &IPCKnowledge{
			Channels: []IPCChannel{
				{Name: "get-config", Direction: "renderer-to-main", Privileged: true, RiskLevel: "high"},
			},
			Protocols: []string{"ipc"},
		},
		Security: &SecurityKnowledge{
			RiskScore: 75,
			RiskLevel: "HIGH",
			Settings: []SecuritySetting{
				{Name: "nodeIntegration", Value: "true", Safe: false, Comment: "dangerous"},
			},
			Vulnerabilities: []string{"XSS via webview"},
		},
		Stealth: &StealthKnowledge{
			ScreenCaptureBlock: true,
			ScreenShareHide:    true,
			AntiDebugging:      []string{"isDebuggerPresent"},
		},
		Telemetry: &TelemetryKnowledge{
			Services: []TelemetryService{
				{Name: "Sentry", Category: "error_tracking", Endpoint: "https://sentry.io"},
			},
		},
		SourceFiles: []SourceFile{
			{Path: "main.js", Original: "main.js", Size: 1024, Purpose: "entry point", Content: []byte("console.log")},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded KnowledgeResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify key fields
	if decoded.AppName != "TestApp" {
		t.Errorf("AppName = %q, want %q", decoded.AppName, "TestApp")
	}
	if decoded.Framework != "Electron" {
		t.Errorf("Framework = %q", decoded.Framework)
	}
	if decoded.UI == nil {
		t.Fatal("UI is nil")
	}
	if !decoded.UI.IsSPA {
		t.Error("UI.IsSPA should be true")
	}
	if len(decoded.UI.Routes) != 2 {
		t.Errorf("UI.Routes len = %d, want 2", len(decoded.UI.Routes))
	}
	if decoded.UI.Routes[0].Path != "/" {
		t.Errorf("first route path = %q", decoded.UI.Routes[0].Path)
	}
	if decoded.Communication == nil || !decoded.Communication.CertificatePinning {
		t.Error("CertificatePinning should be true")
	}
	if decoded.Auth == nil || !decoded.Auth.MFA {
		t.Error("MFA should be true")
	}
	if decoded.Security == nil || decoded.Security.RiskScore != 75 {
		t.Error("RiskScore should be 75")
	}
	if decoded.Stealth == nil || !decoded.Stealth.ScreenCaptureBlock {
		t.Error("ScreenCaptureBlock should be true")
	}
	// SourceFile.Content should be omitted from JSON (json:"-")
	if len(decoded.SourceFiles) != 1 {
		t.Fatalf("SourceFiles len = %d", len(decoded.SourceFiles))
	}
	if decoded.SourceFiles[0].Content != nil {
		t.Error("SourceFile.Content should be nil after JSON round-trip")
	}
	if decoded.SourceFiles[0].Size != 1024 {
		t.Errorf("SourceFile.Size = %d", decoded.SourceFiles[0].Size)
	}
}

func TestKnowledgeResultOmitEmpty(t *testing.T) {
	minimal := KnowledgeResult{
		AppName:   "Minimal",
		Framework: "Tauri",
	}
	data, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"communication", "auth", "ui", "ipc", "security", "stealth", "telemetry", "source_files", "version"} {
		if _, ok := m[key]; ok {
			t.Errorf("key %q should be omitted when nil/empty", key)
		}
	}
}
