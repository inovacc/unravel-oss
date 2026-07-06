/*
Copyright (c) 2026 Security Research
*/
package schema

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/electron/api"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/electron/stealth"
	"github.com/inovacc/unravel-oss/pkg/garble"
)

func TestExtract_MinimalResult(t *testing.T) {
	r := &dissect.DissectResult{
		Path:     "/tmp/test.apk",
		FileName: "test.apk",
		Detection: &detect.DetectResult{
			FileType: "apk",
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if s.AppName != "test.apk" {
		t.Errorf("AppName = %q, want %q", s.AppName, "test.apk")
	}
	if s.Framework != "android" {
		t.Errorf("Framework = %q, want %q", s.Framework, "android")
	}
	if s.Confidence != 0 {
		t.Errorf("Confidence = %f, want 0", s.Confidence)
	}
	if s.AnalysisDate.IsZero() {
		t.Error("AnalysisDate should be set")
	}
}

func TestExtract_WithNetworkAnalysis(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/app.apk",
		FileName:  "app.apk",
		Detection: &detect.DetectResult{FileType: "apk"},
		NetworkAnalysis: &network.ScanResult{
			Endpoints: []network.EndpointInfo{
				{URL: "https://api.example.com/v1"},
				{URL: "https://sentry.io/report"},
			},
			CertPinning:      &network.CertPinResult{},
			CleartextAllowed: true,
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if len(s.Communication.Endpoints) != 2 {
		t.Fatalf("Endpoints = %d, want 2", len(s.Communication.Endpoints))
	}
	if s.Communication.Endpoints[1].Purpose != "telemetry" {
		t.Errorf("sentry endpoint purpose = %q, want telemetry", s.Communication.Endpoints[1].Purpose)
	}
	if !s.Communication.CertificatePinning {
		t.Error("expected CertificatePinning = true")
	}
	if !s.Communication.CleartextAllowed {
		t.Error("expected CleartextAllowed = true")
	}
}

func TestExtract_WithElectronApp(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/app.asar",
		FileName:  "app.asar",
		Detection: &detect.DetectResult{FileType: "asar"},
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{
				Name:       "TestApp",
				Type:       "electron",
				Version:    "1.2.3",
				HasStealth: true,
				Telemetry:  []string{"mixpanel", "sentry"},
			},
			Analysis: app.SecurityResult{
				StealthFeatures: []stealth.Finding{
					{Name: "Content Protection", Description: "setContentProtection(true)"},
				},
				IPCCommands: []ipc.Finding{
					{Channel: "update-check", Direction: "renderer-to-main"},
				},
				APIEndpoints: []api.Finding{
					{URL: "https://api.testapp.com/v2", Purpose: "api"},
				},
				RiskScore: 75,
			},
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if s.AppName != "TestApp" {
		t.Errorf("AppName = %q, want TestApp", s.AppName)
	}
	if s.Framework != "electron" {
		t.Errorf("Framework = %q, want electron", s.Framework)
	}
	if s.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", s.Version)
	}
	if !s.Stealth.ScreenCaptureBlock {
		t.Error("expected ScreenCaptureBlock = true")
	}
	if len(s.IPC.Channels) != 1 {
		t.Fatalf("IPC channels = %d, want 1", len(s.IPC.Channels))
	}
	if s.IPC.Channels[0].Name != "update-check" {
		t.Errorf("IPC channel = %q, want update-check", s.IPC.Channels[0].Name)
	}
	if len(s.Telemetry.Services) != 2 {
		t.Errorf("Telemetry services = %d, want 2", len(s.Telemetry.Services))
	}
	if s.Security.RiskScore != 75 {
		t.Errorf("RiskScore = %d, want 75", s.Security.RiskScore)
	}
	if s.Confidence == 0 {
		t.Error("expected non-zero confidence")
	}
}

func TestExtract_WithManifest(t *testing.T) {
	exported := true
	r := &dissect.DissectResult{
		Path:      "/tmp/app.apk",
		FileName:  "app.apk",
		Detection: &detect.DetectResult{FileType: "apk"},
		ManifestInfo: &manifest.Manifest{
			Package:     "com.example.app",
			VersionName: "2.0.0",
			Security: manifest.SecurityFlags{
				Debuggable: true,
			},
			Permissions: []manifest.Permission{
				{Name: "android.permission.INTERNET", RiskLevel: "normal"},
				{Name: "android.permission.CAMERA", RiskLevel: "dangerous"},
			},
			Components: []manifest.Component{
				{Name: ".MainActivity", Type: "activity", Exported: &exported},
			},
		},
		ManifestAnalysis: &manifest.Analysis{
			SecurityScore: 45,
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if s.AppName != "com.example.app" {
		t.Errorf("AppName = %q, want com.example.app", s.AppName)
	}
	if s.Version != "2.0.0" {
		t.Errorf("Version = %q, want 2.0.0", s.Version)
	}
	if !s.Security.Debuggable {
		t.Error("expected Debuggable = true")
	}
	if len(s.Security.DangerousPermissions) != 1 {
		t.Fatalf("DangerousPermissions = %d, want 1", len(s.Security.DangerousPermissions))
	}
	if s.Security.RiskScore != 45 {
		t.Errorf("RiskScore = %d, want 45", s.Security.RiskScore)
	}
	// Exported component should appear as IPC channel
	if len(s.IPC.Channels) != 1 {
		t.Fatalf("IPC channels = %d, want 1", len(s.IPC.Channels))
	}
}

func TestExtract_WithSecrets(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/app.apk",
		FileName:  "app.apk",
		Detection: &detect.DetectResult{FileType: "apk"},
		Secrets: &secret.ScanResult{
			TotalFindings:  2,
			HighConfidence: 1,
			Findings: []secret.Finding{
				{Type: "api_key", Value: "AIza..."},
				{Type: "bearer_token", Value: "eyJ..."},
			},
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if len(s.Auth.Methods) != 2 {
		t.Fatalf("Auth methods = %d, want 2", len(s.Auth.Methods))
	}
}

func TestExtract_WithObfuscation(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/app.apk",
		FileName:  "app.apk",
		Detection: &detect.DetectResult{FileType: "apk"},
		ObfuscationAnalysis: &obfuscation.Result{
			Type: obfuscation.ObfR8,
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if s.Stealth.CodeObfuscation != "r8" {
		t.Errorf("CodeObfuscation = %q, want r8", s.Stealth.CodeObfuscation)
	}
}

func TestExtract_WithGarble(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/binary",
		FileName:  "binary",
		Detection: &detect.DetectResult{FileType: "pe"},
		GarbleDetect: &garble.DetectionResult{
			IsGarbled: true,
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if s.Stealth.CodeObfuscation != "garble" {
		t.Errorf("CodeObfuscation = %q, want garble", s.Stealth.CodeObfuscation)
	}
}

func TestExtract_WithTelemetry(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/app.apk",
		FileName:  "app.apk",
		Detection: &detect.DetectResult{FileType: "apk"},
		TelemetryAnalysis: &telemetry.ScanResult{
			SDKs: []telemetry.SDKInfo{
				{Name: "Firebase Analytics"},
				{Name: "Sentry"},
			},
			HasAnalytics: true,
		},
	}

	s, err := Extract(r, Options{})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if len(s.Telemetry.Services) != 2 {
		t.Fatalf("Telemetry services = %d, want 2", len(s.Telemetry.Services))
	}
	if !s.Telemetry.EventTracking {
		t.Error("expected EventTracking = true")
	}
}

func TestExtract_AIAnalysisMCP(t *testing.T) {
	r := &dissect.DissectResult{
		Path:      "/tmp/app.asar",
		FileName:  "app.asar",
		Detection: &detect.DetectResult{FileType: "asar"},
	}

	s, err := Extract(r, Options{AIAnalysisMCP: true})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if s.AIPrompt == "" {
		t.Error("expected non-empty AIPrompt with AIAnalysisMCP=true")
	}
}

func TestGenerateSchemaPrompt(t *testing.T) {
	s := &ApplicationSchema{
		AppName:   "TestApp",
		Framework: "electron",
		Version:   "1.0",
		Communication: CommunicationSchema{
			Endpoints: []Endpoint{{URL: "https://api.example.com", Purpose: "api"}},
		},
	}

	prompt := GenerateSchemaPrompt(s, &dissect.DissectResult{})

	if prompt == "" {
		t.Fatal("prompt should not be empty")
	}
	if !strings.Contains(prompt, "TestApp") {
		t.Error("prompt should contain app name")
	}
	if !strings.Contains(prompt, "api.example.com") {
		t.Error("prompt should contain endpoint URL")
	}
}

func TestCalculateConfidence(t *testing.T) {
	// Empty schema
	s := &ApplicationSchema{}
	if calculateConfidence(s) != 0 {
		t.Errorf("empty schema confidence = %f, want 0", calculateConfidence(s))
	}

	// Full schema
	s = &ApplicationSchema{
		Communication: CommunicationSchema{Endpoints: []Endpoint{{URL: "x"}}},
		Auth:          AuthSchema{Methods: []AuthMethod{{Type: "bearer"}}},
		Storage:       StorageSchema{Databases: []Database{{Type: "sqlite"}}},
		IPC:           IPCSchema{Channels: []IPCChannel{{Name: "x"}}},
		Stealth:       StealthSchema{ScreenCaptureBlock: true},
		Telemetry:     TelemetrySchema{Services: []TelemetryService{{Name: "x"}}},
		Security:      SecuritySchema{RiskScore: 50},
	}
	if calculateConfidence(s) != 1.0 {
		t.Errorf("full schema confidence = %f, want 1.0", calculateConfidence(s))
	}
}

func TestCategorizePurpose(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://sentry.io/report", "telemetry"},
		{"https://auth.example.com/login", "auth"},
		{"https://cdn.example.com/assets/img.png", "cdn"},
		{"wss://realtime.example.com", "websocket"},
		{"https://api.example.com/v1/users", "api"},
	}

	for _, tt := range tests {
		if got := categorizePurpose(tt.url); got != tt.want {
			t.Errorf("categorizePurpose(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestDetectFramework(t *testing.T) {
	tests := []struct {
		name string
		r    *dissect.DissectResult
		want string
	}{
		{"apk", &dissect.DissectResult{Detection: &detect.DetectResult{FileType: "apk"}}, "android"},
		{"asar", &dissect.DissectResult{Detection: &detect.DetectResult{FileType: "asar"}}, "electron"},
		{"deb", &dissect.DissectResult{Detection: &detect.DetectResult{FileType: "deb"}}, "debian"},
		{"rpm", &dissect.DissectResult{Detection: &detect.DetectResult{FileType: "rpm"}}, "rpm"},
		{"msi", &dissect.DissectResult{Detection: &detect.DetectResult{FileType: "msi"}}, "windows-installer"},
		{"unknown", &dissect.DissectResult{Detection: &detect.DetectResult{FileType: "xyz"}}, "xyz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectFramework(tt.r); got != tt.want {
				t.Errorf("detectFramework() = %q, want %q", got, tt.want)
			}
		})
	}
}
