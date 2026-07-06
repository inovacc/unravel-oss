/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"strings"
	"testing"
)

func TestGenerate_AllOptions(t *testing.T) {
	config := ScriptConfig{
		PackageName:    "com.example.app",
		IncludeSSL:     true,
		IncludeRoot:    true,
		IncludeDebug:   true,
		IncludeNetwork: true,
		IncludeStorage: true,
		IncludeCrypto:  true,
		IncludeIPC:     true,
		CustomHooks:    []string{"com.example.MyClass.myMethod"},
	}

	result := Generate(config)

	if result.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q, want %q", result.PackageName, "com.example.app")
	}

	// 7 built-in + 1 custom = 8
	if len(result.Scripts) != 8 {
		t.Fatalf("got %d scripts, want 8", len(result.Scripts))
	}

	expectedNames := []string{
		"ssl_pinning_bypass", "root_detection_bypass", "anti_debug_bypass",
		"network_capture", "storage_monitor", "crypto_monitor", "ipc_monitor",
		"custom_com_example_MyClass_myMethod",
	}

	for i, name := range expectedNames {
		if result.Scripts[i].Name != name {
			t.Errorf("script[%d].Name = %q, want %q", i, result.Scripts[i].Name, name)
		}
	}

	// Verify all scripts contain Java.perform
	for _, s := range result.Scripts {
		if !strings.Contains(s.Content, "Java.perform") {
			t.Errorf("script %q missing Java.perform", s.Name)
		}
	}

	// Verify categories
	for _, s := range result.Scripts {
		switch {
		case strings.Contains(s.Name, "bypass"):
			if s.Category != "bypass" {
				t.Errorf("script %q category = %q, want bypass", s.Name, s.Category)
			}
		case strings.Contains(s.Name, "monitor") || strings.Contains(s.Name, "capture") || strings.Contains(s.Name, "custom"):
			if s.Category != "monitor" {
				t.Errorf("script %q category = %q, want monitor", s.Name, s.Category)
			}
		}
	}
}

func TestGenerate_Minimal(t *testing.T) {
	config := ScriptConfig{
		PackageName:    "com.example.minimal",
		IncludeNetwork: true,
	}

	result := Generate(config)

	if len(result.Scripts) != 1 {
		t.Fatalf("got %d scripts, want 1", len(result.Scripts))
	}

	if result.Scripts[0].Name != "network_capture" {
		t.Errorf("script name = %q, want network_capture", result.Scripts[0].Name)
	}
}

func TestGenerate_NoOptions(t *testing.T) {
	result := Generate(ScriptConfig{PackageName: "com.example.empty"})

	if len(result.Scripts) != 0 {
		t.Errorf("got %d scripts, want 0", len(result.Scripts))
	}
}

func TestGenerateFromAnalysis_WithCertPinning(t *testing.T) {
	input := AnalysisInput{
		PackageName:    "com.example.pinned",
		HasCertPinning: true,
	}

	result := GenerateFromAnalysis(input)

	if result.PackageName != "com.example.pinned" {
		t.Errorf("PackageName = %q, want com.example.pinned", result.PackageName)
	}

	hasSSL := false
	hasNetwork := false

	for _, s := range result.Scripts {
		if s.Name == "ssl_pinning_bypass" {
			hasSSL = true
		}

		if s.Name == "network_capture" {
			hasNetwork = true
		}
	}

	if !hasSSL {
		t.Error("missing ssl_pinning_bypass script")
	}

	if !hasNetwork {
		t.Error("missing network_capture script")
	}

	found := false
	for _, ad := range result.AutoDetected {
		if strings.Contains(ad, "cert pinning") {
			found = true
		}
	}

	if !found {
		t.Error("auto-detected should include cert pinning")
	}
}

func TestGenerateFromAnalysis_WithRootDetection(t *testing.T) {
	input := AnalysisInput{
		PackageName: "com.example.rooted",
		NativeFindings: []NativeFinding{
			{Category: "root-detection"},
			{Category: "anti-debug"},
		},
	}

	result := GenerateFromAnalysis(input)

	hasRoot := false
	hasDebug := false

	for _, s := range result.Scripts {
		if s.Name == "root_detection_bypass" {
			hasRoot = true
		}

		if s.Name == "anti_debug_bypass" {
			hasDebug = true
		}
	}

	if !hasRoot {
		t.Error("missing root_detection_bypass script")
	}

	if !hasDebug {
		t.Error("missing anti_debug_bypass script")
	}
}

func TestGenerateFromAnalysis_Empty(t *testing.T) {
	result := GenerateFromAnalysis(AnalysisInput{})

	// Should still get network monitor
	if len(result.Scripts) != 1 {
		t.Fatalf("got %d scripts, want 1 (network monitor)", len(result.Scripts))
	}

	if result.Scripts[0].Name != "network_capture" {
		t.Errorf("script name = %q, want network_capture", result.Scripts[0].Name)
	}
}

func TestGenerateFromAnalysis_FullAPK(t *testing.T) {
	input := AnalysisInput{
		PackageName:     "com.example.full",
		HasCertPinning:  true,
		HasExportedComp: true,
		NativeFindings: []NativeFinding{
			{Category: "root-detection"},
			{Category: "anti-debug"},
		},
		DEXRiskAPIs: []string{"javax.crypto.Cipher"},
	}

	result := GenerateFromAnalysis(input)

	expectedScripts := map[string]bool{
		"ssl_pinning_bypass":    false,
		"root_detection_bypass": false,
		"anti_debug_bypass":     false,
		"network_capture":       false,
		"crypto_monitor":        false,
		"ipc_monitor":           false,
	}

	for _, s := range result.Scripts {
		if _, ok := expectedScripts[s.Name]; ok {
			expectedScripts[s.Name] = true
		}
	}

	for name, found := range expectedScripts {
		if !found {
			t.Errorf("missing expected script: %s", name)
		}
	}

	// All scripts must contain Java.perform
	for _, s := range result.Scripts {
		if !strings.Contains(s.Content, "Java.perform") {
			t.Errorf("script %q missing Java.perform", s.Name)
		}
	}

	if len(result.AutoDetected) < 4 {
		t.Errorf("expected at least 4 auto-detected reasons, got %d", len(result.AutoDetected))
	}
}

func TestCustomHooks(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		wantMethod bool
	}{
		{"class and method", "com.example.Foo.bar", true},
		{"class only", "com.example.Foo", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := customHook(tt.pattern)

			if !strings.Contains(script.Content, "Java.perform") {
				t.Error("missing Java.perform")
			}

			if !strings.Contains(script.Name, "custom_") {
				t.Errorf("name %q should start with custom_", script.Name)
			}

			if tt.wantMethod {
				if !strings.Contains(script.Content, ".implementation") {
					t.Error("method hook should contain .implementation")
				}
			}
		})
	}
}

func TestGenerateFromAnalysis_DuplicateNativeFindings(t *testing.T) {
	input := AnalysisInput{
		NativeFindings: []NativeFinding{
			{Category: "root-detection"},
			{Category: "root-detection"},
			{Category: "anti-debug"},
			{Category: "anti-debug"},
		},
	}

	result := GenerateFromAnalysis(input)

	rootCount := 0
	debugCount := 0

	for _, s := range result.Scripts {
		if s.Name == "root_detection_bypass" {
			rootCount++
		}

		if s.Name == "anti_debug_bypass" {
			debugCount++
		}
	}

	if rootCount != 1 {
		t.Errorf("root_detection_bypass count = %d, want 1", rootCount)
	}

	if debugCount != 1 {
		t.Errorf("anti_debug_bypass count = %d, want 1", debugCount)
	}
}

func TestScriptDescriptions(t *testing.T) {
	config := ScriptConfig{
		IncludeSSL:     true,
		IncludeRoot:    true,
		IncludeDebug:   true,
		IncludeNetwork: true,
		IncludeStorage: true,
		IncludeCrypto:  true,
		IncludeIPC:     true,
	}

	result := Generate(config)

	for _, s := range result.Scripts {
		if s.Description == "" {
			t.Errorf("script %q has empty description", s.Name)
		}

		if s.Category == "" {
			t.Errorf("script %q has empty category", s.Name)
		}

		if s.Content == "" {
			t.Errorf("script %q has empty content", s.Name)
		}
	}
}

func TestGenerateFromAnalysis_CryptoAPIs(t *testing.T) {
	tests := []struct {
		name string
		apis []string
		want bool
	}{
		{"Cipher", []string{"javax.crypto.Cipher"}, true},
		{"MessageDigest", []string{"java.security.MessageDigest"}, true},
		{"SecretKey", []string{"javax.crypto.spec.SecretKeySpec"}, true},
		{"unrelated", []string{"java.io.File"}, false},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateFromAnalysis(AnalysisInput{DEXRiskAPIs: tt.apis})

			hasCrypto := false
			for _, s := range result.Scripts {
				if s.Name == "crypto_monitor" {
					hasCrypto = true
				}
			}

			if hasCrypto != tt.want {
				t.Errorf("crypto_monitor present = %v, want %v", hasCrypto, tt.want)
			}
		})
	}
}
