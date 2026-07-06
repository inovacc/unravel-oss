/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"strings"
	"testing"
)

func TestGenerateCapture_WithDomains(t *testing.T) {
	domains := []string{"api.example.com", "cdn.example.com", "auth.example.com"}
	result := GenerateCapture("com.example.app", domains)

	if result.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q, want %q", result.PackageName, "com.example.app")
	}

	if len(result.Templates) != 4 {
		t.Fatalf("got %d templates, want 4", len(result.Templates))
	}

	if len(result.Domains) != 3 {
		t.Errorf("got %d domains, want 3", len(result.Domains))
	}

	// Verify each template references at least one domain
	for _, tmpl := range result.Templates {
		if !strings.Contains(tmpl.Content, "api.example.com") {
			t.Errorf("template %q missing domain reference", tmpl.Name)
		}
	}
}

func TestGenerateCapture_NoDomains(t *testing.T) {
	result := GenerateCapture("com.example.app", nil)

	if len(result.Templates) != 4 {
		t.Fatalf("got %d templates, want 4", len(result.Templates))
	}

	// mitmproxy should still have capture logic
	for _, tmpl := range result.Templates {
		if tmpl.Content == "" {
			t.Errorf("template %q has empty content", tmpl.Name)
		}
	}
}

func TestGenerateCaptureFromAnalysis_WithNetworkData(t *testing.T) {
	input := AnalysisInput{
		PackageName: "com.example.network",
		Domains:     []string{"api.example.com", "telemetry.example.com"},
	}

	result := GenerateCaptureFromAnalysis(input)

	if result.PackageName != "com.example.network" {
		t.Errorf("PackageName = %q, want %q", result.PackageName, "com.example.network")
	}

	if len(result.Domains) != 2 {
		t.Errorf("got %d domains, want 2", len(result.Domains))
	}

	if len(result.Templates) != 4 {
		t.Fatalf("got %d templates, want 4", len(result.Templates))
	}
}

func TestGenerateCaptureFromAnalysis_Empty(t *testing.T) {
	result := GenerateCaptureFromAnalysis(AnalysisInput{})

	if len(result.Templates) != 4 {
		t.Fatalf("got %d templates, want 4", len(result.Templates))
	}

	if len(result.Domains) != 0 {
		t.Errorf("got %d domains, want 0", len(result.Domains))
	}
}

func TestCaptureTemplateFormats(t *testing.T) {
	result := GenerateCapture("com.example.app", []string{"api.example.com"})

	expected := map[string]string{
		"capture_mitmproxy": "py",
		"pcapdroid_config":  "json",
		"burp_project":      "json",
		"charles_session":   "xml",
	}

	for _, tmpl := range result.Templates {
		want, ok := expected[tmpl.Name]
		if !ok {
			t.Errorf("unexpected template name: %q", tmpl.Name)

			continue
		}

		if tmpl.Format != want {
			t.Errorf("template %q format = %q, want %q", tmpl.Name, tmpl.Format, want)
		}
	}
}

func TestCaptureTemplateContent(t *testing.T) {
	domains := []string{"api.example.com"}
	result := GenerateCapture("com.example.app", domains)

	tests := []struct {
		name     string
		tool     string
		keywords []string
	}{
		{
			name:     "mitmproxy",
			tool:     "mitmproxy",
			keywords: []string{"mitmproxy", "def request", "def response", "SENSITIVE_HEADERS", "TARGET_DOMAINS"},
		},
		{
			name:     "pcapdroid",
			tool:     "pcapdroid",
			keywords: []string{"app_filter", "tls_decryption", "capture_domains"},
		},
		{
			name:     "burp",
			tool:     "burp",
			keywords: []string{"project_options", "scope", "advanced_mode"},
		},
		{
			name:     "charles",
			tool:     "charles",
			keywords: []string{"charles-session", "sslProxying", "mapLocal", "rewrite"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tmpl *CaptureTemplate

			for i := range result.Templates {
				if result.Templates[i].Tool == tt.tool {
					tmpl = &result.Templates[i]

					break
				}
			}

			if tmpl == nil {
				t.Fatalf("template for tool %q not found", tt.tool)
			}

			for _, kw := range tt.keywords {
				if !strings.Contains(tmpl.Content, kw) {
					t.Errorf("template %q missing keyword %q", tt.name, kw)
				}
			}

			if tmpl.Description == "" {
				t.Errorf("template %q has empty description", tt.name)
			}

			if tmpl.Tool != tt.tool {
				t.Errorf("template %q tool = %q, want %q", tt.name, tmpl.Tool, tt.tool)
			}
		})
	}
}

func TestCaptureTemplateDomainFiltering(t *testing.T) {
	// With domains: mitmproxy should have domain_match with actual filtering
	withDomains := GenerateCapture("com.example.app", []string{"api.example.com"})

	for _, tmpl := range withDomains.Templates {
		if tmpl.Tool == "mitmproxy" {
			if strings.Contains(tmpl.Content, "return True") {
				t.Error("mitmproxy with domains should not have catch-all return True")
			}
		}
	}

	// Without domains: mitmproxy should capture all
	noDomains := GenerateCapture("com.example.app", nil)

	for _, tmpl := range noDomains.Templates {
		if tmpl.Tool == "mitmproxy" {
			if !strings.Contains(tmpl.Content, "return True") {
				t.Error("mitmproxy without domains should have catch-all return True")
			}
		}
	}
}
