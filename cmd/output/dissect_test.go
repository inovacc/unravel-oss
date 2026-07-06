/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/garble"
)

// ── CollectDissectFindings ────────────────────────────────────────────────────

func TestCollectDissectFindings_Empty(t *testing.T) {
	t.Parallel()

	findings := CollectDissectFindings(&dissect.DissectResult{})
	if len(findings) != 0 {
		t.Errorf("empty DissectResult: expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestCollectDissectFindings_GarbleDetect(t *testing.T) {
	t.Parallel()

	t.Run("garbled", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			GarbleDetect: &garble.DetectionResult{
				IsGarbled:  true,
				Confidence: 0.85,
			},
		}
		findings := CollectDissectFindings(r)
		if !containsAny(findings, "GARBLED") {
			t.Errorf("expected GARBLED finding, got: %v", findings)
		}
	})

	t.Run("not garbled", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			GarbleDetect: &garble.DetectionResult{
				IsGarbled:  false,
				Confidence: 0.1,
			},
		}
		findings := CollectDissectFindings(r)
		if !containsAny(findings, "not garbled") {
			t.Errorf("expected 'not garbled' finding, got: %v", findings)
		}
	})
}

func TestCollectDissectFindings_GarbleInfo(t *testing.T) {
	t.Parallel()

	r := &dissect.DissectResult{
		GarbleInfo: &garble.BinaryInfo{
			GoVersion:  "go1.21.0",
			ModulePath: "github.com/example/app",
		},
	}
	findings := CollectDissectFindings(r)
	assertContains(t, findings, "go1.21.0")
	assertContains(t, findings, "github.com/example/app")
}

func TestCollectDissectFindings_CertInfo(t *testing.T) {
	t.Parallel()

	t.Run("signed with common name", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			CertInfo: &cert.CertInfo{
				HasSignature: true,
				Signer: &cert.CertDetail{
					CommonName: "ACME Corp",
				},
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "ACME Corp")
	})

	t.Run("signed signer empty name uses org", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			CertInfo: &cert.CertInfo{
				HasSignature: true,
				Signer: &cert.CertDetail{
					CommonName:   "",
					Organization: "BigOrg",
				},
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "BigOrg")
	})

	t.Run("no signer falls back to unknown", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			CertInfo: &cert.CertInfo{
				HasSignature: true,
				Signer:       nil,
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "unknown")
	})

	t.Run("unsigned", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			CertInfo: &cert.CertInfo{
				HasSignature: false,
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "No digital signature")
	})
}

func TestCollectDissectFindings_BeautifiedJS(t *testing.T) {
	t.Parallel()

	r := &dissect.DissectResult{
		BeautifiedJS: strings.Repeat("x", 5000),
	}
	findings := CollectDissectFindings(r)
	assertContains(t, findings, "JS beautified")
	assertContains(t, findings, "5000 bytes")
}

func TestCollectDissectFindings_AIPrompt(t *testing.T) {
	t.Parallel()

	r := &dissect.DissectResult{
		AIPrompt: "You are an analyst...",
	}
	findings := CollectDissectFindings(r)
	assertContains(t, findings, "AI dissection prompt")
}

func TestCollectDissectFindings_ASARStats(t *testing.T) {
	t.Parallel()

	r := &dissect.DissectResult{
		ASARStats: &dissect.ASARSummary{
			FileCount: 123,
			TotalSize: 5 * 1024 * 1024,
		},
	}
	findings := CollectDissectFindings(r)
	assertContains(t, findings, "ASAR: 123 files")
}

func TestCollectDissectFindings_JSAnalysis(t *testing.T) {
	t.Parallel()

	t.Run("high obfuscation with dangerous calls", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{
				ObfuscationScore: 75,
				DangerousCalls:   []string{"eval", "Function"},
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "HIGH")
		assertContains(t, findings, "Dangerous calls: 2")
	})

	t.Run("medium obfuscation", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{
				ObfuscationScore: 30,
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "MEDIUM")
	})

	t.Run("low obfuscation", func(t *testing.T) {
		t.Parallel()
		r := &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{
				ObfuscationScore: 5,
			},
		}
		findings := CollectDissectFindings(r)
		assertContains(t, findings, "LOW")
	})
}

// ── printWrappedField ─────────────────────────────────────────────────────────

func TestPrintWrappedField_ShortValue(t *testing.T) {
	out := captureStdout(t, func() {
		printWrappedField("Name", "short.exe", 70)
	})

	if !strings.Contains(out, "Name:") {
		t.Errorf("expected 'Name:' in output, got: %q", out)
	}
	if !strings.Contains(out, "short.exe") {
		t.Errorf("expected 'short.exe' in output, got: %q", out)
	}
}

func TestPrintWrappedField_LongValue(t *testing.T) {
	longVal := strings.Repeat("a", 200)
	out := captureStdout(t, func() {
		printWrappedField("Path", longVal, 70)
	})

	// Should produce multiple lines since value > contentWidth
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("expected wrapped output with multiple lines, got %d lines: %q", len(lines), out)
	}
	// Each non-empty output line should start with ║
	for i, l := range lines {
		if l != "" && !strings.HasPrefix(l, "║") {
			t.Errorf("line %d does not start with ║: %q", i, l)
		}
	}
}

// ── PrintDissect smoke test ───────────────────────────────────────────────────

func TestPrintDissect_Smoke(t *testing.T) {
	r := &dissect.DissectResult{
		FileName: "app.exe",
		Path:     "/tmp/app.exe",
		Size:     1024 * 100,
		Detection: &detect.DetectResult{
			FileType:   "PE32",
			Category:   "binary",
			Confidence: "high",
		},
		Duration: 150 * time.Millisecond,
	}

	out := captureStdout(t, func() {
		PrintDissect(r)
	})

	if !strings.Contains(out, "app.exe") {
		t.Errorf("expected filename in output, got:\n%s", out)
	}
	if !strings.Contains(out, "100.0 KB") {
		t.Errorf("expected size in output, got:\n%s", out)
	}
	if !strings.Contains(out, "150ms") {
		t.Errorf("expected duration in output, got:\n%s", out)
	}
	if !strings.Contains(out, "PE32") {
		t.Errorf("expected file type in output, got:\n%s", out)
	}
}

func TestPrintDissect_WithErrors(t *testing.T) {
	r := &dissect.DissectResult{
		FileName:  "bad.exe",
		Detection: &detect.DetectResult{},
		Errors:    []string{"failed to read PE header", "checksum mismatch"},
		Duration:  10 * time.Millisecond,
	}

	out := captureStdout(t, func() {
		PrintDissect(r)
	})

	if !strings.Contains(out, "ERRORS (2)") {
		t.Errorf("expected 'ERRORS (2)' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "failed to read PE header") {
		t.Errorf("expected error text in output, got:\n%s", out)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func containsAny(strs []string, substr string) bool {
	for _, s := range strs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func assertContains(t *testing.T, strs []string, substr string) {
	t.Helper()
	if !containsAny(strs, substr) {
		t.Errorf("expected finding containing %q, got: %v", substr, strs)
	}
}
