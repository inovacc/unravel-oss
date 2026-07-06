/*
Copyright (c) 2026 Security Research
*/
package secret

import "testing"

func TestScanText_FindsAPIKeyInText(t *testing.T) {
	// AIza... matches the high-confidence TypeGoogleAPIKey pattern in patterns.go
	// (`AIza[0-9A-Za-z_-]{35}`). 35 trailing chars after the AIza prefix.
	const raw = "gemini_api_key = AIza" + "SyCNiOUFR3_XzarP9s8h7mOJ_8pcAvhtUf0"

	findings := ScanText("data_dir:test", raw)
	if len(findings) < 1 {
		t.Fatalf("expected >=1 finding, got %d", len(findings))
	}

	for _, f := range findings {
		if f.File != "data_dir:test" {
			t.Errorf("File = %q, want %q", f.File, "data_dir:test")
		}
		if f.Value == "AIza"+"SyCNiOUFR3_XzarP9s8h7mOJ_8pcAvhtUf0" {
			t.Errorf("Value is unmasked raw key: %q", f.Value)
		}
		if f.Value == "" {
			t.Errorf("Value is empty")
		}
	}
}

func TestScanText_EmptyHonest(t *testing.T) {
	if got := ScanText("x", ""); got != nil {
		t.Fatalf("ScanText(empty) = %v, want nil", got)
	}
}
