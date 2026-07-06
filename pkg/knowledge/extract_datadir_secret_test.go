package knowledge

import (
	"strings"
	"testing"
)

func TestScanDataDirSecrets_SurfacesLocalStorageKey(t *testing.T) {
	dd := &DataDirKnowledge{
		LocalStorage: &LocalStorageData{
			Origins: []StorageOrigin{
				{
					Origin: "https://x",
					Entries: []StorageEntry{
						// AIza... matches secret.TypeGoogleAPIKey (high confidence).
						{Key: "gemini_api_key", Value: "AIza" + "SyCNiOUFR3_XzarP9s8h7mOJ_8pcAvhtUf0"},
					},
				},
			},
		},
	}

	scanDataDirSecrets(dd)

	if len(dd.SecretFindings) < 1 {
		t.Fatalf("expected >=1 SecretFinding, got %d", len(dd.SecretFindings))
	}

	const rawKey = "AIza" + "SyCNiOUFR3_XzarP9s8h7mOJ_8pcAvhtUf0"
	var found bool
	for _, f := range dd.SecretFindings {
		if !strings.Contains(strings.ToLower(f.Type), "google") {
			continue
		}
		found = true
		if f.MaskedValue == "" {
			t.Fatalf("Google API key finding: MaskedValue empty, want masked value")
		}
		if !strings.Contains(f.MaskedValue, "***") {
			t.Fatalf("MaskedValue %q not masked (no ***)", f.MaskedValue)
		}
		if strings.Contains(f.MaskedValue, rawKey) || f.MaskedValue == rawKey {
			t.Fatalf("MaskedValue leaks raw secret: %q", f.MaskedValue)
		}
		if strings.Contains(rawKey, f.MaskedValue) {
			t.Fatalf("MaskedValue %q is a raw substring of the secret", f.MaskedValue)
		}
	}
	if !found {
		t.Fatalf("no Google API key SecretFinding among %d findings", len(dd.SecretFindings))
	}
}

func TestScanDataDirSecrets_NilSafe(t *testing.T) {
	scanDataDirSecrets(nil) // must not panic

	dd := &DataDirKnowledge{}
	scanDataDirSecrets(dd)
	if dd.SecretFindings != nil {
		t.Fatalf("empty dd: SecretFindings = %v, want nil", dd.SecretFindings)
	}
}
