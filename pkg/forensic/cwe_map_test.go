/*
Copyright (c) 2026 Security Research
*/
package forensic

import "testing"

func TestCWEFor(t *testing.T) {
	tests := []struct {
		findingType string
		wantCWE     int
		wantOK      bool
	}{
		{"csp_relaxation", 693, true},
		{"eval_or_unsafe_inline", 95, true},
		{"hardcoded_credential", 798, true},
		{"dangerous_permission", 250, true},
		{"content_protection", 732, true},
		{"sandbox_removed", 693, true},
		// Generic Android forensic categories (RPT-03 coverage on real teardowns)
		{"permissions", 250, true},
		{"attack_surface", 749, true},
		{"network", 319, true},
		{"secrets", 798, true},
		{"crypto", 327, true},
		{"tls", 295, true},
		{"webview", 749, true},
		{"intent", 927, true},
		{"ipc", 927, true},
		{"storage", 922, true},
		{"logging", 532, true},
		{"signing", 347, true},
		{"signature", 347, true},
		{"obfuscation", 693, true},
		{"debug", 489, true},
		{"debuggable", 489, true},
		{"backup", 200, true},
		{"telemetry", 359, true},
		{"stealth", 732, true},
		{"screen_capture", 732, true},
		{"nonexistent", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.findingType, func(t *testing.T) {
			gotCWE, gotOK := CWEFor(tt.findingType)
			if gotCWE != tt.wantCWE || gotOK != tt.wantOK {
				t.Errorf("CWEFor(%q) = (%d,%v); want (%d,%v)",
					tt.findingType, gotCWE, gotOK, tt.wantCWE, tt.wantOK)
			}
		})
	}
}

func TestCWELink(t *testing.T) {
	want := "https://cwe.mitre.org/data/definitions/693.html"
	if got := CWELink(693); got != want {
		t.Errorf("CWELink(693) = %q; want %q", got, want)
	}
	want798 := "https://cwe.mitre.org/data/definitions/798.html"
	if got := CWELink(798); got != want798 {
		t.Errorf("CWELink(798) = %q; want %q", got, want798)
	}
}

// TestRegisterCWE_AddNew verifies that RegisterCWE adds a brand-new entry
// not present in the init seed and that subsequent CWEFor / CWEDescription
// lookups see it.
func TestRegisterCWE_AddNew(t *testing.T) {
	const id = "CWE-9999"
	const desc = "Synthetic Test Weakness"

	if _, ok := CWEFor(id); ok {
		t.Fatalf("seed already contains %s", id)
	}
	RegisterCWE(id, desc)

	cwe, ok := CWEFor(id)
	if !ok {
		t.Fatalf("CWEFor(%q) not found after RegisterCWE", id)
	}
	if cwe != 9999 {
		t.Errorf("CWEFor(%q) cwe = %d; want 9999", id, cwe)
	}
	got, ok := CWEDescription(id)
	if !ok {
		t.Fatalf("CWEDescription(%q) not found after RegisterCWE", id)
	}
	if got != desc {
		t.Errorf("CWEDescription(%q) = %q; want %q", id, got, desc)
	}

	// Idempotent: a second identical call must not panic, must not duplicate.
	RegisterCWE(id, desc)
	if got, _ := CWEDescription(id); got != desc {
		t.Errorf("after idempotent re-register, description = %q; want %q", got, desc)
	}
}

// TestRegisterCWE_DoesNotOverwriteSeed verifies that calling RegisterCWE on
// an existing key with an empty description leaves the seed text intact.
func TestRegisterCWE_DoesNotOverwriteSeed(t *testing.T) {
	// "secrets" is seeded with description "Use of Hard-coded Credentials".
	original, ok := CWEDescription("secrets")
	if !ok || original == "" {
		t.Fatalf("seed entry secrets missing or empty")
	}

	// Call RegisterCWE with an empty description — must NOT clobber the seed.
	RegisterCWE("secrets", "")

	got, _ := CWEDescription("secrets")
	if got != original {
		t.Errorf("seed description overwritten: got %q; want %q", got, original)
	}

	// Numeric id must also be preserved.
	cwe, _ := CWEFor("secrets")
	if cwe != 798 {
		t.Errorf("seed cwe overwritten: got %d; want 798", cwe)
	}
}
