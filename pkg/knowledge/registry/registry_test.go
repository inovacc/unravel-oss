package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// findCategory returns the Category with the given name, or nil.
func findCategory(cats []Category, name string) *Category {
	for i := range cats {
		if cats[i].Category == name {
			return &cats[i]
		}
	}
	return nil
}

// findFact returns the Fact with the given key within a category, or nil.
func findFact(c *Category, key string) *Fact {
	if c == nil {
		return nil
	}
	for i := range c.Facts {
		if c.Facts[i].Key == key {
			return &c.Facts[i]
		}
	}
	return nil
}

func TestLoadOverrideSupplementsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	// Override file: overrides crypto/db_cipher and adds a NEW (category,key)
	// (crypto/new_override_fact), plus a brand-new category.
	override := `category: crypto
applies_to: [whatsapp]
facts:
  - key: db_cipher
    value_format: enum:overridden
    gap_prompt: |
      OVERRIDDEN PROMPT
  - key: new_override_fact
    value_format: string
    gap_prompt: |
      A brand-new fact added by the override.
`
	newCat := `category: telemetry
applies_to: [whatsapp]
facts:
  - key: beacon_url
    value_format: string
    gap_prompt: |
      Where does the app phone home?
`
	if err := os.WriteFile(filepath.Join(dir, "crypto_override.yaml"), []byte(override), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "telemetry.yaml"), []byte(newCat), 0o600); err != nil {
		t.Fatalf("write newCat: %v", err)
	}

	cats, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(overrideDir): %v", err)
	}

	// (a) overridden existing (category,key) → override wins.
	crypto := findCategory(cats, "crypto")
	if crypto == nil {
		t.Fatal("crypto category missing after override")
	}
	cipher := findFact(crypto, "db_cipher")
	if cipher == nil {
		t.Fatal("crypto/db_cipher missing after override")
	}
	if cipher.ValueFormat != "enum:overridden" {
		t.Errorf("db_cipher not overridden: ValueFormat=%q", cipher.ValueFormat)
	}

	// (b) NEW (category,key) within an existing category supplements it.
	if findFact(crypto, "new_override_fact") == nil {
		t.Error("crypto/new_override_fact not added by override")
	}

	// (c) untouched built-in fact unchanged.
	if findFact(crypto, "db_kdf") == nil {
		t.Error("untouched crypto/db_kdf disappeared after override")
	}

	// (d) brand-new category supplements the registry.
	tel := findCategory(cats, "telemetry")
	if tel == nil || findFact(tel, "beacon_url") == nil {
		t.Error("brand-new telemetry category not merged")
	}

	// (e) other built-in categories untouched.
	if findCategory(cats, "auth") == nil {
		t.Error("built-in auth category disappeared after override")
	}
}

func TestLoadOverrideMissingDirNoOp(t *testing.T) {
	base, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	// Non-existent dir is a clean no-op equal to embedded-only load.
	got, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Load(missing dir) returned error: %v", err)
	}
	if len(got) != len(base) {
		t.Errorf("missing override dir changed result: got %d cats, want %d", len(got), len(base))
	}
}

func TestLoadOverrideMalformedFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("category: [this is: not valid"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error for malformed override file, got nil")
	}
}

func TestLoadEmbedded(t *testing.T) {
	cats, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cats) == 0 {
		t.Fatal("Load returned no categories")
	}

	want := map[string]bool{
		"crypto":   true,
		"auth":     true,
		"protocol": true,
		"storage":  true,
	}
	got := map[string]bool{}
	for _, c := range cats {
		got[c.Category] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("expected category %q in result, got %v", name, got)
		}
	}
}

func TestLoadCategoriesSorted(t *testing.T) {
	cats, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for i := 1; i < len(cats); i++ {
		if cats[i-1].Category > cats[i].Category {
			t.Errorf("categories not sorted: %q before %q", cats[i-1].Category, cats[i].Category)
		}
	}
}

func TestLoadFactsHaveKeys(t *testing.T) {
	cats, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, c := range cats {
		if len(c.Facts) == 0 {
			t.Errorf("category %q has no facts", c.Category)
		}
		for _, f := range c.Facts {
			if f.Key == "" {
				t.Errorf("category %q has fact with empty key", c.Category)
			}
		}
	}
}

func TestMaterializeFiltersByKnownApps(t *testing.T) {
	cats, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	known := []string{"whatsapp", "teams"}
	mats := Materialize(cats, known)
	if len(mats) == 0 {
		t.Fatal("Materialize returned no rows")
	}
	allowed := map[string]bool{"whatsapp": true, "teams": true}
	for _, m := range mats {
		if !allowed[m.App] {
			t.Errorf("Materialize emitted unknown app %q", m.App)
		}
		if m.Category == "" || m.Key == "" {
			t.Errorf("Materialize emitted empty fields: %+v", m)
		}
	}
}

func TestMaterializeEmptyKnownApps(t *testing.T) {
	cats, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := Materialize(cats, nil); len(got) != 0 {
		t.Errorf("expected 0 rows for empty known-apps, got %d", len(got))
	}
}
