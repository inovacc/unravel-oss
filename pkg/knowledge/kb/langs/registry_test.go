package langs

import (
	"testing"
)

// TestLookupReturnsRegisteredExtractor exercises Register / Lookup for
// the ".go" extension that go_lang.go's init() seeds. Other tests in
// this package depend on this baseline working.
func TestLookupReturnsRegisteredExtractor(t *testing.T) {
	fn, lang, ok := Lookup(".go")
	if !ok {
		t.Fatal("expected .go extractor to be registered")
	}
	if lang != "go" {
		t.Errorf("lang = %q, want %q", lang, "go")
	}
	if fn == nil {
		t.Fatal("Lookup returned nil ExtractFn")
	}
}

func TestLookupNormalisesLeadingDot(t *testing.T) {
	if _, _, ok := Lookup("go"); !ok {
		t.Error("expected lookup without leading dot to succeed")
	}
}

func TestLookupCaseInsensitive(t *testing.T) {
	if _, _, ok := Lookup(".GO"); !ok {
		t.Error("expected .GO to be matched case-insensitively")
	}
}

func TestLookupUnknownExtension(t *testing.T) {
	if _, _, ok := Lookup(".this-extension-does-not-exist"); ok {
		t.Error("expected unknown extension to return ok=false")
	}
}

func TestRegisterIgnoresEmptyExt(t *testing.T) {
	// Register("",...) must be a no-op so we don't poison the map.
	Register("", "noop", func(path string, body []byte) (Module, error) {
		return Module{}, nil
	})
	if _, _, ok := Lookup(""); ok {
		t.Error("Register with empty ext leaked into the registry")
	}
}

func TestRegisterIgnoresNilFn(t *testing.T) {
	Register(".bogus", "bogus", nil)
	if _, _, ok := Lookup(".bogus"); ok {
		t.Error("Register with nil fn leaked into the registry")
	}
}

func TestDefaultExtractorBasics(t *testing.T) {
	body := []byte("hello world")
	m, err := DefaultExtractor("/tmp/foo.txt", body)
	if err != nil {
		t.Fatalf("DefaultExtractor: %v", err)
	}
	if m.Name != "foo.txt" {
		t.Errorf("Name = %q, want foo.txt", m.Name)
	}
	if m.Lang != "" {
		t.Errorf("DefaultExtractor must leave Lang empty, got %q", m.Lang)
	}
	if m.Size != len(body) {
		t.Errorf("Size = %d, want %d", m.Size, len(body))
	}
	if len(m.BodySHA256) != 64 {
		t.Errorf("BodySHA256 should be 64 hex chars, got %d", len(m.BodySHA256))
	}
}

func TestRegisteredIncludesGo(t *testing.T) {
	got := Registered()
	if got[".go"] != "go" {
		t.Errorf("Registered() missing .go=>go entry; got %v", got)
	}
}
