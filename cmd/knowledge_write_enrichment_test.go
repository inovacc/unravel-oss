/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadParsedJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e.json")
	if err := os.WriteFile(p, []byte(`{"summary":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("inline", func(t *testing.T) {
		b, err := loadParsedJSON("", `{"summary":"x"}`)
		if err != nil || string(b) != `{"summary":"x"}` {
			t.Fatalf("got %q err %v", b, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		b, err := loadParsedJSON(p, "")
		if err != nil || string(b) != `{"summary":"y"}` {
			t.Fatalf("got %q err %v", b, err)
		}
	})
	t.Run("both is error", func(t *testing.T) {
		if _, err := loadParsedJSON(p, `{}`); err == nil {
			t.Fatal("expected error when both provided")
		}
	})
	t.Run("neither is error", func(t *testing.T) {
		if _, err := loadParsedJSON("", ""); err == nil {
			t.Fatal("expected error when neither provided")
		}
	})
	t.Run("missing file is error", func(t *testing.T) {
		if _, err := loadParsedJSON(filepath.Join(dir, "nope.json"), ""); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}
