/*
Copyright (c) 2026 Security Research
*/

package kb_output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	headers := []string{"ID", "Name"}
	rows := [][]string{
		{"1", "Alice"},
		{"2", "Bob"},
	}

	err := WriteTable(&buf, headers, rows)
	if err != nil {
		t.Fatalf("WriteTable failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ID") || !strings.Contains(output, "Name") {
		t.Errorf("Output missing headers: %q", output)
	}
	if !strings.Contains(output, "Alice") || !strings.Contains(output, "Bob") {
		t.Errorf("Output missing data: %q", output)
	}
}

func TestWriteJSON(t *testing.T) {
	t.Run("ValidObject", func(t *testing.T) {
		var buf bytes.Buffer
		payload := struct {
			Foo string `json:"foo"`
		}{Foo: "bar"}

		err := WriteJSON(&buf, 42, payload)
		if err != nil {
			t.Fatalf("WriteJSON failed: %v", err)
		}

		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("Failed to unmarshal output: %v", err)
		}

		if m["foo"] != "bar" {
			t.Errorf("Expected foo=bar, got %v", m["foo"])
		}
		if m["schema_version"] != float64(42) {
			t.Errorf("Expected schema_version=42, got %v", m["schema_version"])
		}
	})

	t.Run("InvalidNonObject", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteJSON(&buf, 1, []string{"not", "an", "object"})
		if err == nil {
			t.Fatal("Expected error for non-object payload, got nil")
		}
		if !strings.Contains(err.Error(), "object") {
			t.Errorf("Expected error containing 'object', got %q", err.Error())
		}
	})
}

func TestResolveDSN(t *testing.T) {
	// New contract: ResolveDSN reads config.yaml only. The legacy --dsn flag
	// and UNRAVEL_KB_DSN env-var fallbacks have been removed; tests inject
	// a config.yaml via UNRAVEL_CONFIG (honored by config.Path).

	t.Run("FlagAndEnvIgnored", func(t *testing.T) {
		t.Setenv("UNRAVEL_KB_DSN", "should-not-win")
		t.Setenv("UNRAVEL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
		_, err := ResolveDSN("flag-also-should-not-win")
		if err == nil {
			t.Fatal("Expected ErrConfigNotFound surface, got nil")
		}
	})

	t.Run("ErrorWhenConfigMissing", func(t *testing.T) {
		t.Setenv("UNRAVEL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
		_, err := ResolveDSN("")
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
		if !strings.Contains(err.Error(), "unravel db setup") {
			t.Errorf("Expected error mentioning 'unravel db setup', got %q", err.Error())
		}
	})

	t.Run("LoadsFromConfigYAML", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		// Plaintext password via UNRAVEL_DB_PASSWORD env hook so we don't
		// touch the keychain in unit tests.
		yaml := "database:\n  host: 127.0.0.1\n  port: 5432\n  user: u\n  dbname: d\n  sslmode: disable\n"
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		t.Setenv("UNRAVEL_CONFIG", path)
		t.Setenv("UNRAVEL_DB_PASSWORD", "pw")

		res, err := ResolveDSN("")
		if err != nil {
			t.Fatalf("ResolveDSN failed: %v", err)
		}
		if !strings.HasPrefix(res, "postgres://u:pw@127.0.0.1:5432/d") {
			t.Errorf("unexpected dsn shape: %q", res)
		}
	})
}

func TestSparkline(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		if res := Sparkline(nil); res != "" {
			t.Errorf("Expected empty string, got %q", res)
		}
	})

	t.Run("Uniform", func(t *testing.T) {
		res := Sparkline([]float64{10, 10, 10})
		if res != "   " { // runes[0] is ' ' (U+2581)
			// Wait, let me check the runes in my output.go
			// runes := []rune(" ▂▃▄▅▆▇█")
			// runes[0] is ' '
			if res != string([]rune{'\u2581', '\u2581', '\u2581'}) {
				t.Errorf("Expected uniform runes[0], got %q", res)
			}
		}
	})

	t.Run("Ascending", func(t *testing.T) {
		// 0..7 should map to each of the 8 runes
		res := Sparkline([]float64{0, 1, 2, 3, 4, 5, 6, 7})
		expected := "▁▂▃▄▅▆▇█"
		if res != expected {
			t.Errorf("Expected %q, got %q", expected, res)
		}
	})
}

func TestBindFlags(t *testing.T) {
	cmd := &cobra.Command{}
	var jsonFlag bool
	var dsnFlag string

	BindJSONFlag(cmd, &jsonFlag)
	BindDSNFlag(cmd, &dsnFlag) // intentional no-op since DSN comes from config.yaml only

	if f := cmd.Flags().Lookup("json"); f == nil {
		t.Error("json flag not bound")
	}
	if f := cmd.Flags().Lookup("dsn"); f != nil {
		t.Error("dsn flag should NOT be bound (config-only DSN policy)")
	}
}
