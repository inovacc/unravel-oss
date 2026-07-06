package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreSeeded(t *testing.T) {
	c := Default()
	if c.Database.Host == "" || c.Database.Port == 0 ||
		c.Database.User == "" || c.Database.DBName == "" || c.Database.SSLMode == "" {
		t.Fatalf("Default() missing fields: %+v", c)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := Default()
	cfg.Database.Host = "10.0.0.5"
	cfg.Database.Port = 5433
	cfg.Database.PasswordEnc = "AAAA" // dummy base64 (not real ciphertext — not exercised here)

	if err := SaveTo(cfg, path); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Database.Host != "10.0.0.5" || loaded.Database.Port != 5433 {
		t.Fatalf("round-trip mismatch: %+v", loaded.Database)
	}
	if loaded.Database.PasswordEnc != "AAAA" {
		t.Fatalf("password_enc lost: %q", loaded.Database.PasswordEnc)
	}
}

func TestApplyDefaultsFillsBlankFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Minimal yaml with only host set — load should fill the rest.
	if err := os.WriteFile(path, []byte("database:\n  host: 1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Port != DefaultPort {
		t.Fatalf("port not defaulted: %d", cfg.Database.Port)
	}
	if cfg.Database.User != DefaultUser {
		t.Fatalf("user not defaulted: %q", cfg.Database.User)
	}
}

func TestLoadFromMissingReturnsErrConfigNotFound(t *testing.T) {
	_, err := LoadFrom(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil || !strings.Contains(err.Error(), "config.yaml not found") {
		t.Fatalf("want ErrConfigNotFound, got %v", err)
	}
}

func TestPasswordEnvOverride(t *testing.T) {
	t.Setenv("UNRAVEL_DB_PASSWORD", "from-env")
	cfg := Default()
	// PasswordEnc empty + env var set → returns env value without
	// touching the keychain.
	pw, err := cfg.Password()
	if err != nil {
		t.Fatalf("password: %v", err)
	}
	if pw != "from-env" {
		t.Fatalf("got %q want from-env", pw)
	}
}

func TestDSNContainsCredentials(t *testing.T) {
	t.Setenv("UNRAVEL_DB_PASSWORD", "p@ss/word")
	cfg := Default()
	dsn, err := cfg.DSN(nil) //nolint:staticcheck // ctx unused per signature
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	// Password must be URL-encoded in the userinfo segment.
	if !strings.Contains(dsn, "p%40ss%2Fword") {
		t.Fatalf("password not URL-escaped in dsn: %s", dsn)
	}
	if !strings.HasPrefix(dsn, "postgres://") {
		t.Fatalf("dsn scheme: %s", dsn)
	}
}

func TestRedactedNoSecret(t *testing.T) {
	t.Setenv("UNRAVEL_DB_PASSWORD", "topsecret")
	cfg := Default()
	red := cfg.Redacted()
	if strings.Contains(red, "topsecret") {
		t.Fatalf("redacted DSN leaked password: %s", red)
	}
	if !strings.Contains(red, "REDACTED") {
		t.Fatalf("expected REDACTED token: %s", red)
	}
}
