/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParsePreferences_Valid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Preferences")
	writeFile(t, p, `{"profile":{"name":"Test"},"homepage":"https://x.y","browser":{"feature":"on"}}`)
	doc, err := ParsePreferences(p)
	if err != nil {
		t.Fatalf("ParsePreferences: %v", err)
	}
	if doc.ProfileName != "Test" {
		t.Errorf("ProfileName=%q", doc.ProfileName)
	}
	if doc.Homepage != "https://x.y" {
		t.Errorf("Homepage=%q", doc.Homepage)
	}
	if doc.FeatureFlags["feature"] != "on" {
		t.Errorf("FeatureFlags=%v", doc.FeatureFlags)
	}
}

func TestParsePreferences_Malformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Preferences")
	writeFile(t, p, `{"profile":`)
	_, err := ParsePreferences(p)
	if err == nil {
		t.Fatal("expected error on truncated JSON")
	}
}

func TestParsePreferences_Missing(t *testing.T) {
	_, err := ParsePreferences(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestParsePreferences_DPAPIBlob(t *testing.T) {
	// Build a fake DPAPI blob: magic header + 16 bytes of padding.
	blob := append([]byte{0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF}, make([]byte, 16)...)
	b64 := base64.StdEncoding.EncodeToString(blob)
	payload := map[string]any{
		"profile": map[string]any{
			"name": "Demo",
		},
		"protection": map[string]any{
			"encrypted_key": b64,
			"plain":         "not-a-secret",
		},
	}
	data, _ := json.Marshal(payload)
	p := filepath.Join(t.TempDir(), "Preferences")
	writeFile(t, p, string(data))

	doc, err := ParsePreferences(p)
	if err != nil {
		t.Fatalf("ParsePreferences: %v", err)
	}
	if len(doc.EncryptedBlobs) == 0 {
		t.Fatalf("expected DPAPI blob to be flagged, got none")
	}
	var found bool
	for _, f := range doc.EncryptedBlobs {
		if f.JSONPath == "protection.encrypted_key" && f.Encrypted && f.Note != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("did not flag protection.encrypted_key: got %+v", doc.EncryptedBlobs)
	}
	// Ensure the raw blob value was NOT copied into the flag record.
	for _, f := range doc.EncryptedBlobs {
		if f.JSONPath == "" {
			t.Errorf("empty JSONPath in flag %+v", f)
		}
	}
}

func TestLooksDPAPI(t *testing.T) {
	blob := append([]byte{0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF}, make([]byte, 16)...)
	if !looksDPAPI(base64.StdEncoding.EncodeToString(blob)) {
		t.Error("should match DPAPI blob")
	}
	if looksDPAPI("hello world") {
		t.Error("plaintext should not match")
	}
	if looksDPAPI(base64.StdEncoding.EncodeToString([]byte("not-a-blob-payload-here"))) {
		t.Error("random base64 should not match")
	}
	if looksDPAPI("") {
		t.Error("empty should not match")
	}
}
