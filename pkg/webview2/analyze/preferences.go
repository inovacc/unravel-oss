/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// dpapiMagic is the DPAPI BLOB magic header used to identify opaque encrypted
// values inside Preferences JSON. Per Microsoft docs, DPAPI v2 blobs begin
// with 0x01 0x00 0x00 0x00 followed by the provider GUID; Chromium wraps its
// secrets in a buffer that starts with this prefix (D-14).
var dpapiMagic = []byte{0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF}

// maxPrefsDepth caps DPAPI-blob scan recursion depth (T-03-08, V5 ASVS).
const maxPrefsDepth = 20

// PreferencesDoc is the structured view of a Chromium Preferences / Secure
// Preferences JSON file (D-08). Callers use EncryptedBlobs to locate
// DPAPI-wrapped values without touching the encrypted bytes (D-14).
type PreferencesDoc struct {
	// ProfileName mirrors profile.name when present.
	ProfileName string `json:"profile_name,omitempty"`
	// Homepage mirrors homepage when present.
	Homepage string `json:"homepage,omitempty"`
	// PermissionGrants is the raw profile.content_settings subtree (loose).
	PermissionGrants map[string]any `json:"permission_grants,omitempty"`
	// FeatureFlags is the raw browser or feature subtree if present.
	FeatureFlags map[string]any `json:"feature_flags,omitempty"`
	// EncryptedBlobs records JSON paths that look like DPAPI-wrapped values.
	EncryptedBlobs []EncryptedField `json:"encrypted_blobs,omitempty"`
	// Raw is the fully decoded Preferences tree.
	Raw map[string]any `json:"-"`
}

// EncryptedField marks a JSON path inside a Preferences document whose value
// looks like a DPAPI-wrapped blob. Encrypted is always true; the field exists
// as a stable contract for consumers (D-14). No decryption is attempted.
type EncryptedField struct {
	JSONPath  string `json:"json_path"`
	Encrypted bool   `json:"encrypted"`
	Note      string `json:"note"`
}

// ParsePreferences decodes a Chromium Preferences JSON file and flags values
// that look DPAPI-wrapped. Malformed input returns an error — never panics
// (T-03-08).
func ParsePreferences(path string) (doc *PreferencesDoc, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parse preferences: panic: %v", r)
			doc = nil
		}
	}()
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open preferences: %w", err)
	}
	defer func() { _ = f.Close() }()

	var raw map[string]any
	dec := json.NewDecoder(f)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode preferences: %w", err)
	}

	doc = &PreferencesDoc{Raw: raw}
	// profile.name, homepage
	if profile, ok := raw["profile"].(map[string]any); ok {
		if name, ok := profile["name"].(string); ok {
			doc.ProfileName = name
		}
		if cs, ok := profile["content_settings"].(map[string]any); ok {
			doc.PermissionGrants = cs
		}
	}
	if hp, ok := raw["homepage"].(string); ok {
		doc.Homepage = hp
	}
	if browser, ok := raw["browser"].(map[string]any); ok {
		doc.FeatureFlags = browser
	}

	doc.EncryptedBlobs = scanDPAPIBlobs(raw, "", 0)
	return doc, nil
}

// scanDPAPIBlobs walks a JSON-decoded value up to maxPrefsDepth levels deep
// looking for string values that base64-decode to something starting with the
// DPAPI magic bytes. Records paths without copying the encrypted bytes.
func scanDPAPIBlobs(v any, path string, depth int) []EncryptedField {
	if depth > maxPrefsDepth {
		return nil
	}
	var out []EncryptedField
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			out = append(out, scanDPAPIBlobs(child, childPath, depth+1)...)
		}
	case []any:
		for i, child := range val {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			out = append(out, scanDPAPIBlobs(child, childPath, depth+1)...)
		}
	case string:
		if looksDPAPI(val) {
			out = append(out, EncryptedField{
				JSONPath:  path,
				Encrypted: true,
				Note:      "DPAPI-wrapped; use 'unravel dpapi' to decrypt",
			})
		}
	}
	return out
}

// looksDPAPI returns true when s base64-decodes to something that begins with
// the DPAPI magic header.
func looksDPAPI(s string) bool {
	if len(s) < 16 {
		return false
	}
	// Chromium stores blobs as standard base64. Quick reject on obvious non-base64.
	if strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return false
		}
	}
	if len(decoded) < len(dpapiMagic) {
		return false
	}
	for i, b := range dpapiMagic {
		if decoded[i] != b {
			return false
		}
	}
	return true
}
