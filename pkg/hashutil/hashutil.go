// Package hashutil provides shared sha256 hex helpers used across the unravel
// codebase for content addressing, identity derivation, and short fingerprints.
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashHex returns the lowercase hex sha256 digest of data (64 chars).
func HashHex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// HashHex8 returns the first 8 hex chars (4 bytes) of the sha256 digest of data.
// Common for short content fingerprints in cache keys + filenames.
func HashHex8(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:4])
}

// HashHex16 returns the first 16 hex chars (8 bytes) of the sha256 digest.
// Used by knowledge/kb identity derivation (kb_id) and frida seam IDs.
func HashHex16(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8])
}

// HashHexString is a convenience that hashes a string input.
func HashHexString(s string) string {
	return HashHex([]byte(s))
}

// HashHex16String is a convenience truncating sha256(string) to 16 hex chars.
func HashHex16String(s string) string {
	return HashHex16([]byte(s))
}
