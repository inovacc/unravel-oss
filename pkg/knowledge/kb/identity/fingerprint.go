/*
Copyright (c) 2026 Security Research
*/

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ErrUnknownPlatform is returned by Fingerprint when the supplied Platform
// value is not a member of the D-29-PLATFORM-SET enum.
var ErrUnknownPlatform = errors.New("unknown platform")

// FingerprintInputs is the set of analyzer-derived fields used to derive a
// stable kb_id and per-snapshot ks_id. Only Platform plus one of PackageID
// or DisplayName is required.
type FingerprintInputs struct {
	Platform    string `json:"platform"`
	PackageID   string `json:"package_id"`
	DisplayName string `json:"display_name"`
	AppVersion  string `json:"app_version"`
	CapturedAt  int64  `json:"captured_at"`
}

// platformSet enumerates the D-29-PLATFORM-SET values. New entries require
// migration-row addition only when surfaced from analyzers.
var platformSet = map[string]struct{}{
	"windows-msix": {},
	"windows-pe":   {},
	"electron":     {},
	"tauri":        {},
	"android":      {},
	"ios":          {},
	"macos":        {},
	"linux-deb":    {},
	"linux-rpm":    {},
	"linux-elf":    {},
	"web":          {},
	"other":        {},
}

// canonRE matches runs of non-alphanumerics for canonical_name slugification
// (D-29-CANONICAL-NAME). Compiled once at package init.
var canonRE = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// Fingerprint computes the stable kbID (sha256[:16] of <key>|<platform>) and
// ksID (<kb_id>:<version>:<captured_at>) for a snapshot. When PackageID is
// non-empty it is used verbatim; otherwise the canonical_name slug of
// DisplayName is the hash key. AppVersion empty becomes the literal
// "unknown".
func Fingerprint(in FingerprintInputs) (kbID, ksID string, err error) {
	if in.Platform == "" {
		return "", "", errors.New("platform is required")
	}
	if _, ok := platformSet[in.Platform]; !ok {
		return "", "", fmt.Errorf("%w: %s", ErrUnknownPlatform, in.Platform)
	}

	var key string
	switch {
	case in.PackageID != "":
		key = in.PackageID
	case in.DisplayName != "":
		key = CanonicalName(in.DisplayName)
		if key == "" {
			return "", "", errors.New("display_name yields empty canonical_name")
		}
	default:
		return "", "", errors.New("display_name required when package_id absent")
	}

	h := sha256.Sum256([]byte(key + "|" + in.Platform))
	kbID = hex.EncodeToString(h[:8])

	version := in.AppVersion
	if version == "" {
		version = "unknown"
	}
	ksID = kbID + ":" + version + ":" + strconv.FormatInt(in.CapturedAt, 10)
	return kbID, ksID, nil
}

// CanonicalName slugifies a display name per D-29-CANONICAL-NAME:
//
//	lower(regexp_replace(name, '[^a-zA-Z0-9]+', '-', 'g'))
//
// then trims leading and trailing dashes. Returns "" when the input contains
// no alphanumeric characters.
func CanonicalName(displayName string) string {
	s := canonRE.ReplaceAllString(displayName, "-")
	s = strings.ToLower(s)
	return strings.Trim(s, "-")
}

// PlatformForArtifact maps a lone artifact's filename to a platform string
// accepted by Fingerprint. It is used to synthesize a fingerprint for bare
// binaries (.dll/.jar/.wasm/.exe) that arrive without a knowledge.json
// platform field. Unrecognized extensions fall back to "other" (which is in
// platformSet), so the result is ALWAYS a valid platform.
func PlatformForArtifact(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".exe", ".dll":
		return "windows-pe"
	case ".msix", ".appx":
		return "windows-msix"
	case ".apk":
		return "android"
	case ".ipa":
		return "ios"
	case ".deb":
		return "linux-deb"
	case ".rpm":
		return "linux-rpm"
	case ".wasm":
		return "web"
	case ".so":
		return "linux-elf"
	case ".dylib", ".app":
		return "macos"
	default:
		return "other"
	}
}
