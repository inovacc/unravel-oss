/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// derivePlatform infers the target platform from a Seam (D-06 fallback rules):
//   - inject.FrameworkMacOS         -> "macos"
//   - PtraceEligibleBinary non-nil  -> "linux"
//   - len(PtraceFlags) > 0          -> "linux"
//   - else                          -> "windows"
//
// The function is total; "unknown" never returns an error today, but the
// signature reserves the option for future stricter modes.
func derivePlatform(s inject.Seam) (string, error) {
	if s.Framework == inject.FrameworkMacOS {
		return "macos", nil
	}
	if s.PtraceEligibleBinary != nil || len(s.PtraceFlags) > 0 {
		return "linux", nil
	}
	return "windows", nil
}

// extractTargetPathTag pulls the target path and dynamic tag from a Seam.
// Path comes from the first Evidence entry (or empty string); tag is the
// seam Kind. Both feed seamID per D-13.
func extractTargetPathTag(s inject.Seam) (path, tag string) {
	if len(s.Evidence) > 0 {
		path = s.Evidence[0].Path
	}
	tag = s.Kind
	return
}

// seamID returns the first 8 hex chars of SHA256("platform\ntargetPath\ntag").
// Stable across runs given identical inputs (D-12, D-14).
func seamID(platform, targetPath, tag string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\n%s\n%s", platform, targetPath, tag))
	return hex.EncodeToString(sum[:])[:8]
}
