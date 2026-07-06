//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package detect

import "github.com/inovacc/unravel-oss/pkg/webview2"

// DetectEvergreenRuntime on non-Windows is a graceful fallthrough returning
// Mode="unknown" (research D-03: registry is Windows-specific).
func DetectEvergreenRuntime() (webview2.RuntimeInfo, error) {
	return webview2.RuntimeInfo{Mode: "unknown"}, nil
}
