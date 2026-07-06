/*
Copyright (c) 2026 Security Research
*/

// Package visual orchestrates Phase 8 visual capture (screenshots, DOM trees,
// layout snapshots) for Electron, Tauri, and WebView2 targets. The orchestrator
// is mode-driven (auto | interactive | scripted) and writes every artifact via
// knowledge.WriteFileAtomic for crash-safety. The single curated symlink
// (<kb>/visual/latest) is created by WriteLatestPointer; all other writes
// reject symlinks per D-19.
package visual

import (
	"bytes"
	"fmt"
	"image/png"

	"github.com/kbinani/screenshot"
)

// CaptureScreen captures display index `display` (0 = primary) as PNG bytes.
// Returns the encoded PNG and the captured pixel size (W, H).
// Pure entry point — content-protection probe is the caller's responsibility
// (see ContentProtected in screenshot_windows.go / screenshot_unix.go).
func CaptureScreen(display int) ([]byte, int, int, error) {
	n := screenshot.NumActiveDisplays()
	if display < 0 || display >= n {
		return nil, 0, 0, fmt.Errorf("display index %d out of range (have %d)", display, n)
	}
	bounds := screenshot.GetDisplayBounds(display)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("capture display %d: %w", display, err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, 0, 0, fmt.Errorf("png encode: %w", err)
	}
	return buf.Bytes(), bounds.Dx(), bounds.Dy(), nil
}

// NumActiveDisplays returns the count of currently attached displays. Used by
// tests to gate on headless CI.
func NumActiveDisplays() int { return screenshot.NumActiveDisplays() }
