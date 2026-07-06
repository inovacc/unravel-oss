/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// winuiElementAllowlist contains element / control / brush / type names that
// are expected to appear in any non-trivial WinUI XAML XBF. The fixtures are
// derived from WhatsApp Desktop 2.2615.x; any decode is considered successful
// if it surfaces at least 5 of these literals.
var winuiElementAllowlist = []string{
	"Grid", "Button", "TextBlock", "StackPanel", "Border", "Path", "Style",
	"Setter", "ResourceDictionary", "FontFamily", "Brush", "Page", "UserControl",
	"ContentControl", "ContentPresenter", "VisualState", "VisualStateGroup",
	"DataTemplate", "ControlTemplate", "Color", "SolidColorBrush", "Image",
	"ImageBrush", "Ellipse", "Rectangle", "Line", "Source",
}

// countAllowlistedStrings reports how many pool entries match (substring,
// case-sensitive) any name in the allowlist. Each pool entry counts at most
// once — duplicates inside the pool inflate the count, which is fine: the
// guard is that the decoder surfaced at least N recognizable XAML literals.
func countAllowlistedStrings(pool []string) int {
	n := 0
	for _, s := range pool {
		for _, name := range winuiElementAllowlist {
			if strings.Contains(s, name) {
				n++
				break
			}
		}
	}
	return n
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", "xbf21", name)
	// xbf package lives under pkg/winui/xaml/xbf, fixtures under
	// pkg/winui/xaml/testdata/xbf21 — climb one directory.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func runFixtureDecode(t *testing.T, fixture string, minHits int, mustContain []string, deadline time.Duration) {
	t.Helper()
	data := loadFixture(t, fixture)
	if !IsWAS16XBF(data) {
		t.Fatalf("fixture %s: expected IsWAS16XBF=true", fixture)
	}
	done := make(chan struct{})
	var dec *DecodedXAML
	var err error
	go func() {
		dec, err = DecodeXBFBytes(data)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(deadline):
		t.Fatalf("fixture %s: decode timed out after %s", fixture, deadline)
	}
	if err != nil {
		t.Fatalf("fixture %s: DecodeXBFBytes error: %v", fixture, err)
	}
	if dec == nil {
		t.Fatalf("fixture %s: nil decode", fixture)
	}
	for _, w := range dec.Warnings {
		if strings.Contains(w, "string table truncated") {
			t.Errorf("fixture %s: forbidden warning: %q", fixture, w)
		}
		if strings.Contains(w, "assemblies table truncated") {
			t.Errorf("fixture %s: forbidden warning: %q", fixture, w)
		}
	}
	if dec.Version != "2.1" {
		t.Errorf("fixture %s: want version 2.1 got %q", fixture, dec.Version)
	}
	// Re-decode strings via the v21 helper so we can assert against the pool
	// directly (Recovered carries them as XML <s>...</s> nodes).
	res, derr := DecodeWAS16V21(data)
	if derr != nil {
		t.Fatalf("fixture %s: DecodeWAS16V21 error: %v", fixture, derr)
	}
	hits := countAllowlistedStrings(res.Strings)
	if hits < minHits {
		t.Errorf("fixture %s: only %d/%d allowlisted WinUI tokens recovered. pool sample=%v",
			fixture, hits, minHits, sample(res.Strings, 20))
	}
	for _, want := range mustContain {
		found := false
		for _, s := range res.Strings {
			if strings.Contains(s, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fixture %s: expected pool to contain %q (case-sensitive substring); got sample=%v",
				fixture, want, sample(res.Strings, 20))
		}
	}
	// Recovered text must be non-empty and well-formed-ish.
	if !strings.Contains(dec.Recovered, "<XBFStringPool>") {
		t.Errorf("fixture %s: Recovered missing <XBFStringPool>; got %q", fixture, truncRec(dec.Recovered, 80))
	}
}

func sample(pool []string, n int) []string {
	if len(pool) <= n {
		return pool
	}
	return pool[:n]
}

func truncRec(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func TestXBF21_Small_Decodes(t *testing.T) {
	// small.xbf is WhatsApp's AvatarView (5 strings total: 2 URIs +
	// Placeholder, Ellipse, ImageBrush). Two strings match the allowlist
	// directly (Ellipse, ImageBrush); Placeholder is asserted via
	// mustContain so we still validate it round-trips.
	runFixtureDecode(t, "small.xbf",
		2,
		[]string{"Ellipse", "ImageBrush", "Placeholder"},
		2*time.Second)
}

func TestXBF21_Medium_Decodes(t *testing.T) {
	runFixtureDecode(t, "medium.xbf",
		5,
		[]string{"WhatsApp", "FontFamily", "Source"},
		2*time.Second)
}

func TestXBF21_Large_Decodes(t *testing.T) {
	runFixtureDecode(t, "large.xbf",
		8,
		[]string{"Brush", "Color"},
		5*time.Second)
}

func TestXBF21_Truncated_EmitsRawFallback(t *testing.T) {
	full := loadFixture(t, "small.xbf")
	if len(full) < 32 {
		t.Skip("small.xbf shorter than 32 bytes — fixture corrupted")
	}
	truncated := append([]byte{}, full[:32]...)
	entry := DecodeXBFForEntry(truncated, "synthetic://truncated")
	if entry.Kind != "xbf-raw" {
		t.Fatalf("want kind=xbf-raw on 32-byte truncation, got %q", entry.Kind)
	}
	if entry.RawBytesHex == "" {
		t.Fatalf("want non-empty RawBytesHex on truncation")
	}
	if len(entry.Errors) == 0 {
		t.Fatalf("want at least one error on truncation")
	}
	if !strings.HasPrefix(entry.RawBytesHex, "5842") {
		t.Errorf("RawBytesHex should start with magic 5842; got %q", entry.RawBytesHex[:8])
	}
}

func TestXBF21_FullFixture_Successful_Entry(t *testing.T) {
	full := loadFixture(t, "small.xbf")
	entry := DecodeXBFForEntry(full, "fixtures://small.xbf")
	if entry.Kind != "xbf" {
		t.Fatalf("want kind=xbf on valid fixture, got %q", entry.Kind)
	}
	if entry.Recovered == "" {
		t.Fatalf("want non-empty Recovered on valid fixture")
	}
	for _, e := range entry.Errors {
		if strings.Contains(e, "truncated") {
			t.Errorf("unexpected truncation error: %q", e)
		}
	}
}

// Phase 20 (XBF-V3-01) tests — detect-only forward-compat for v3.

func TestXBFv3_DetectsMajor3(t *testing.T) {
	data, err := os.ReadFile("testdata/v3_minimal.xbf")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !IsXBFv3(data) {
		t.Fatalf("IsXBFv3 should return true for v3_minimal")
	}
	entry := DecodeXBFForEntry(data, "testdata/v3_minimal.xbf")
	if entry.Kind != "xbf-raw" {
		t.Errorf("kind = %q; want xbf-raw", entry.Kind)
	}
	if entry.VersionHint != "3.0" {
		t.Errorf("version_hint = %q; want 3.0", entry.VersionHint)
	}
	if entry.RawBytesHex == "" {
		t.Errorf("raw_bytes_hex should be populated")
	}
}

func TestXBFv3_DetectsMajorMinor(t *testing.T) {
	data, err := os.ReadFile("testdata/v3_with_minor.xbf")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	entry := DecodeXBFForEntry(data, "testdata/v3_with_minor.xbf")
	if entry.VersionHint != "3.5" {
		t.Errorf("version_hint = %q; want 3.5", entry.VersionHint)
	}
}

func TestXBFv3_DoesNotPanicOnTruncated(t *testing.T) {
	data, err := os.ReadFile("testdata/v3_truncated.xbf")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on truncated v3: %v", r)
		}
	}()
	entry := DecodeXBFForEntry(data, "testdata/v3_truncated.xbf")
	if entry.Kind != "xbf-raw" {
		t.Errorf("kind = %q; want xbf-raw", entry.Kind)
	}
	if entry.VersionHint != "3.0" {
		t.Errorf("version_hint = %q; want 3.0 (12 bytes covers minor)", entry.VersionHint)
	}
}
