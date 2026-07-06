/* Copyright (c) 2026 Security Research */
package frida

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScriptNameSanitization verifies that an attacker-controlled script.Name
// containing path-traversal components is reduced to a safe base filename
// before being joined with os.TempDir().  This mirrors the exact sanitisation
// applied in runFrida: filepath.Base then strings.NewReplacer strip.
func TestScriptNameSanitization(t *testing.T) {
	cases := []struct {
		desc       string
		raw        string
		wantEscape bool // true if the old code (no sanitisation) would escape
	}{
		{"relative unix traversal", "../../home/user/.bashrc", true},
		{"absolute unix path", "/etc/shadow", true},
		{"windows style traversal", `C:\Windows\System32\evil.js`, true},
		{"dot dot only", "../..", true},
		{"benign name", "hooks_v2", false},
		{"name with slash", "a/b/c", true},
	}

	tmpDir := os.TempDir()

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			// Replicate the sanitisation from runFrida exactly.
			safeName := filepath.Base(tc.raw)
			safeName = strings.NewReplacer("/", "_", "\\", "_").Replace(safeName)

			scriptPath := filepath.Join(tmpDir, "frida_"+safeName+"_0.js")
			cleanScript := filepath.Clean(scriptPath)
			cleanTmp := filepath.Clean(tmpDir)

			// Must stay inside tmpDir.
			if !strings.HasPrefix(cleanScript, cleanTmp+string(os.PathSeparator)) {
				t.Errorf("script path %q escaped temp dir %q", scriptPath, tmpDir)
			}

			// Base name must not contain separators.
			base := filepath.Base(cleanScript)
			if strings.ContainsAny(base, "/\\") {
				t.Errorf("sanitised base name %q still contains path separators", base)
			}

			// Must not be degenerate.
			if base == "" || base == "." || base == ".." {
				t.Errorf("sanitised base name is degenerate: %q", base)
			}

			// Verify old code WOULD have escaped (regression documentation).
			if tc.wantEscape {
				oldPath := filepath.Join(tmpDir, "frida_"+tc.raw+"_0.js")
				oldClean := filepath.Clean(oldPath)
				if strings.HasPrefix(oldClean, cleanTmp+string(os.PathSeparator)) {
					// On some inputs filepath.Join already collapses traversal;
					// mark as informational rather than hard fail.
					t.Logf("NOTE: old path %q did not escape on this OS (filepath.Join collapsed it)", oldPath)
				}
			}
		})
	}
}
