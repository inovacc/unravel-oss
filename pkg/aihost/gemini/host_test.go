/*
Copyright (c) 2026 Security Research
*/
package gemini

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/all"
)

// redirectHome points os.UserHomeDir at a fresh temp dir so Install writes
// stay hermetic (never touch the real ~/.gemini).
func redirectHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USERPROFILE", home) // windows
	t.Setenv("HOME", home)        // unix
	return home
}

// neutralizePATH points PATH at an empty dir so registerViaCLI's
// exec.LookPath("gemini") deterministically fails — keeping Install hermetic
// regardless of whether a real gemini CLI is on the developer's PATH.
func neutralizePATH(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

func findCheck(checks []aihost.DoctorCheck, name string) (aihost.DoctorCheck, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return aihost.DoctorCheck{}, false
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestName(t *testing.T) {
	if got := (Host{}).Name(); got != "gemini" {
		t.Fatalf("Name() = %q, want gemini", got)
	}
}

func TestInstallTarget_UnderHome(t *testing.T) {
	home := redirectHome(t)
	got, err := (Host{}).InstallTarget()
	if err != nil {
		t.Fatalf("InstallTarget: %v", err)
	}
	want := filepath.Join(home, ".gemini", "extensions", Name)
	if got != want {
		t.Fatalf("InstallTarget() = %q, want %q", got, want)
	}
}

func TestWalk_IncludesPortableLibraries(t *testing.T) {
	got := map[string]bool{}
	if err := (Host{}).Walk(func(p string, _ []byte) error { got[p] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"skills/enrich/SKILL.md",
		"skills/unravel-command-library/SKILL.md",
		"skills/unravel-agent-library/SKILL.md",
	} {
		if !got[want] {
			t.Errorf("Walk did not yield %s", want)
		}
	}
}

func TestManifestFiles_Keys(t *testing.T) {
	mf, err := (Host{}).ManifestFiles()
	if err != nil {
		t.Fatalf("ManifestFiles: %v", err)
	}
	data, ok := mf["gemini-extension.json"]
	if !ok {
		t.Fatalf("ManifestFiles missing gemini-extension.json (keys: %v)", keysOf(mf))
	}
	if !json.Valid(data) {
		t.Fatalf("gemini-extension.json is not valid JSON")
	}
}

// TestInstallRoundtrip installs into a redirected temp home (with gemini CLI
// neutralized), verifies the asset + extension manifest land, and Uninstall
// removes the target wholesale.
func TestInstallRoundtrip(t *testing.T) {
	redirectHome(t)
	neutralizePATH(t)
	h := Host{}
	target, err := h.InstallTarget()
	if err != nil {
		t.Fatalf("InstallTarget: %v", err)
	}

	n, err := h.Install(target)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if n < 2 {
		t.Fatalf("Install wrote %d files, want >= 2 (skill + extension manifest)", n)
	}
	for _, rel := range []string{
		"skills/enrich/SKILL.md",
		"gemini-extension.json",
		"GEMINI.md",
	} {
		if _, err := os.Stat(filepath.Join(target, rel)); err != nil {
			t.Errorf("expected installed file %s: %v", rel, err)
		}
	}

	if err := h.Uninstall(target); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("after Uninstall, target still present (err=%v)", err)
	}
}

// TestDoctor_MissingThenInstalled pins the verdict transition. A clean home
// fails; a freshly installed tree is DEGRADED because gemini CLI
// auto-registration is intentionally deferred (cli_register WARN), even though
// the install payload (extension manifest + GEMINI.md context file) is complete.
func TestDoctor_MissingThenInstalled(t *testing.T) {
	redirectHome(t)
	neutralizePATH(t)
	h := Host{}

	before := h.Doctor()
	if before.Verdict != "FAILED" {
		t.Fatalf("pre-install verdict = %q, want FAILED", before.Verdict)
	}

	target, _ := h.InstallTarget()
	if _, err := h.Install(target); err != nil {
		t.Fatalf("Install: %v", err)
	}

	after := h.Doctor()
	for _, name := range []string{"install_target", "extension_manifest"} {
		c, ok := findCheck(after.Checks, name)
		if !ok || c.Verdict != "PASS" {
			t.Errorf("post-install %s = %+v (ok=%v), want PASS", name, c, ok)
		}
	}
	if c, ok := findCheck(after.Checks, "context_file"); !ok || c.Verdict != "PASS" {
		t.Errorf("post-install context_file = %+v (ok=%v), want PASS", c, ok)
	}
	// cli_register stays WARN until gemini CLI auto-registration is wired — the
	// reason a fully-installed tree is DEGRADED rather than OK.
	if c, ok := findCheck(after.Checks, "cli_register"); !ok || c.Verdict != "WARN" {
		t.Errorf("post-install cli_register = %+v (ok=%v), want WARN", c, ok)
	}
	if after.Verdict != "DEGRADED" {
		t.Fatalf("post-install verdict = %q, want DEGRADED", after.Verdict)
	}
	if after.Host != "gemini" {
		t.Fatalf("report Host = %q, want gemini", after.Host)
	}
}
