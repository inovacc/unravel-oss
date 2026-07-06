/*
Copyright (c) 2026 Security Research
*/
package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/all"
)

// redirectHome points os.UserHomeDir at a fresh temp dir so Install and
// PatchMarketplace writes stay hermetic (never touch the real ~/.codex or
// ~/.agents). Mirrors the pattern in pkg/aihost/claude/install_test.go.
func redirectHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USERPROFILE", home) // windows
	t.Setenv("HOME", home)        // unix
	return home
}

func findCheck(checks []aihost.DoctorCheck, name string) (aihost.DoctorCheck, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return aihost.DoctorCheck{}, false
}

func TestName(t *testing.T) {
	if got := (Host{}).Name(); got != "codex" {
		t.Fatalf("Name() = %q, want codex", got)
	}
}

func TestInstallTarget_UnderHome(t *testing.T) {
	home := redirectHome(t)
	got, err := (Host{}).InstallTarget()
	if err != nil {
		t.Fatalf("InstallTarget: %v", err)
	}
	want := filepath.Join(home, ".codex", "plugins", Name)
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
	for _, key := range []string{".codex-plugin/plugin.json", ".mcp.json"} {
		data, ok := mf[key]
		if !ok {
			t.Fatalf("ManifestFiles missing key %q", key)
		}
		if !json.Valid(data) {
			t.Fatalf("ManifestFiles[%q] is not valid JSON", key)
		}
	}
}

// TestInstallRoundtrip installs into a redirected temp home, verifies the
// asset + manifest files land, the marketplace.json entry is patched in, and
// Uninstall removes the target wholesale.
func TestInstallRoundtrip(t *testing.T) {
	home := redirectHome(t)
	h := Host{}
	target, err := h.InstallTarget()
	if err != nil {
		t.Fatalf("InstallTarget: %v", err)
	}

	n, err := h.Install(target)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if n < 3 {
		t.Fatalf("Install wrote %d files, want >= 3 (skill + 2 manifests)", n)
	}
	for _, rel := range []string{
		"skills/enrich/SKILL.md",
		".codex-plugin/plugin.json",
		".mcp.json",
	} {
		if _, err := os.Stat(filepath.Join(target, rel)); err != nil {
			t.Errorf("expected installed file %s: %v", rel, err)
		}
	}

	// PatchMarketplace writes ~/.agents/plugins/marketplace.json with our entry.
	mpPath := filepath.Join(home, ".agents", "plugins", "marketplace.json")
	raw, err := os.ReadFile(mpPath)
	if err != nil {
		t.Fatalf("marketplace.json not written: %v", err)
	}
	var doc struct {
		Plugins []struct {
			Name string `json:"name"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("marketplace.json invalid: %v", err)
	}
	found := false
	for _, p := range doc.Plugins {
		if p.Name == Name {
			found = true
		}
	}
	if !found {
		t.Fatalf("marketplace.json has no %q plugin entry", Name)
	}

	if err := h.Uninstall(target); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("after Uninstall, target still present (err=%v)", err)
	}
}

// TestDoctor_MissingThenInstalled pins the verdict transition: a clean home
// fails (no install target), and a freshly installed tree is DEGRADED because
// codex CLI marketplace auto-registration is intentionally not wired yet.
func TestDoctor_MissingThenInstalled(t *testing.T) {
	redirectHome(t)
	h := Host{}

	before := h.Doctor()
	if before.Verdict != "FAILED" {
		t.Fatalf("pre-install verdict = %q, want FAILED", before.Verdict)
	}
	if c, ok := findCheck(before.Checks, "install_target"); !ok || c.Verdict != "FAIL" {
		t.Fatalf("pre-install install_target = %+v (ok=%v), want FAIL", c, ok)
	}

	target, _ := h.InstallTarget()
	if _, err := h.Install(target); err != nil {
		t.Fatalf("Install: %v", err)
	}

	after := h.Doctor()
	for _, name := range []string{"install_target", "plugin_manifest", "mcp_manifest"} {
		c, ok := findCheck(after.Checks, name)
		if !ok || c.Verdict != "PASS" {
			t.Errorf("post-install %s = %+v (ok=%v), want PASS", name, c, ok)
		}
	}
	if c, ok := findCheck(after.Checks, "marketplace_register"); !ok || c.Verdict != "WARN" {
		t.Errorf("post-install marketplace_register = %+v (ok=%v), want WARN", c, ok)
	}
	if after.Verdict != "DEGRADED" {
		t.Fatalf("post-install verdict = %q, want DEGRADED", after.Verdict)
	}
	if after.Host != "codex" {
		t.Fatalf("report Host = %q, want codex", after.Host)
	}
}
