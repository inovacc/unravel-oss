/*
Copyright (c) 2026 Security Research
*/
package pydeps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

func copyFixture(t *testing.T, dir, srcRel, dstName string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", srcRel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", srcRel, err)
	}
	if err := os.WriteFile(filepath.Join(dir, dstName), raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", dstName, err)
	}
}

func depMap(deps []cve.DepInput) map[string]cve.DepInput {
	out := make(map[string]cve.DepInput, len(deps))
	for _, d := range deps {
		out[d.Name] = d
	}
	return out
}

func TestPyExtractor_RequirementsTxt(t *testing.T) {
	tmp := t.TempDir()
	copyFixture(t, tmp, "requirements.txt", "requirements.txt")
	copyFixture(t, tmp, "child.txt", "child.txt")
	deps, err := PyExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	m := depMap(deps)

	check := func(name, version string, private bool) {
		t.Helper()
		d, ok := m[name]
		if !ok {
			t.Errorf("missing dep %q", name)
			return
		}
		if d.Version != version {
			t.Errorf("dep %s version=%q want %q", name, d.Version, version)
		}
		if d.Private != private {
			t.Errorf("dep %s private=%v want %v", name, d.Private, private)
		}
		if d.Ecosystem != cve.EcosystemPyPI {
			t.Errorf("dep %s ecosystem=%q want PyPI", name, d.Ecosystem)
		}
	}
	check("flask", "2.3.0", false)
	check("django", "4.2", false)      // >= lower bound
	check("requests", "2.30", false)   // >= with extras stripped
	check("numpy", "1.24", false)      // ~= lower bound
	check("pyyaml", "6.0", false)      // recursive include
	check("git-private-pkg", "", true) // git+ direct URL
}

func TestPyExtractor_RequirementsRecursiveInclude(t *testing.T) {
	tmp := t.TempDir()
	copyFixture(t, tmp, "requirements.txt", "requirements.txt")
	copyFixture(t, tmp, "child.txt", "child.txt")
	deps, err := PyExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for _, d := range deps {
		if d.Name == "pyyaml" {
			return
		}
	}
	t.Fatalf("expected pyyaml from recursive include, got %+v", deps)
}

func TestPyExtractor_PyprojectPoetry(t *testing.T) {
	tmp := t.TempDir()
	copyFixture(t, tmp, "pyproject.poetry.toml", "pyproject.toml")
	deps, err := PyExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	m := depMap(deps)
	if _, ok := m["python"]; ok {
		t.Errorf("python runtime spec must be skipped")
	}
	d, ok := m["requests"]
	if !ok {
		t.Fatalf("missing requests")
	}
	if d.Version != "2.30.0" {
		t.Errorf("requests version=%q want 2.30.0", d.Version)
	}
	d2, ok := m["internal-thing"]
	if !ok {
		t.Fatalf("missing internal-thing")
	}
	if !d2.Private {
		t.Errorf("internal-thing should be Private (git source)")
	}
	d3, ok := m["flask"]
	if !ok {
		t.Fatalf("missing flask")
	}
	if d3.Version != "2.3" {
		t.Errorf("flask version=%q want 2.3 (lower bound of >=2.3,<3)", d3.Version)
	}
}

func TestPyExtractor_PyprojectPEP621(t *testing.T) {
	tmp := t.TempDir()
	copyFixture(t, tmp, "pyproject.pep621.toml", "pyproject.toml")
	deps, err := PyExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	m := depMap(deps)
	if d, ok := m["flask"]; !ok || d.Version != "2.3.0" {
		t.Errorf("flask=%+v want 2.3.0", d)
	}
	if d, ok := m["requests"]; !ok || d.Version != "2.30" {
		t.Errorf("requests=%+v want 2.30", d)
	}
	if d, ok := m["numpy"]; !ok || d.Version != "1.24" {
		t.Errorf("numpy=%+v want 1.24", d)
	}
}

func TestPyExtractor_PrivateGitSource(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "requirements.txt"),
		[]byte("foo @ git+https://internal/foo\nbar==1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := PyExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	m := depMap(deps)
	if !m["foo"].Private {
		t.Errorf("foo should be Private")
	}
	if m["bar"].Private {
		t.Errorf("bar should NOT be Private")
	}
}

func TestPyLatestVersion_FiltersPreReleases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// info.version is a stable; releases include pre-releases that must
		// not be picked.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{"version": "1.5.0"},
			"releases": map[string]any{
				"1.5.0":   []any{},
				"2.0.0a1": []any{}, // pre-release
				"1.4.9":   []any{},
			},
		})
	}))
	t.Cleanup(srv.Close)

	old := pypiBaseURL
	pypiBaseURL = srv.URL
	t.Cleanup(func() { pypiBaseURL = old })

	got, err := LatestVersion(context.Background(), "demo")
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if got != "1.5.0" {
		t.Errorf("got %q want 1.5.0", got)
	}

	// Now a payload where info.version itself is a pre-release; expect
	// fallback to the largest stable release key.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{"version": "2.0.0a2"},
			"releases": map[string]any{
				"1.9.0":   []any{},
				"1.10.0":  []any{},
				"2.0.0a2": []any{},
			},
		})
	}))
	t.Cleanup(srv2.Close)
	pypiBaseURL = srv2.URL

	got2, err := LatestVersion(context.Background(), "demo")
	if err != nil {
		t.Fatalf("LatestVersion(2): %v", err)
	}
	if got2 != "1.9.0" && got2 != "1.10.0" {
		t.Errorf("got %q expected stable fallback (1.9.0 or 1.10.0)", got2)
	}
}
