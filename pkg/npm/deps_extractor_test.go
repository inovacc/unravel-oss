/*
Copyright (c) 2026 Security Research
*/
package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestNPMExtractor_Detects_PackageJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"x","version":"1.0.0"}`)
	if !(NPMExtractor{}).Detect(dir) {
		t.Fatal("expected Detect=true with package.json present")
	}
}

func TestNPMExtractor_Detects_NodeModules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "node_modules", "foo", "package.json"), `{"name":"foo","version":"1.0.0"}`)
	if !(NPMExtractor{}).Detect(dir) {
		t.Fatal("expected Detect=true via node_modules")
	}
}

func TestNPMExtractor_LockfileV1(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"),
		`{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
	  "name":"app",
	  "lockfileVersion":1,
	  "dependencies":{
	    "lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}
	  }
	}`)
	deps, err := (NPMExtractor{}).Extract(dir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := findDep(deps, "lodash")
	if got == nil {
		t.Fatal("expected lodash in deps")
	}
	if got.Version != "4.17.20" {
		t.Fatalf("expected version=4.17.20, got %q", got.Version)
	}
	if got.Private {
		t.Fatal("public lodash should not be Private")
	}
}

func TestNPMExtractor_LockfileV2(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"),
		`{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
	  "name":"app",
	  "lockfileVersion":2,
	  "packages":{
	    "":{"name":"app","version":"1.0.0"},
	    "node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}
	  }
	}`)
	deps, err := (NPMExtractor{}).Extract(dir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := findDep(deps, "lodash")
	if got == nil || got.Version != "4.17.21" {
		t.Fatalf("expected lodash@4.17.21, got %+v", got)
	}
}

func TestNPMExtractor_LockfileV3(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"),
		`{"name":"app","version":"1.0.0","dependencies":{"react":"^18.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
	  "name":"app",
	  "lockfileVersion":3,
	  "packages":{
	    "":{"name":"app","version":"1.0.0"},
	    "node_modules/react":{"version":"18.2.0","resolved":"https://registry.npmjs.org/react/-/react-18.2.0.tgz"}
	  }
	}`)
	deps, err := (NPMExtractor{}).Extract(dir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := findDep(deps, "react")
	if got == nil || got.Version != "18.2.0" {
		t.Fatalf("expected react@18.2.0, got %+v", got)
	}
}

func TestNPMExtractor_PrivateScoped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"),
		`{"name":"app","version":"1.0.0","dependencies":{"@internal/foo":"1.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
	  "name":"app",
	  "lockfileVersion":2,
	  "packages":{
	    "":{"name":"app","version":"1.0.0"},
	    "node_modules/@internal/foo":{"version":"1.0.0","resolved":"https://npm.internal.example.com/@internal/foo/-/foo-1.0.0.tgz"}
	  }
	}`)
	deps, err := (NPMExtractor{}).Extract(dir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := findDep(deps, "@internal/foo")
	if got == nil {
		t.Fatal("expected @internal/foo in deps")
	}
	if !got.Private {
		t.Fatal("scoped pkg from non-public registry should be Private=true")
	}
}

func TestNPMLatestVersion_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/lodash/latest") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "1.2.3"})
	}))
	defer srv.Close()

	v, err := latestVersionFrom(context.Background(), srv.URL, "lodash")
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if v != "1.2.3" {
		t.Fatalf("expected 1.2.3, got %q", v)
	}
}

func findDep(deps []cve.DepInput, name string) *cve.DepInput {
	for i := range deps {
		if deps[i].Name == name {
			return &deps[i]
		}
	}
	return nil
}
