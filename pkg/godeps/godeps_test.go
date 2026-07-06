/*
Copyright (c) 2026 Security Research
*/
package godeps

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

func writeFixture(t *testing.T, dir, src string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", src))
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), raw, 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
}

func TestGoExtractor_DetectsGoMod(t *testing.T) {
	tmp := t.TempDir()
	if (GoExtractor{}).Detect(tmp) {
		t.Fatalf("expected no detect on empty dir")
	}
	writeFixture(t, tmp, "go.mod.simple")
	if !(GoExtractor{}).Detect(tmp) {
		t.Fatalf("expected detect=true after writing go.mod")
	}
}

func TestGoExtractor_ExtractsRequires(t *testing.T) {
	tmp := t.TempDir()
	writeFixture(t, tmp, "go.mod.simple")
	deps, err := GoExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	want := map[string]string{
		"github.com/spf13/cobra": "v1.10.2",
		"gopkg.in/yaml.v3":       "v3.0.1",
		"golang.org/x/mod":       "v0.33.0",
	}
	if len(deps) != len(want) {
		t.Fatalf("deps len = %d, want %d (%+v)", len(deps), len(want), deps)
	}
	for _, d := range deps {
		v, ok := want[d.Name]
		if !ok {
			t.Errorf("unexpected dep %q", d.Name)
			continue
		}
		if d.Version != v {
			t.Errorf("dep %s version = %q, want %q", d.Name, d.Version, v)
		}
		if d.Ecosystem != cve.EcosystemGo {
			t.Errorf("dep %s ecosystem = %q, want Go", d.Name, d.Ecosystem)
		}
		if d.Private {
			t.Errorf("dep %s should not be Private", d.Name)
		}
	}
}

func TestGoExtractor_ReplaceMarksPrivate(t *testing.T) {
	tmp := t.TempDir()
	writeFixture(t, tmp, "go.mod.replace")
	deps, err := GoExtractor{}.Extract(tmp)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := map[string]bool{}
	for _, d := range deps {
		got[d.Name] = d.Private
	}
	if got["github.com/public/lib"] {
		t.Errorf("public lib should NOT be private")
	}
	if !got["github.com/forked/lib"] {
		t.Errorf("forked->internal.corp host should be Private")
	}
	if !got["github.com/local/lib"] {
		t.Errorf("local-path replace should be Private")
	}
}

func TestGoLatestVersion_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"Version": "v1.2.3"})
	}))
	t.Cleanup(srv.Close)

	old := proxyBaseURL
	proxyBaseURL = srv.URL
	t.Cleanup(func() { proxyBaseURL = old })

	got, err := LatestVersion(context.Background(), "github.com/spf13/cobra")
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if got != "1.2.3" {
		t.Errorf("got %q, want %q", got, "1.2.3")
	}
}

func TestGoLatestVersion_EscapesPath(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"Version": "v1.0.0"})
	}))
	t.Cleanup(srv.Close)

	old := proxyBaseURL
	proxyBaseURL = srv.URL
	t.Cleanup(func() { proxyBaseURL = old })

	if _, err := LatestVersion(context.Background(), "github.com/Azure/azure-sdk-go"); err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if !strings.Contains(seenPath, "!azure") {
		t.Errorf("expected case-escaped !azure in path, got %q", seenPath)
	}
}
