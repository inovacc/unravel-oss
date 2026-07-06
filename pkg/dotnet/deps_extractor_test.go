/*
Copyright (c) 2026 Security Research
*/
package dotnet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeDepsJSON(t *testing.T, dir, fname string) string {
	t.Helper()
	p := filepath.Join(dir, fname)
	body := `{
	  "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0"},
	  "libraries": {
	    "Newtonsoft.Json/13.0.1": {"type":"package","serviceable":true,"path":"newtonsoft.json/13.0.1"},
	    "Microsoft.Extensions.Logging/8.0.0": {"type":"package","serviceable":true,"path":"microsoft.extensions.logging/8.0.0"},
	    "MyApp/1.0.0": {"type":"project","serviceable":false}
	  },
	  "targets": {
	    ".NETCoreApp,Version=v8.0": {
	      "Newtonsoft.Json/13.0.1": {},
	      "Microsoft.Extensions.Logging/8.0.0": {},
	      "MyApp/1.0.0": {}
	    }
	  }
	}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestDotNetExtractor_DetectsDepsJSON(t *testing.T) {
	dir := t.TempDir()
	writeDepsJSON(t, dir, "MyApp.deps.json")
	if !(DotNetExtractor{}).Detect(dir) {
		t.Fatal("expected Detect=true with *.deps.json present")
	}
}

func TestDotNetExtractor_ExtractsLibraries(t *testing.T) {
	dir := t.TempDir()
	writeDepsJSON(t, dir, "MyApp.deps.json")

	deps, err := (DotNetExtractor{}).Extract(dir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 package deps (project filtered), got %d: %+v", len(deps), deps)
	}
	names := map[string]string{}
	for _, d := range deps {
		names[d.Name] = d.Version
	}
	if names["Newtonsoft.Json"] != "13.0.1" {
		t.Fatalf("missing Newtonsoft.Json@13.0.1: %+v", names)
	}
	if names["Microsoft.Extensions.Logging"] != "8.0.0" {
		t.Fatalf("missing Microsoft.Extensions.Logging@8.0.0: %+v", names)
	}
}

func TestDotNetLatestVersion_FiltersPreReleases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"versions": []string{"1.0.0", "1.1.0-beta", "1.0.1"},
		})
	}))
	defer srv.Close()

	v, err := latestVersionFrom(context.Background(), srv.URL, "Some.Pkg")
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if v != "1.0.1" {
		t.Fatalf("expected 1.0.1 (filtered pre-release), got %q", v)
	}
}
