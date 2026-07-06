package goversions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHTTPSources(t *testing.T) {
	dl, _ := os.ReadFile("testdata/dl.json")
	mods, _ := os.ReadFile("testdata/modules.json")
	osv, _ := os.ReadFile("testdata/osv.json")
	hist, _ := os.ReadFile("testdata/release-history.html")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dl/" && r.URL.Query().Get("mode") == "json":
			_, _ = w.Write(dl)
		case r.URL.Path == "/index/modules.json":
			_, _ = w.Write(mods)
		case r.URL.Path == "/ID/GO-2023-1878.json":
			_, _ = w.Write(osv)
		case r.URL.Path == "/doc/devel/release":
			_, _ = w.Write(hist)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := &HTTPSources{Client: srv.Client(), DLBase: srv.URL, VulnBase: srv.URL, DocBase: srv.URL}
	ctx := context.Background()

	rels, err := s.Downloads(ctx)
	if err != nil || len(rels) != 2 {
		t.Fatalf("downloads: %v len=%d", err, len(rels))
	}
	vs, err := s.Vulns(ctx)
	if err != nil || len(vs) != 1 || vs[0].ID != "GO-2023-1878" {
		t.Fatalf("vulns: %v %+v", err, vs)
	}
	m, err := s.ReleaseMeta(ctx)
	if err != nil || m["go1.22.5"].Date != "2024-07-02" {
		t.Fatalf("meta: %v %+v", err, m)
	}
}
