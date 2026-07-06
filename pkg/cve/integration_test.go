/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fixtureServer wires the captured OSV+NVD JSON files under
// testdata/integration/ to a single httptest.Server. The server tracks a hit
// counter (used by the offline test to assert no calls escape).
type fixtureServer struct {
	t      *testing.T
	srv    *httptest.Server
	hits   int64
	osvMap map[string]string // {ecosystem|name} → fixture path
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	dir := filepath.Join("testdata", "integration")
	fs := &fixtureServer{
		t: t,
		osvMap: map[string]string{
			"npm|lodash":             filepath.Join(dir, "osv_lodash.json"),
			"PyPI|requests":          filepath.Join(dir, "osv_requests.json"),
			"Go|golang.org/x/crypto": filepath.Join(dir, "osv_golang_x_crypto.json"),
			"NuGet|Newtonsoft.Json":  filepath.Join(dir, "osv_newtonsoft.json"),
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fs.hits, 1)
		// Parse the incoming batch and assemble a per-query results array. The
		// production protocol returns results[] in the same order as the
		// queries[] in the request body.
		var req struct {
			Queries []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type vulnResult struct {
			Vulns []json.RawMessage `json:"vulns"`
		}
		var resultsArr []vulnResult
		for _, q := range req.Queries {
			key := q.Package.Ecosystem + "|" + q.Package.Name
			path, ok := fs.osvMap[key]
			if !ok {
				resultsArr = append(resultsArr, vulnResult{Vulns: []json.RawMessage{}})
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				resultsArr = append(resultsArr, vulnResult{Vulns: []json.RawMessage{}})
				continue
			}
			// Pull just the first result.vulns array from the fixture and
			// attach it under THIS query's slot.
			var fixture struct {
				Results []struct {
					Vulns []json.RawMessage `json:"vulns"`
				} `json:"results"`
			}
			if err := json.Unmarshal(data, &fixture); err != nil || len(fixture.Results) == 0 {
				resultsArr = append(resultsArr, vulnResult{Vulns: []json.RawMessage{}})
				continue
			}
			resultsArr = append(resultsArr, vulnResult{Vulns: fixture.Results[0].Vulns})
		}
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(map[string]any{"results": resultsArr})
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/rest/json/cves/2.0", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fs.hits, 1)
		cveID := r.URL.Query().Get("cveId")
		if cveID == "" {
			http.Error(w, "missing cveId", http.StatusBadRequest)
			return
		}
		path := filepath.Join(dir, "nvd_"+cveID+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	fs.srv = httptest.NewServer(mux)
	t.Cleanup(fs.srv.Close)
	return fs
}

func (f *fixtureServer) OSVEndpoint() string { return f.srv.URL + "/v1/querybatch" }
func (f *fixtureServer) NVDEndpoint() string { return f.srv.URL + "/rest/json/cves/2.0" }
func (f *fixtureServer) Hits() int64         { return atomic.LoadInt64(&f.hits) }

// TestIntegration_AllEcosystems is the captured-fixture matrix test required
// by 14-05 task 2. It drives cve.Client.Query for one DepInput per ecosystem
// and asserts vuln+CWE+sources for each.
func TestIntegration_AllEcosystems(t *testing.T) {
	fs := newFixtureServer(t)

	tmp := t.TempDir()
	client := NewClient(Options{
		Online:      true,
		HTTPTimeout: 5 * time.Second,
		CacheRoot:   tmp,
		NoCache:     true,
		OSVEndpoint: fs.OSVEndpoint(),
		NVDEndpoint: fs.NVDEndpoint(),
		// Tight rate-limit spacing so the 4 NVD lookups don't add 24s.
		NVDAPIKey: "test-key",
	})

	deps := []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20"},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.27.0"},
		{Ecosystem: EcosystemGo, Name: "golang.org/x/crypto", Version: "v0.0.0-20220817201139-bc19a97f63c8"},
		{Ecosystem: EcosystemNuGet, Name: "Newtonsoft.Json", Version: "12.0.0"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := client.Query(ctx, deps)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("expected 4 EnrichedDeps, got %d", len(out))
	}

	want := []struct {
		ecosystem Ecosystem
		pkg       string
		cveID     string
		cwe       string
	}{
		{EcosystemNPM, "lodash", "CVE-2021-23337", "CWE-77"},
		{EcosystemPyPI, "requests", "CVE-2023-32681", "CWE-200"},
		{EcosystemGo, "golang.org/x/crypto", "CVE-2022-27191", "CWE-362"},
		{EcosystemNuGet, "Newtonsoft.Json", "CVE-2024-21907", "CWE-770"},
	}

	for i, w := range want {
		got := out[i]
		if got.Status != "ok" {
			t.Errorf("[%s/%s] status=%q reason=%q want ok", w.ecosystem, w.pkg, got.Status, got.Reason)
			continue
		}
		if len(got.Vulnerabilities) == 0 {
			t.Errorf("[%s/%s] no vulnerabilities returned", w.ecosystem, w.pkg)
			continue
		}
		v := got.Vulnerabilities[0]
		if v.ID != w.cveID {
			// Acceptable: canonical id may bubble up GHSA prefix if alias missing.
			// We REQUIRE the CVE id appear in the alias list at minimum.
			found := false
			for _, a := range v.Aliases {
				if a == w.cveID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("[%s/%s] CVE id %s not found (id=%s aliases=%v)", w.ecosystem, w.pkg, w.cveID, v.ID, v.Aliases)
			}
		}
		// CWE assertion — must contain the expected CWE-N (folded from OSV
		// database_specific.cwe_ids OR NVD weaknesses).
		hasCWE := false
		for _, c := range v.CWE {
			if c == w.cwe {
				hasCWE = true
				break
			}
		}
		if !hasCWE {
			t.Errorf("[%s/%s] CWE %s not found in %v", w.ecosystem, w.pkg, w.cwe, v.CWE)
		}
		// Sources[] must contain at least "osv" (NVD optional — depends on
		// whether NVD lookup landed; CWE folding from NVD is the load-bearing
		// path though).
		hasOSV := false
		hasNVD := false
		for _, s := range v.Sources {
			if s.Name == "osv" {
				hasOSV = true
			}
			if s.Name == "nvd" {
				hasNVD = true
			}
		}
		if !hasOSV {
			t.Errorf("[%s/%s] osv source missing from %v", w.ecosystem, w.pkg, v.Sources)
		}
		if !hasNVD {
			t.Errorf("[%s/%s] nvd source missing from %v", w.ecosystem, w.pkg, v.Sources)
		}
	}
}

// TestIntegration_OfflineMode_NoNetworkCalls asserts that when Options.Online
// is false, zero requests hit the test server.
func TestIntegration_OfflineMode_NoNetworkCalls(t *testing.T) {
	fs := newFixtureServer(t)

	tmp := t.TempDir()
	client := NewClient(Options{
		Online:      false,
		CacheRoot:   tmp,
		NoCache:     true,
		OSVEndpoint: fs.OSVEndpoint(),
		NVDEndpoint: fs.NVDEndpoint(),
	})

	deps := []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20"},
		{Ecosystem: EcosystemPyPI, Name: "requests", Version: "2.27.0"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := client.Query(ctx, deps)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := fs.Hits(); got != 0 {
		t.Errorf("offline mode leaked %d network calls to fixture server", got)
	}
	for _, d := range out {
		if d.Status != "skipped" || d.Reason != "offline" {
			t.Errorf("[%s/%s] status=%q reason=%q want skipped/offline",
				d.Ecosystem, d.Package, d.Status, d.Reason)
		}
	}
}
