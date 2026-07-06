/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fullVulnPayload is what GET /v1/vulns/{id} returns. Mirrors GHSA-style
// records observed live (severity[].score = full CVSS:3.1 vector,
// database_specific.cwe_ids = [...], affected[].ranges[] SEMVER, etc).
const fullVulnPayload = `{
  "id": "GHSA-test-aaaa-bbbb",
  "summary": "test vuln",
  "aliases": ["CVE-2024-9999"],
  "references": [{"type": "ADVISORY", "url": "https://example/sec/1"}],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "database_specific": {"cwe_ids": ["CWE-77", "CWE-94"]},
  "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
}`

// TestOSV_FetchVulnDetails_PopulatesFromSingleVulnEndpoint feeds a httptest
// server returning the full single-vuln payload and asserts merge populates
// CVSS / CWE / AffectedVersions on the matching osvVuln row.
func TestOSV_FetchVulnDetails_PopulatesFromSingleVulnEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.Error(w, "bad path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fullVulnPayload))
	}))
	defer srv.Close()

	c := newOSVClient(2*time.Second, 4)
	c.vulnEndpoint = srv.URL + "/v1/vulns/"

	rows := []osvVuln{
		{ID: "GHSA-test-aaaa-bbbb", PkgEcosystem: "npm", PkgName: "x", PkgVersion: "1.0.0"},
	}
	details := c.fetchVulnDetails(context.Background(), []string{rows[0].ID})
	if _, ok := details[rows[0].ID]; !ok {
		t.Fatalf("fetchVulnDetails: missing detail for %s", rows[0].ID)
	}
	mergeVulnDetails(rows, details)

	if rows[0].CVSSScore < 9.0 {
		t.Errorf("CVSSScore = %v, want ~9.8", rows[0].CVSSScore)
	}
	if rows[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", rows[0].Severity)
	}
	if len(rows[0].CWEIDs) != 2 || rows[0].CWEIDs[0] != "CWE-77" {
		t.Errorf("CWEIDs = %v, want [CWE-77 CWE-94]", rows[0].CWEIDs)
	}
	if rows[0].AffectedVersions != ">=0,<4.17.21" {
		t.Errorf("AffectedVersions = %q, want >=0,<4.17.21", rows[0].AffectedVersions)
	}
	if len(rows[0].References) == 0 {
		t.Errorf("References not populated")
	}
}

// TestOSV_FetchVulnDetails_404SkipsGracefully ensures one 404 doesn't poison
// the rest of the batch and missing entries simply aren't in the map.
func TestOSV_FetchVulnDetails_404SkipsGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "MISSING-1" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		payload := strings.Replace(fullVulnPayload, "GHSA-test-aaaa-bbbb", id, 1)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := newOSVClient(2*time.Second, 4)
	c.vulnEndpoint = srv.URL + "/v1/vulns/"

	details := c.fetchVulnDetails(context.Background(),
		[]string{"GHSA-aaa", "MISSING-1", "GHSA-bbb"})

	if _, ok := details["MISSING-1"]; ok {
		t.Errorf("404 should be omitted from details, got entry")
	}
	if _, ok := details["GHSA-aaa"]; !ok {
		t.Errorf("GHSA-aaa missing from details")
	}
	if _, ok := details["GHSA-bbb"]; !ok {
		t.Errorf("GHSA-bbb missing from details")
	}
}

// TestOSV_FetchVulnDetails_RateLimitBackoff returns 429 once with Retry-After,
// then 200. The fetch should retry and succeed without erroring.
func TestOSV_FetchVulnDetails_RateLimitBackoff(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "throttled", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fullVulnPayload))
	}))
	defer srv.Close()

	c := newOSVClient(5*time.Second, 4)
	c.vulnEndpoint = srv.URL + "/v1/vulns/"

	t0 := time.Now()
	details := c.fetchVulnDetails(context.Background(), []string{"GHSA-test-aaaa-bbbb"})
	elapsed := time.Since(t0)

	if _, ok := details["GHSA-test-aaaa-bbbb"]; !ok {
		t.Fatalf("retry path failed: details map empty (elapsed=%v hits=%d)", elapsed, atomic.LoadInt32(&hits))
	}
	if elapsed < 800*time.Millisecond {
		t.Errorf("retry happened too fast (%v) — backoff not honored", elapsed)
	}
	if got := atomic.LoadInt32(&hits); got < 2 {
		t.Errorf("expected ≥2 hits (1x429 + 1x200), got %d", got)
	}
}

// TestOSV_FetchVulnDetails_CachesAcrossCalls verifies the disk cache absorbs
// repeated calls (only one HTTP hit per id across two sequential calls).
func TestOSV_FetchVulnDetails_CachesAcrossCalls(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(fullVulnPayload))
	}))
	defer srv.Close()

	c := newOSVClient(2*time.Second, 4)
	c.vulnEndpoint = srv.URL + "/v1/vulns/"
	c.cache = newCacheAt(t.TempDir())

	for i := 0; i < 3; i++ {
		details := c.fetchVulnDetails(context.Background(), []string{"GHSA-test-aaaa-bbbb"})
		if _, ok := details["GHSA-test-aaaa-bbbb"]; !ok {
			t.Fatalf("iteration %d: details missing", i)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 HTTP hit (subsequent served from cache), got %d", got)
	}
}

// TestClient_Query_OSVTwoPhase wires the full /v1/querybatch (returning only
// id+modified) -> /v1/vulns/{id} (returning full payload) flow end-to-end.
func TestClient_Query_OSVTwoPhase(t *testing.T) {
	batchSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Minimal batch response: only id+modified per vuln.
		resp := map[string]any{
			"results": []map[string]any{
				{"vulns": []map[string]any{
					{"id": "GHSA-test-aaaa-bbbb", "modified": "2024-01-01T00:00:00Z"},
				}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer batchSrv.Close()

	vulnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fullVulnPayload))
	}))
	defer vulnSrv.Close()

	c := NewClient(Options{
		Online:      true,
		NoCache:     true,
		MaxInFlight: 4,
		HTTPTimeout: 2 * time.Second,
		OSVEndpoint: batchSrv.URL,
	})
	// Override the per-vuln endpoint after NewClient.
	c.osv.vulnEndpoint = vulnSrv.URL + "/v1/vulns/"
	// Disable NVD/GHSA so the test stays hermetic.
	c.nvd.endpoint = "http://127.0.0.1:1" // non-listening
	c.ghsa = nil

	out, err := c.Query(context.Background(), []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20"},
	})
	if err != nil {
		t.Fatalf("Query err = %v", err)
	}
	if len(out) != 1 || len(out[0].Vulnerabilities) == 0 {
		t.Fatalf("expected 1 vuln on dep, got %d deps / %d vulns", len(out), func() int {
			if len(out) == 0 {
				return 0
			}
			return len(out[0].Vulnerabilities)
		}())
	}
	v := out[0].Vulnerabilities[0]
	if v.Severity.CVSSv3 < 9.0 {
		t.Errorf("CVSSv3 not populated via two-phase: %v", v.Severity.CVSSv3)
	}
	if len(v.CWE) == 0 {
		t.Errorf("CWE not populated via two-phase: %+v", v)
	}
	if v.AffectedVersions == "" {
		t.Errorf("AffectedVersions empty: %+v", v)
	}
}

// silence unused-import linters if present in cve_test.go pruning.
var _ = fmt.Sprintf
