/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestEcosystemConstants_MatchOSV(t *testing.T) {
	tests := []struct {
		got, want string
	}{
		{string(EcosystemNPM), "npm"},
		{string(EcosystemGo), "Go"},
		{string(EcosystemPyPI), "PyPI"},
		{string(EcosystemNuGet), "NuGet"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("ecosystem string %q != %q (case-sensitive)", tt.got, tt.want)
		}
	}
}

func TestParseCVSSv3Level(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"9.8", "critical"},
		{"9.0", "critical"},
		{"7.5", "high"},
		{"7.0", "high"},
		{"5.0", "medium"},
		{"4.0", "medium"},
		{"3.5", "low"},
		{"0.1", "low"},
		{"0", "none"},
		{"", "none"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseCVSSv3Level(tt.in); got != tt.want {
				t.Errorf("parseCVSSv3Level(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCache_GetPutTTL(t *testing.T) {
	dir := t.TempDir()
	c := newCacheAt(dir)

	key := CacheKey("npm", "lodash", "4.17.20", "osv")
	if key == "" || len(key) != 32 {
		t.Fatalf("CacheKey returned bad key %q (len=%d)", key, len(key))
	}

	want := []byte(`{"hello":"world"}`)
	if err := c.Put("osv", key, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := c.Get("osv", key)
	if !ok {
		t.Fatal("Get: cache miss after Put")
	}
	if string(got) != string(want) {
		t.Errorf("Get returned %q; want %q", got, want)
	}

	// Force-expire by backdating the file mtime.
	p := filepath.Join(dir, "osv", key+".json")
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if _, ok := c.Get("osv", key); ok {
		t.Error("Get returned hit on expired entry")
	}
}

func TestMerge_OSVAuthoritative_NVDCWEFold(t *testing.T) {
	osvRows := []osvVuln{
		{
			ID:               "GHSA-35jh-r3h4-6jhm",
			Aliases:          []string{"CVE-2021-23337"},
			CVSSScore:        7.2,
			CVSSVector:       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity:         "high",
			AffectedVersions: "<4.17.21",
			References:       []string{"https://example.com/advisory"},
			PkgEcosystem:     "npm",
			PkgName:          "lodash",
			PkgVersion:       "4.17.20",
		},
	}
	nvdMap := map[string]*nvdRecord{
		"CVE-2021-23337": {
			CVEID:        "CVE-2021-23337",
			CWE:          []string{"CWE-77"},
			CVSSv3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CVSSv3Score:  7.2,
			References:   []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
		},
	}

	merged := Merge(osvRows, nvdMap, nil, nil)

	if len(merged) != 1 {
		t.Fatalf("merged len = %d; want 1", len(merged))
	}
	v := merged[0]
	if v.ID != "CVE-2021-23337" {
		t.Errorf("canonical id = %q; want CVE-2021-23337", v.ID)
	}
	if v.Severity.Level != "high" {
		t.Errorf("severity level = %q; want high (OSV authoritative)", v.Severity.Level)
	}
	if len(v.CWE) == 0 || v.CWE[0] != "CWE-77" {
		t.Errorf("CWE not folded from NVD; got %v", v.CWE)
	}
	// Both sources recorded.
	gotSources := map[string]bool{}
	for _, s := range v.Sources {
		gotSources[s.Name] = true
	}
	if !gotSources["osv"] || !gotSources["nvd"] {
		t.Errorf("sources missing osv/nvd attribution: %+v", v.Sources)
	}
}

func TestClient_OfflineMode_SkipsAllNetwork(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(Options{Online: false, CacheRoot: t.TempDir()})
	deps := []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20"},
	}
	got, err := c.Query(context.Background(), deps)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Status != "skipped" || got[0].Reason != "offline" {
		t.Errorf("got Status=%q Reason=%q; want skipped/offline", got[0].Status, got[0].Reason)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("offline mode made %d HTTP calls", n)
	}
}

func TestClient_PrivatePackage_SkipsAPI(t *testing.T) {
	c := NewClient(Options{Online: true, CacheRoot: t.TempDir()})
	// Private=true → API not called regardless of Online.
	deps := []DepInput{
		{Ecosystem: EcosystemNPM, Name: "@mycorp/internal", Version: "1.0.0", Private: true},
	}
	got, err := c.Query(context.Background(), deps)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].Status != "skipped" || got[0].Reason != "private-package" {
		t.Errorf("got Status=%q Reason=%q; want skipped/private-package",
			got[0].Status, got[0].Reason)
	}
}

// TestOSVFixture_Decodes — ensures the recorded OSV fixture parses cleanly.
func TestOSVFixture_Decodes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "osv_lodash_response.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var parsed osvBatchResp
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Results) != 1 || len(parsed.Results[0].Vulns) != 1 {
		t.Fatalf("fixture shape unexpected: %+v", parsed)
	}
	v := parsed.Results[0].Vulns[0]
	if v.ID != "GHSA-35jh-r3h4-6jhm" {
		t.Errorf("fixture id = %q", v.ID)
	}
	rows := foldOSVResp(parsed, []DepInput{
		{Ecosystem: EcosystemNPM, Name: "lodash", Version: "4.17.20"},
	})
	if len(rows) != 1 {
		t.Fatalf("foldOSVResp len = %d", len(rows))
	}
	if len(rows[0].CWEIDs) == 0 || rows[0].CWEIDs[0] != "CWE-77" {
		t.Errorf("CWE not extracted from database_specific: %v", rows[0].CWEIDs)
	}
}

// ----------------------------------------------------------------
// Phase 17 — CVE polish (CVE-POL-01..04) test additions.
// ----------------------------------------------------------------

// TestOSV_ParsesCWEIds_FromDatabaseSpecific — CVE-POL-03.
func TestOSV_ParsesCWEIds_FromDatabaseSpecific(t *testing.T) {
	parsed := osvBatchResp{Results: []struct {
		Vulns []osvRespVuln `json:"vulns"`
	}{{Vulns: []osvRespVuln{{
		ID:         "GHSA-xyz-cwe",
		DBSpecific: map[string]any{"cwe_ids": []any{"CWE-77"}},
	}}}}}
	rows := foldOSVResp(parsed, []DepInput{{Ecosystem: EcosystemNPM, Name: "x", Version: "1"}})
	if len(rows) != 1 || len(rows[0].CWEIDs) == 0 || rows[0].CWEIDs[0] != "CWE-77" {
		t.Fatalf("CWE not extracted from database_specific: %+v", rows)
	}
	merged := Merge(rows, nil, nil, nil)
	if len(merged) != 1 || len(merged[0].CWE) == 0 || merged[0].CWE[0] != "CWE-77" {
		t.Errorf("CWE not folded into Vulnerability via merge: %+v", merged)
	}
}

// TestOSV_ParsesCVSSv3Score — CVE-POL-02. Vector → numeric base score.
func TestOSV_ParsesCVSSv3Score(t *testing.T) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	score, err := scoreFromVector(vector)
	if err != nil {
		t.Fatalf("scoreFromVector: %v", err)
	}
	if score < 9.5 || score > 10.0 {
		t.Errorf("CVSS score = %f; want ≈9.8", score)
	}
	parsed := osvBatchResp{Results: []struct {
		Vulns []osvRespVuln `json:"vulns"`
	}{{Vulns: []osvRespVuln{{
		ID:       "GHSA-xyz-sev",
		Severity: []osvRespSev{{Type: "CVSS_V3", Score: vector}},
	}}}}}
	rows := foldOSVResp(parsed, []DepInput{{Ecosystem: EcosystemNPM, Name: "x", Version: "1"}})
	if len(rows) != 1 || rows[0].CVSSScore < 9.5 {
		t.Errorf("Score not populated from vector via foldOSVResp: %+v", rows)
	}
}

// TestOSV_PrecomputedDBSpecificCVSSScore — when severity[] is empty but
// database_specific.cvss.score is present, use it (CVE-POL-02 fallback).
func TestOSV_PrecomputedDBSpecificCVSSScore(t *testing.T) {
	parsed := osvBatchResp{Results: []struct {
		Vulns []osvRespVuln `json:"vulns"`
	}{{Vulns: []osvRespVuln{{
		ID: "GHSA-xyz-pre",
		DBSpecific: map[string]any{
			"cvss": map[string]any{"score": 7.2},
		},
	}}}}}
	rows := foldOSVResp(parsed, []DepInput{{Ecosystem: EcosystemNPM, Name: "x", Version: "1"}})
	if len(rows) != 1 || rows[0].CVSSScore != 7.2 {
		t.Errorf("Pre-computed cvss.score not used: %+v", rows)
	}
	if rows[0].Severity != "high" {
		t.Errorf("Severity level = %q; want high", rows[0].Severity)
	}
}

// TestOSV_SerializesRanges — CVE-POL-04. SEMVER affected[].ranges →
// AffectedVersions string.
func TestOSV_SerializesRanges(t *testing.T) {
	parsed := osvBatchResp{Results: []struct {
		Vulns []osvRespVuln `json:"vulns"`
	}{{Vulns: []osvRespVuln{{
		ID: "GHSA-xyz-aff",
		Affected: []osvRespAffec{{Ranges: []osvRespRange{{
			Type: "SEMVER",
			Events: []osvRespEvent{
				{Introduced: "0"},
				{Fixed: "4.17.21"},
			},
		}}}},
	}}}}}
	rows := foldOSVResp(parsed, []DepInput{{Ecosystem: EcosystemNPM, Name: "x", Version: "1"}})
	if len(rows) != 1 {
		t.Fatalf("len = %d", len(rows))
	}
	if rows[0].AffectedVersions != ">=0,<4.17.21" {
		t.Errorf("AffectedVersions = %q; want >=0,<4.17.21", rows[0].AffectedVersions)
	}
}

// stubProber is a test-only LatestProber for the Go ecosystem.
type stubProber struct {
	eco     Ecosystem
	version string
	calls   int32
}

func (s *stubProber) Ecosystem() Ecosystem { return s.eco }
func (s *stubProber) Latest(_ context.Context, _ string) (string, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.version, nil
}

// TestClient_Query_LatestProberPopulates — CVE-POL-01. Registered prober
// fills VersionLatest + OutdatedBy on Query.
func TestClient_Query_LatestProberPopulates(t *testing.T) {
	// OSV stub returning empty (no vulns) so Query proceeds to latest probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	defer srv.Close()

	// Use a unique ecosystem so we don't collide with init-registered Go probers.
	const testEco Ecosystem = "TestEco-LP"
	stub := &stubProber{eco: testEco, version: "2.5.0"}
	RegisterLatestProber(stub)

	c := NewClient(Options{
		Online:      true,
		CacheRoot:   t.TempDir(),
		OSVEndpoint: srv.URL,
	})
	got, err := c.Query(context.Background(), []DepInput{
		{Ecosystem: testEco, Name: "example.com/foo", Version: "1.2.3"},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].VersionLatest != "2.5.0" {
		t.Errorf("VersionLatest = %q; want 2.5.0", got[0].VersionLatest)
	}
	if got[0].OutdatedBy == nil {
		t.Fatal("OutdatedBy nil; want major=1")
	}
	if got[0].OutdatedBy.Major != 1 {
		t.Errorf("OutdatedBy.Major = %d; want 1", got[0].OutdatedBy.Major)
	}
	if atomic.LoadInt32(&stub.calls) != 1 {
		t.Errorf("prober called %d times; want 1", stub.calls)
	}
}

// TestClient_Query_NilProber_NoPanic — DepInput with unregistered ecosystem
// completes Query without panicking; VersionLatest stays empty.
func TestClient_Query_NilProber_NoPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	defer srv.Close()
	c := NewClient(Options{
		Online:      true,
		CacheRoot:   t.TempDir(),
		OSVEndpoint: srv.URL,
	})
	got, err := c.Query(context.Background(), []DepInput{
		{Ecosystem: Ecosystem("Unknown-Ecosystem-Z"), Name: "x", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].VersionLatest != "" {
		t.Errorf("expected empty VersionLatest for unknown ecosystem; got %+v", got)
	}
}

// TestComputeVersionDelta_Semver — declared 1.2.3 → latest 2.5.0 = major 1.
func TestComputeVersionDelta_Semver(t *testing.T) {
	tests := []struct {
		declared, latest string
		want             *VersionDelta
	}{
		{"1.2.3", "2.5.0", &VersionDelta{Major: 1}},
		{"v1.2.3", "v1.5.0", &VersionDelta{Minor: 3}},
		{"1.2.3", "1.2.7", &VersionDelta{Patch: 4}},
		{"1.2.3", "1.2.3", nil}, // no delta
		{"2.0.0", "1.0.0", nil}, // declared > latest → no delta
	}
	for _, tt := range tests {
		got := computeVersionDelta(tt.declared, tt.latest)
		if (got == nil) != (tt.want == nil) {
			t.Errorf("computeVersionDelta(%q,%q) = %+v; want %+v", tt.declared, tt.latest, got, tt.want)
			continue
		}
		if got != nil && (got.Major != tt.want.Major || got.Minor != tt.want.Minor || got.Patch != tt.want.Patch) {
			t.Errorf("computeVersionDelta(%q,%q) = %+v; want %+v", tt.declared, tt.latest, got, tt.want)
		}
	}
}

// TestComputeVersionDelta_GoPseudoVersion — pseudo-versions return nil delta.
func TestComputeVersionDelta_GoPseudoVersion(t *testing.T) {
	if d := computeVersionDelta("v0.0.0-20220817201139-bc19a97f63c8", "1.2.3"); d != nil {
		t.Errorf("pseudo-version should be unparseable; got %+v", d)
	}
	if d := computeVersionDelta("1.2.3", "v0.0.0-20220817201139-bc19a97f63c8"); d != nil {
		t.Errorf("pseudo-version should be unparseable; got %+v", d)
	}
}

// TestRegisterLatestProber_Idempotent — re-registering same Ecosystem is no-op.
func TestRegisterLatestProber_Idempotent(t *testing.T) {
	const eco Ecosystem = "TestEco-Idem"
	a := &stubProber{eco: eco, version: "1.0.0"}
	b := &stubProber{eco: eco, version: "9.9.9"}
	RegisterLatestProber(a)
	RegisterLatestProber(b)
	got := proberFor(eco)
	if got == nil {
		t.Fatal("proberFor returned nil")
	}
	v, _ := got.Latest(context.Background(), "x")
	if v != "1.0.0" {
		t.Errorf("expected first registration to win; got %q", v)
	}
}

// TestNVDFixture_Decodes — ensures the recorded NVD fixture parses cleanly.
func TestNVDFixture_Decodes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nvd_cve_2021_23337.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var parsed nvdRespV2
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec := foldNVDResp(parsed, "CVE-2021-23337")
	if rec == nil {
		t.Fatal("foldNVDResp returned nil")
	}
	if len(rec.CWE) == 0 || rec.CWE[0] != "CWE-77" {
		t.Errorf("CWE extraction failed: %v", rec.CWE)
	}
	if rec.CVSSv3Score < 7.0 || rec.CVSSv3Score > 8.0 {
		t.Errorf("CVSS score = %f; expected ~7.2", rec.CVSSv3Score)
	}
}
