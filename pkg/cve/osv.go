/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// osvEndpoint is the OSV batch query endpoint.
// Reference: https://google.github.io/osv.dev/post-v1-querybatch/
const osvEndpoint = "https://api.osv.dev/v1/querybatch"

// osvVulnEndpoint is the OSV per-vuln detail endpoint base. The batch
// endpoint (v1/querybatch) returns only {id, modified} per vuln; the full
// payload (severity, database_specific.cwe_ids, affected[].ranges) requires
// a second-pass GET v1/vulns/{id} per id.
// Reference: https://google.github.io/osv.dev/get-v1-vulns/
const osvVulnEndpoint = "https://api.osv.dev/v1/vulns/"

const (
	osvBatchSize       = 1000
	osvMaxBackoff      = 5 * time.Minute
	osvDefaultTimeout  = 10 * time.Second
	osvDefaultInflight = 8
)

// osvClient queries https://api.osv.dev/v1/querybatch.
type osvClient struct {
	http         *http.Client
	endpoint     string
	vulnEndpoint string        // base URL (with trailing slash) for /v1/vulns/{id}
	sem          chan struct{} // bounded in-flight semaphore
	cache        *cache
}

func newOSVClient(httpTimeout time.Duration, maxInFlight int) *osvClient {
	if httpTimeout <= 0 {
		httpTimeout = osvDefaultTimeout
	}
	if maxInFlight <= 0 {
		maxInFlight = osvDefaultInflight
	}
	return &osvClient{
		http:         &http.Client{Timeout: httpTimeout},
		endpoint:     osvEndpoint,
		vulnEndpoint: osvVulnEndpoint,
		sem:          make(chan struct{}, maxInFlight),
	}
}

// osvPackage / osvQuery are wire types for the request body.
type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

// osvVuln is the per-vuln data we extract from the response.
type osvVuln struct {
	ID               string     `json:"id"`
	Aliases          []string   `json:"aliases,omitempty"`
	Summary          string     `json:"summary,omitempty"`
	Withdrawn        *time.Time `json:"withdrawn,omitempty"`
	References       []string   `json:"references,omitempty"`
	CWEIDs           []string   `json:"cwe_ids,omitempty"`
	CVSSVector       string     `json:"cvss_vector,omitempty"`
	CVSSScore        float64    `json:"cvss_score,omitempty"`
	Severity         string     `json:"severity_level,omitempty"`
	AffectedVersions string     `json:"affected_versions,omitempty"`
	// Pkg back-pointer for fan-out result attribution.
	PkgEcosystem string `json:"-"`
	PkgName      string `json:"-"`
	PkgVersion   string `json:"-"`
}

// raw OSV response shapes.
type osvRespVuln struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Summary    string         `json:"summary"`
	Withdrawn  string         `json:"withdrawn"`
	References []osvRespRef   `json:"references"`
	Severity   []osvRespSev   `json:"severity"`
	Affected   []osvRespAffec `json:"affected"`
	DBSpecific map[string]any `json:"database_specific"`
}

type osvRespRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvRespSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRespAffec struct {
	Ranges     []osvRespRange `json:"ranges"`
	DBSpecific map[string]any `json:"database_specific"`
}

type osvRespRange struct {
	Type   string         `json:"type"`
	Events []osvRespEvent `json:"events"`
}

type osvRespEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []osvRespVuln `json:"vulns"`
	} `json:"results"`
}

// Query sends a batched query to OSV. Inputs are split into chunks of
// osvBatchSize and the resulting vulns are flattened with package
// back-references attached.
func (c *osvClient) Query(ctx context.Context, deps []DepInput) ([]osvVuln, error) {
	if len(deps) == 0 {
		return nil, nil
	}
	var out []osvVuln
	for start := 0; start < len(deps); start += osvBatchSize {
		end := start + osvBatchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[start:end]

		// in-flight cap
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			return out, ctx.Err()
		}
		vs, err := c.queryChunk(ctx, chunk)
		<-c.sem
		if err != nil {
			return out, err
		}
		out = append(out, vs...)
	}
	return out, nil
}

func (c *osvClient) queryChunk(ctx context.Context, deps []DepInput) ([]osvVuln, error) {
	queries := make([]osvQuery, len(deps))
	for i, d := range deps {
		queries[i] = osvQuery{
			Package: osvPackage{Ecosystem: string(d.Ecosystem), Name: d.Name},
			Version: d.Version,
		}
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal: %w", err)
	}

	backoff := time.Second
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("osv: new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("osv: do: %w", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			defer func() { _ = resp.Body.Close() }()
			data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			if err != nil {
				return nil, fmt.Errorf("osv: read: %w", err)
			}
			var parsed osvBatchResp
			if err := json.Unmarshal(data, &parsed); err != nil {
				return nil, fmt.Errorf("osv: decode: %w", err)
			}
			return foldOSVResp(parsed, deps), nil
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			retry := parseRetryAfter(resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
			if retry <= 0 {
				retry = backoff
			}
			if retry > osvMaxBackoff {
				retry = osvMaxBackoff
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retry):
			}
			backoff *= 2
			if backoff > osvMaxBackoff {
				backoff = osvMaxBackoff
			}
			continue
		default:
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("osv: status %d: %s", resp.StatusCode, string(b))
		}
	}
}

// fetchVulnDetails fetches the full payload for each vuln id via
// GET /v1/vulns/{id}. The batch endpoint /v1/querybatch returns only
// {id, modified} per vuln; severity, database_specific.cwe_ids and
// affected[].ranges[] live only on the per-vuln record.
//
// Returns a map id -> osvRespVuln. Failures (404, 5xx after backoff,
// network errors) are silently skipped: missing entries cause the merge
// to leave fields empty rather than failing the whole Query.
//
// Cache: 24h disk cache keyed by ("osv-vuln", id). Reuses the existing
// pkg/cve cache layer.
func (c *osvClient) fetchVulnDetails(ctx context.Context, ids []string) map[string]osvRespVuln {
	out := make(map[string]osvRespVuln, len(ids))
	if len(ids) == 0 {
		return out
	}
	// Dedupe.
	seen := make(map[string]struct{}, len(ids))
	uniq := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range uniq {
		wg.Add(1)
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			return out
		}
		go func(id string) {
			defer wg.Done()
			defer func() { <-c.sem }()
			v, ok := c.fetchOneVuln(ctx, id)
			if !ok {
				return
			}
			mu.Lock()
			out[id] = v
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

// fetchOneVuln retrieves a single OSV vuln record with cache + retry.
func (c *osvClient) fetchOneVuln(ctx context.Context, id string) (osvRespVuln, bool) {
	// Cache lookup (key="osv-vuln" / id).
	if c.cache != nil {
		if data, hit := c.cache.Get("osv-vuln", id); hit {
			var v osvRespVuln
			if err := json.Unmarshal(data, &v); err == nil {
				return v, true
			}
		}
	}
	url := c.vulnEndpoint + id
	backoff := time.Second
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return osvRespVuln{}, false
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return osvRespVuln{}, false
		}
		switch resp.StatusCode {
		case http.StatusOK:
			data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			_ = resp.Body.Close()
			if err != nil {
				return osvRespVuln{}, false
			}
			var v osvRespVuln
			if err := json.Unmarshal(data, &v); err != nil {
				return osvRespVuln{}, false
			}
			if c.cache != nil {
				_ = c.cache.Put("osv-vuln", id, data)
			}
			return v, true
		case http.StatusNotFound:
			_ = resp.Body.Close()
			return osvRespVuln{}, false
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			retry := parseRetryAfter(resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
			if retry <= 0 {
				retry = backoff
			}
			if retry > osvMaxBackoff {
				retry = osvMaxBackoff
			}
			select {
			case <-ctx.Done():
				return osvRespVuln{}, false
			case <-time.After(retry):
			}
			backoff *= 2
			if backoff > osvMaxBackoff {
				backoff = osvMaxBackoff
			}
			continue
		default:
			_ = resp.Body.Close()
			return osvRespVuln{}, false
		}
	}
	return osvRespVuln{}, false
}

// mergeVulnDetails overlays per-vuln details onto a slice of osvVuln (which
// were folded from the minimal batch response). Fields already populated on
// row are preserved; details fill the gaps.
func mergeVulnDetails(rows []osvVuln, details map[string]osvRespVuln) {
	if len(details) == 0 {
		return
	}
	for i := range rows {
		v, ok := details[rows[i].ID]
		if !ok {
			continue
		}
		if rows[i].Summary == "" {
			rows[i].Summary = v.Summary
		}
		if len(rows[i].Aliases) == 0 && len(v.Aliases) > 0 {
			rows[i].Aliases = append([]string(nil), v.Aliases...)
		}
		if rows[i].Withdrawn == nil && v.Withdrawn != "" {
			if t, err := time.Parse(time.RFC3339, v.Withdrawn); err == nil {
				rows[i].Withdrawn = &t
			}
		}
		if len(rows[i].References) == 0 {
			for _, ref := range v.References {
				rows[i].References = append(rows[i].References, ref.URL)
			}
		}
		// Severity / CVSS
		if rows[i].CVSSScore == 0 {
			for _, s := range v.Severity {
				if strings.HasPrefix(s.Type, "CVSS_V3") {
					rows[i].CVSSVector = s.Score
					if score, err := scoreFromVector(s.Score); err == nil {
						rows[i].CVSSScore = score
					}
					rows[i].Severity = parseCVSSv3Level(s.Score)
					break
				}
			}
		}
		if rows[i].CVSSScore == 0 {
			if cvssBlob, ok := v.DBSpecific["cvss"].(map[string]any); ok {
				switch s := cvssBlob["score"].(type) {
				case float64:
					rows[i].CVSSScore = s
				case string:
					if f, err := strconv.ParseFloat(s, 64); err == nil {
						rows[i].CVSSScore = f
					}
				}
				if rows[i].Severity == "" || rows[i].Severity == "none" {
					rows[i].Severity = scoreToLevel(rows[i].CVSSScore)
				}
			}
		}
		// CWE
		if len(rows[i].CWEIDs) == 0 {
			if cwes, ok := v.DBSpecific["cwe_ids"]; ok {
				rows[i].CWEIDs = anyToStringSlice(cwes)
			}
		}
		// Affected ranges
		if rows[i].AffectedVersions == "" {
			rows[i].AffectedVersions = formatAffectedRanges(v.Affected)
		}
	}
}

// foldOSVResp flattens batch results, attaching original package info.
func foldOSVResp(r osvBatchResp, deps []DepInput) []osvVuln {
	if len(r.Results) == 0 {
		return nil
	}
	var out []osvVuln
	n := len(r.Results)
	if n > len(deps) {
		n = len(deps)
	}
	for i := 0; i < n; i++ {
		dep := deps[i]
		for _, v := range r.Results[i].Vulns {
			ov := osvVuln{
				ID:           v.ID,
				Aliases:      append([]string(nil), v.Aliases...),
				Summary:      v.Summary,
				PkgEcosystem: string(dep.Ecosystem),
				PkgName:      dep.Name,
				PkgVersion:   dep.Version,
			}
			if v.Withdrawn != "" {
				if t, err := time.Parse(time.RFC3339, v.Withdrawn); err == nil {
					ov.Withdrawn = &t
				}
			}
			for _, ref := range v.References {
				ov.References = append(ov.References, ref.URL)
			}
			// Severity
			for _, s := range v.Severity {
				if strings.HasPrefix(s.Type, "CVSS_V3") {
					ov.CVSSVector = s.Score
					if score, err := scoreFromVector(s.Score); err == nil {
						ov.CVSSScore = score
					}
					ov.Severity = parseCVSSv3Level(s.Score)
				}
			}
			// Pre-computed CVSS score in database_specific (preferred when
			// present — saves us from hand-computing). Shape:
			//   "database_specific": { "cvss": { "score": 7.2 } }
			if ov.CVSSScore == 0 {
				if cvssBlob, ok := v.DBSpecific["cvss"].(map[string]any); ok {
					switch s := cvssBlob["score"].(type) {
					case float64:
						ov.CVSSScore = s
					case string:
						if f, err := strconv.ParseFloat(s, 64); err == nil {
							ov.CVSSScore = f
						}
					}
					if ov.Severity == "" || ov.Severity == "none" {
						ov.Severity = scoreToLevel(ov.CVSSScore)
					}
				}
			}
			// CWE from database_specific
			if cwes, ok := v.DBSpecific["cwe_ids"]; ok {
				ov.CWEIDs = anyToStringSlice(cwes)
			}
			// Affected ranges → human-readable string ("introduced..fixed")
			ov.AffectedVersions = formatAffectedRanges(v.Affected)
			out = append(out, ov)
		}
	}
	return out
}

func anyToStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func formatAffectedRanges(a []osvRespAffec) string {
	var parts []string
	for _, af := range a {
		for _, r := range af.Ranges {
			var introduced, fixed string
			for _, e := range r.Events {
				if e.Introduced != "" {
					introduced = e.Introduced
				}
				if e.Fixed != "" {
					fixed = e.Fixed
				}
			}
			if fixed != "" && introduced != "" {
				parts = append(parts, fmt.Sprintf(">=%s,<%s", introduced, fixed))
			} else if fixed != "" {
				parts = append(parts, "<"+fixed)
			} else if introduced != "" {
				parts = append(parts, ">="+introduced)
			}
		}
	}
	return strings.Join(parts, " || ")
}

// scoreFromVector tries to extract a base score from a CVSS v3 vector.
// OSV's `severity[].score` field is sometimes the full vector
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") and sometimes already
// the numeric base score ("7.2"). When the input is a vector, we compute
// the CVSS v3.1 base score per NIST SP 800-30 / FIRST formula. Returns 0
// on unparseable input (consumer falls back to NVD).
func scoreFromVector(vector string) (float64, error) {
	vector = strings.TrimSpace(vector)
	if vector == "" {
		return 0, fmt.Errorf("empty vector")
	}
	if f, err := strconv.ParseFloat(vector, 64); err == nil {
		return f, nil
	}
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, nil
	}
	return cvss3BaseScore(vector), nil
}

// cvss3BaseScore implements the CVSS v3.1 base score formula. Returns 0
// when required metrics are missing.
//
// Reference: https://www.first.org/cvss/v3.1/specification-document § 7.1
func cvss3BaseScore(vector string) float64 {
	metrics := map[string]string{}
	for _, p := range strings.Split(vector, "/") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	scope := metrics["S"]
	prRaw := metrics["PR"]
	prMap := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prMap = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr := prMap[prRaw]
	cMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c := cMap[metrics["C"]]
	i := cMap[metrics["I"]]
	a := cMap[metrics["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 && prRaw != "N" && prRaw != "" {
		// PR=N is legitimate (0.85), but others should map; skip score on missing AV/AC/UI.
	}
	if av == 0 || ac == 0 || ui == 0 {
		return 0
	}
	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploit := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "C" {
		base = roundUp(min(1.08*(impact+exploit), 10))
	} else {
		base = roundUp(min(impact+exploit, 10))
	}
	if base < 0 {
		return 0
	}
	return base
}

func pow(b float64, e int) float64 {
	r := 1.0
	for i := 0; i < e; i++ {
		r *= b
	}
	return r
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// roundUp rounds to one decimal per CVSS spec ("Roundup" function in §7.1).
func roundUp(x float64) float64 {
	intInput := int(x*100000 + 0.5)
	if intInput%10000 == 0 {
		return float64(intInput) / 100000
	}
	return float64((intInput/10000)+1) / 10
}

// parseCVSSv3Level returns none|low|medium|high|critical from a CVSS v3
// vector or score string per the standard score bands.
func parseCVSSv3Level(vector string) string {
	score, _ := scoreFromVector(vector)
	return scoreToLevel(score)
}

// scoreToLevel maps a numeric CVSS-v3 score to a band label.
func scoreToLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// parseRetryAfter parses an HTTP Retry-After header value (seconds or HTTP date).
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}
