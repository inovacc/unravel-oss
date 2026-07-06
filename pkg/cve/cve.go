/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options controls the top-level Client behavior.
type Options struct {
	Online      bool          // false = skip all network, return Status:"skipped"
	NoCache     bool          // bypass cache layer
	MaxInFlight int           // default 8
	HTTPTimeout time.Duration // default 10s
	NVDAPIKey   string        // overrides env

	// CacheRoot overrides the default ($UserCacheDir/unravel/cve). Tests use this.
	CacheRoot string

	// OSVEndpoint and NVDEndpoint override the upstream URLs (test-only seams
	// used by 14-05 integration tests with httptest.Server). When empty, the
	// production endpoints are used. NVDEndpoint is also exercised by the
	// 14-05 wave-3 nvdClient.endpoint field.
	OSVEndpoint string
	NVDEndpoint string
}

// Client orchestrates OSV/NVD/GHSA/grype lookups, caching, and merging.
type Client struct {
	opts  Options
	osv   *osvClient
	nvd   *nvdClient
	ghsa  *ghsaClient
	grype *grypeClient
	cache *cache
}

// NewClient builds a Client from the given options. All fields default sensibly.
func NewClient(opts Options) *Client {
	if opts.HTTPTimeout <= 0 {
		opts.HTTPTimeout = osvDefaultTimeout
	}
	if opts.MaxInFlight <= 0 {
		opts.MaxInFlight = osvDefaultInflight
	}
	c := &Client{opts: opts}
	if opts.Online {
		c.osv = newOSVClient(opts.HTTPTimeout, opts.MaxInFlight)
		c.nvd = newNVDClient(opts.HTTPTimeout, opts.NVDAPIKey)
		c.ghsa = newGHSAClient()
		c.grype = newGrypeClient()
		if opts.OSVEndpoint != "" {
			c.osv.endpoint = opts.OSVEndpoint
		}
		if opts.NVDEndpoint != "" {
			c.nvd.endpoint = opts.NVDEndpoint
		}
	}
	if opts.NoCache {
		c.cache = disabledCache()
	} else if opts.CacheRoot != "" {
		c.cache = newCacheAt(opts.CacheRoot)
	} else {
		c.cache = newCache()
	}
	// Share the cache with the OSV client so per-vuln detail fetches
	// (GET /v1/vulns/{id}) are also cached on disk for 24h.
	if c.osv != nil {
		c.osv.cache = c.cache
	}
	return c
}

// Query enriches the given dependency list. Returns one EnrichedDep per input,
// in the same order. Errors from individual sources are degraded into per-dep
// status fields rather than a top-level error.
func (c *Client) Query(ctx context.Context, deps []DepInput) ([]EnrichedDep, error) {
	out := make([]EnrichedDep, len(deps))
	for i, d := range deps {
		out[i] = EnrichedDep{
			Ecosystem:       d.Ecosystem,
			Package:         d.Name,
			VersionDeclared: d.Version,
			Vulnerabilities: []Vulnerability{},
			Status:          "ok",
		}
	}

	// (1) Offline short-circuit (D-01).
	if !c.opts.Online {
		for i := range out {
			out[i].Status = "skipped"
			out[i].Reason = "offline"
		}
		return out, nil
	}

	// (2) Filter private packages (D-08); collect online deps to query.
	var queryable []DepInput
	queryIdx := make([]int, 0, len(deps))
	for i, d := range deps {
		if d.Private {
			out[i].Status = "skipped"
			out[i].Reason = "private-package"
			continue
		}
		queryable = append(queryable, d)
		queryIdx = append(queryIdx, i)
	}
	if len(queryable) == 0 {
		return out, nil
	}

	// (3) OSV batch query.
	osvRows, err := c.osv.Query(ctx, queryable)
	if err != nil {
		// Hard error from OSV — mark queryable rows as errored, keep going.
		for _, idx := range queryIdx {
			out[idx].Status = "error"
			out[idx].Reason = "osv: " + err.Error()
		}
		return out, nil
	}

	// (3b) OSV per-vuln detail fetch. /v1/querybatch returns only {id, modified}
	// per vuln; severity, database_specific.cwe_ids, and affected[].ranges[]
	// require a second-pass GET /v1/vulns/{id}. We fan out (bounded by the
	// shared semaphore inside fetchVulnDetails) and overlay the full payload
	// onto the minimal batch rows.
	if len(osvRows) > 0 {
		ids := make([]string, 0, len(osvRows))
		for _, ov := range osvRows {
			ids = append(ids, ov.ID)
		}
		details := c.osv.fetchVulnDetails(ctx, ids)
		mergeVulnDetails(osvRows, details)
	}

	// (4) Fan-out NVD + GHSA enrichment per unique CVE id.
	nvdMap := make(map[string]*nvdRecord)
	ghsaMap := make(map[string]*ghsaRecord)
	cveSeen := make(map[string]struct{})
	for _, ov := range osvRows {
		for _, alias := range append([]string{ov.ID}, ov.Aliases...) {
			if !strings.HasPrefix(alias, "CVE-") {
				continue
			}
			if _, ok := cveSeen[alias]; ok {
				continue
			}
			cveSeen[alias] = struct{}{}
			if rec, err := c.nvd.Lookup(ctx, alias); err == nil && rec != nil {
				nvdMap[alias] = rec
			}
			if rec, err := c.ghsa.Lookup(ctx, alias); err == nil && rec != nil {
				ghsaMap[alias] = rec
			}
		}
	}

	// (5) Group OSV rows + grype results back to their input dep, then Merge.
	for ii, idx := range queryIdx {
		dep := queryable[ii]
		var pkgRows []osvVuln
		for _, ov := range osvRows {
			if ov.PkgEcosystem == string(dep.Ecosystem) && ov.PkgName == dep.Name && ov.PkgVersion == dep.Version {
				pkgRows = append(pkgRows, ov)
			}
		}
		var grypeRows []grypeVuln
		// Only invoke grype as offline-fallback if OSV produced zero hits AND
		// grype is installed (the client returns nil when missing).
		if len(pkgRows) == 0 {
			if gv, err := c.grype.Query(ctx, dep); err == nil {
				grypeRows = gv
			}
		}
		merged := Merge(pkgRows, nvdMap, ghsaMap, grypeRows)
		out[idx].Vulnerabilities = merged
	}

	// (6) Latest-version probes (CVE-POL-01). Per-ecosystem probers are
	// registered via blank-import of pkg/cve/registry. We fan-out probes
	// with a bounded semaphore reusing MaxInFlight. Failures are swallowed:
	// VersionLatest stays empty rather than failing the whole Query.
	c.fillLatestVersions(ctx, queryable, queryIdx, out)

	return out, nil
}

// fillLatestVersions probes each queried dep's ecosystem prober and fills
// VersionLatest + OutdatedBy on the matching out entry. Concurrency is
// bounded by c.opts.MaxInFlight. No-op when no prober is registered for an
// ecosystem (e.g. test runs that didn't import pkg/cve/registry).
func (c *Client) fillLatestVersions(ctx context.Context, queryable []DepInput, queryIdx []int, out []EnrichedDep) {
	if len(queryable) == 0 {
		return
	}
	maxInFlight := c.opts.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = osvDefaultInflight
	}
	sem := make(chan struct{}, maxInFlight)
	var wg sync.WaitGroup
	for ii, idx := range queryIdx {
		dep := queryable[ii]
		prober := proberFor(dep.Ecosystem)
		if prober == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, dep DepInput, prober LatestProber) {
			defer wg.Done()
			defer func() { <-sem }()
			latest, err := prober.Latest(ctx, dep.Name)
			if err != nil || latest == "" {
				return
			}
			out[idx].VersionLatest = latest
			if delta := computeVersionDelta(dep.Version, latest); delta != nil {
				out[idx].OutdatedBy = delta
			}
		}(idx, dep, prober)
	}
	wg.Wait()
}

// computeVersionDelta returns the {major,minor,patch} gap between declared
// and latest. Returns nil when either is unparseable (e.g. Go pseudo-versions
// like v0.0.0-20220817201139-bc19a97f63c8) or when there is no positive
// delta — caller leaves OutdatedBy unset in that case.
func computeVersionDelta(declared, latest string) *VersionDelta {
	dMaj, dMin, dPat, ok1 := splitSemverTriplet(declared)
	lMaj, lMin, lPat, ok2 := splitSemverTriplet(latest)
	if !ok1 || !ok2 {
		return nil
	}
	d := &VersionDelta{
		Major: lMaj - dMaj,
		Minor: lMin - dMin,
		Patch: lPat - dPat,
	}
	if d.Major < 0 {
		d.Major = 0
	}
	if d.Minor < 0 {
		d.Minor = 0
	}
	if d.Patch < 0 {
		d.Patch = 0
	}
	if d.Major == 0 && d.Minor == 0 && d.Patch == 0 {
		return nil
	}
	// If major bumped, minor/patch deltas are not meaningful — zero them.
	if d.Major > 0 {
		d.Minor = 0
		d.Patch = 0
	} else if d.Minor > 0 {
		d.Patch = 0
	}
	return d
}

// splitSemverTriplet parses the leading numeric major.minor.patch from v.
// Strips a leading "v". Pseudo-versions ("v0.0.0-yyyymmddhhmmss-hash") and
// other non-semver inputs return ok=false.
func splitSemverTriplet(v string) (maj, min, pat int, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	// Reject pseudo-versions / pre-release / build metadata: pkg-level
	// caller treats those as non-comparable. Returning ok=false makes
	// computeVersionDelta yield nil so OutdatedBy stays unset.
	if strings.ContainsAny(v, "-+") {
		return 0, 0, 0, false
	}
	parts := strings.SplitN(v, ".", 4)
	if len(parts) < 1 || parts[0] == "" {
		return 0, 0, 0, false
	}
	nums := []int{0, 0, 0}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, 0, 0, false
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], true
}
