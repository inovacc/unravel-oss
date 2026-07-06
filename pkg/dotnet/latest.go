/*
Copyright (c) 2026 Security Research
*/
package dotnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// latestProber wraps LatestVersion for the cve.LatestProber registry.
type latestProber struct{}

func (latestProber) Ecosystem() cve.Ecosystem { return cve.EcosystemNuGet }
func (latestProber) Latest(ctx context.Context, pkg string) (string, error) {
	return LatestVersion(ctx, pkg)
}

func init() { cve.RegisterLatestProber(latestProber{}) }

// nugetFlatContainerEndpoint is the canonical NuGet v3 flat-container service
// root. The full URL is /<lowercased-id>/index.json which returns
// {"versions":[...]}.
const nugetFlatContainerEndpoint = "https://api.nuget.org/v3-flatcontainer"

// LatestVersion returns the highest stable (non pre-release) semver string
// listed by NuGet's flat-container service for pkg. Pre-release versions
// (anything containing a '-') are filtered. Returns "" + nil err when the
// package is unknown (404). Same retry posture as pkg/npm.LatestVersion:
// 3 attempts, 10s timeout, exponential backoff capped at 30s.
func LatestVersion(ctx context.Context, pkg string) (string, error) {
	return latestVersionFrom(ctx, nugetFlatContainerEndpoint, pkg)
}

func latestVersionFrom(ctx context.Context, base, pkg string) (string, error) {
	if pkg == "" {
		return "", errors.New("LatestVersion: pkg required")
	}
	target := strings.TrimRight(base, "/") + "/" + strings.ToLower(pkg) + "/index.json"

	const maxAttempts = 3
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	var lastErr error
	for range maxAttempts {
		versions, retry, err := singleNuGetAttempt(ctx, target)
		if err == nil {
			return maxStableSemver(versions), nil
		}
		lastErr = err
		if !retry {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return "", lastErr
}

// singleNuGetAttempt returns (versions, retry, err).
func singleNuGetAttempt(ctx context.Context, target string) ([]string, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false, fmt.Errorf("nuget latest: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "github.com/inovacc/unravel-oss/1.0 (+https://github.com/dyammarcano/unravel)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("nuget latest: GET %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode >= 500 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, true, fmt.Errorf("nuget latest: %d %s", resp.StatusCode, resp.Status)
	}
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, false, fmt.Errorf("nuget latest: %d %s", resp.StatusCode, resp.Status)
	}

	var doc struct {
		Versions []string `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, false, fmt.Errorf("nuget latest: decode: %w", err)
	}
	return doc.Versions, false, nil
}

// maxStableSemver returns the highest stable (non pre-release) version from
// the input list. Pre-releases (anything with '-') are ignored. Comparison
// is on numeric major.minor.patch components; non-numeric segments compare
// lexicographically as a fallback.
func maxStableSemver(versions []string) string {
	var best string
	for _, v := range versions {
		if v == "" {
			continue
		}
		if strings.Contains(v, "-") {
			// pre-release per SemVer
			continue
		}
		if best == "" || semverLess(best, v) {
			best = v
		}
	}
	return best
}

// semverLess returns true when a < b using numeric-major.minor.patch
// comparison. Trailing components default to 0.
func semverLess(a, b string) bool {
	pa := splitSemverNums(a)
	pb := splitSemverNums(b)
	for i := range 3 {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			return va < vb
		}
	}
	// fall back to lexicographic on the original strings
	return a < b
}

func splitSemverNums(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// stop at first non-numeric part (shouldn't happen since we filter
		// pre-releases, but be safe).
		if p == "" {
			out = append(out, 0)
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}
