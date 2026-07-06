/*
Copyright (c) 2026 Security Research
*/
package pydeps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// latestProber wraps LatestVersion for the cve.LatestProber registry.
type latestProber struct{}

func (latestProber) Ecosystem() cve.Ecosystem { return cve.EcosystemPyPI }
func (latestProber) Latest(ctx context.Context, pkg string) (string, error) {
	return LatestVersion(ctx, pkg)
}

func init() { cve.RegisterLatestProber(latestProber{}) }

// pypiBaseURL is overridable for tests.
var pypiBaseURL = "https://pypi.org/pypi"

// pypiResponse is the minimal slice of PyPI's JSON API we care about.
type pypiResponse struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Releases map[string]any `json:"releases"`
}

// preReleaseRe matches a release tag containing PEP 440 pre-release
// markers: 1.0a1, 2.0b3, 3.0rc1, 4.0.dev2, 1.0.post1 (post is post-release;
// excluded from "latest" too here since it's not a typical user-facing
// release).
var preReleaseRe = regexp.MustCompile(`(?i)(a|b|c|rc|dev|alpha|beta|pre|preview)\d*\b`)

// LatestVersion returns the latest non-pre-release version for a PyPI
// package via:
//
//	GET https://pypi.org/pypi/<pkg>/json
//
// info.version is preferred when it is itself non-pre; otherwise the
// max stable from releases keys is selected via lexical fallback.
func LatestVersion(ctx context.Context, pkg string) (string, error) {
	if pkg == "" {
		return "", fmt.Errorf("pydeps: empty package name")
	}
	url := fmt.Sprintf("%s/%s/json", strings.TrimRight(pypiBaseURL, "/"), pkg)
	body, err := pyHTTPGet(ctx, url, 3)
	if err != nil {
		return "", err
	}
	var r pypiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("pydeps: decode pypi response: %w", err)
	}
	if r.Info.Version != "" && !isPreRelease(r.Info.Version) {
		return r.Info.Version, nil
	}
	// Fallback: pick the lexically largest stable release key.
	var best string
	for v := range r.Releases {
		if isPreRelease(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	if best == "" {
		// All known releases are pre-releases; return info.version regardless
		// so caller still gets *something*.
		return r.Info.Version, nil
	}
	return best, nil
}

// isPreRelease returns true for PEP 440 pre / dev / post / rc tags.
func isPreRelease(v string) bool {
	return preReleaseRe.MatchString(v)
}

func pyHTTPGet(ctx context.Context, url string, retries int) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	backoff := 500 * time.Millisecond
	for i := range retries {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("pydeps: build request: %w", err)
		}
		req.Header.Set("User-Agent", "unravel-cve/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if rerr == nil && resp.StatusCode == http.StatusOK {
				return body, nil
			}
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("pydeps: 404 from %s", url)
			}
			lastErr = fmt.Errorf("pydeps: http %d from %s", resp.StatusCode, url)
		}
		if i+1 < retries {
			j := time.Duration(rand.Int63n(int64(backoff / 4))) //nolint:gosec // G404 -- retry-backoff jitter only; not security-sensitive, no crypto strength required
			sleep := min(backoff+j, 30*time.Second)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(sleep):
			}
			backoff *= 2
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("pydeps: exhausted retries")
	}
	return nil, lastErr
}
