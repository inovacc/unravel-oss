/*
Copyright (c) 2026 Security Research
*/
package npm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// latestProber wraps LatestVersion for the cve.LatestProber registry.
type latestProber struct{}

func (latestProber) Ecosystem() cve.Ecosystem { return cve.EcosystemNPM }
func (latestProber) Latest(ctx context.Context, pkg string) (string, error) {
	return LatestVersion(ctx, pkg)
}

func init() { cve.RegisterLatestProber(latestProber{}) }

// npmLatestEndpoint is the canonical npm "latest dist-tag" endpoint. Hitting
// /<pkg>/latest returns a single doc {"version":"x.y.z", ...} so the body is
// tiny.
const npmLatestEndpoint = "https://registry.npmjs.org"

// LatestVersion probes registry.npmjs.org/<pkg>/latest and returns the
// semver string. Honors the supplied context and applies a 10s per-attempt
// timeout, retrying up to 3 times on 5xx with exponential backoff capped at
// 30s. 404 returns an empty string + nil error so callers treat unknown
// packages as "no upstream version known" rather than fatal.
func LatestVersion(ctx context.Context, pkg string) (string, error) {
	return latestVersionFrom(ctx, npmLatestEndpoint, pkg)
}

// latestVersionFrom is the test seam — production callers use LatestVersion
// which pins the npm registry URL.
func latestVersionFrom(ctx context.Context, base, pkg string) (string, error) {
	if pkg == "" {
		return "", errors.New("LatestVersion: pkg required")
	}
	// PathEscape on each segment so scoped names (@scope/pkg) round-trip.
	escaped := pkg
	if strings.HasPrefix(pkg, "@") && strings.Contains(pkg, "/") {
		// scoped: @scope/name → %40scope/name (npm wants the slash literal)
		idx := strings.Index(pkg, "/")
		escaped = url.PathEscape(pkg[:idx]) + "/" + url.PathEscape(pkg[idx+1:])
	} else {
		escaped = url.PathEscape(pkg)
	}
	target := strings.TrimRight(base, "/") + "/" + escaped + "/latest"

	const maxAttempts = 3
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	var lastErr error
	for range maxAttempts {
		ver, retry, err := singleNPMLatestAttempt(ctx, target)
		if err == nil {
			return ver, nil
		}
		lastErr = err
		if !retry {
			return "", err
		}
		// sleep with backoff capped at maxBackoff
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

// singleNPMLatestAttempt returns (version, retry, err). retry=true means the
// caller may re-issue the request after a backoff (5xx, transient transport).
func singleNPMLatestAttempt(ctx context.Context, target string) (string, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return "", false, fmt.Errorf("npm latest: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "github.com/inovacc/unravel-oss/1.0 (+https://github.com/dyammarcano/unravel)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// transport error — retryable
		return "", true, fmt.Errorf("npm latest: GET %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// unknown package — not retryable, not fatal
		return "", false, nil
	}
	if resp.StatusCode >= 500 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", true, fmt.Errorf("npm latest: %d %s", resp.StatusCode, resp.Status)
	}
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", false, fmt.Errorf("npm latest: %d %s", resp.StatusCode, resp.Status)
	}

	var doc struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", false, fmt.Errorf("npm latest: decode: %w", err)
	}
	return doc.Version, false, nil
}
