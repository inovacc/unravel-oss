/*
Copyright (c) 2026 Security Research
*/
package godeps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/module"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// latestProber wraps LatestVersion for the cve.LatestProber registry.
type latestProber struct{}

func (latestProber) Ecosystem() cve.Ecosystem { return cve.EcosystemGo }
func (latestProber) Latest(ctx context.Context, pkg string) (string, error) {
	return LatestVersion(ctx, pkg)
}

func init() { cve.RegisterLatestProber(latestProber{}) }

// proxyBaseURL is overridable for tests.
var proxyBaseURL = "https://proxy.golang.org"

// LatestVersion returns the latest tagged version for a Go module via the
// Go module proxy protocol:
//
//	GET https://proxy.golang.org/<escaped-module>/@latest
//	-> {"Version":"v1.2.3","Time":"..."}
//
// Module path case is encoded with `!` per the proxy spec; we use
// module.EscapePath to get correct case escaping.
//
// Returned version has the leading "v" stripped to match the canonical
// form used elsewhere in cve.EnrichedDep.VersionLatest.
func LatestVersion(ctx context.Context, modulePath string) (string, error) {
	if modulePath == "" {
		return "", fmt.Errorf("godeps: empty module path")
	}
	escaped, err := module.EscapePath(modulePath)
	if err != nil {
		return "", fmt.Errorf("godeps: escape %q: %w", modulePath, err)
	}
	url := fmt.Sprintf("%s/%s/@latest", strings.TrimRight(proxyBaseURL, "/"), escaped)

	body, err := httpGetWithRetry(ctx, url, 3)
	if err != nil {
		return "", err
	}
	var info struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("godeps: decode @latest: %w", err)
	}
	return strings.TrimPrefix(info.Version, "v"), nil
}

// httpGetWithRetry performs a GET with exponential backoff up to 30s.
// Used by both godeps and pydeps; kept package-local to avoid coupling.
func httpGetWithRetry(ctx context.Context, url string, retries int) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	backoff := 500 * time.Millisecond
	for i := range retries {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("godeps: build request: %w", err)
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
				return nil, fmt.Errorf("godeps: 404 from %s", url)
			}
			lastErr = fmt.Errorf("godeps: http %d from %s", resp.StatusCode, url)
		}
		if i+1 < retries {
			// jitter to avoid thundering herd
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
		lastErr = fmt.Errorf("godeps: exhausted retries")
	}
	return nil, lastErr
}
