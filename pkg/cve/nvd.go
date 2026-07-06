/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// nvdEndpoint is the NVD v2.0 CVE lookup endpoint.
// Reference: https://nvd.nist.gov/developers/vulnerabilities (v1 deprecated Sep 2023).
const nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	nvdMaxBackoff     = 5 * time.Minute
	nvdSpacingNoKey   = 6 * time.Second        // 5 req / 30s
	nvdSpacingWithKey = 600 * time.Millisecond // 50 req / 30s
)

// nvdClient is the per-CVE NVD lookup client with rate limiting.
type nvdClient struct {
	http     *http.Client
	apiKey   string
	endpoint string // overridable for tests; defaults to nvdEndpoint
	mu       sync.Mutex
	lastReq  time.Time
}

func newNVDClient(httpTimeout time.Duration, apiKey string) *nvdClient {
	if httpTimeout <= 0 {
		httpTimeout = osvDefaultTimeout
	}
	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}
	return &nvdClient{
		http:     &http.Client{Timeout: httpTimeout},
		apiKey:   apiKey,
		endpoint: nvdEndpoint,
	}
}

// nvdRecord captures the fields we care about from a v2.0 lookup response.
type nvdRecord struct {
	CVEID        string
	CVSSv3Vector string
	CVSSv3Score  float64
	CWE          []string
	References   []string
	Published    time.Time
}

type nvdRespV2 struct {
	Vulnerabilities []struct {
		CVE struct {
			ID         string `json:"id"`
			Published  string `json:"published"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// rateWait enforces the per-key rate budget between calls.
func (c *nvdClient) rateWait(ctx context.Context) error {
	c.mu.Lock()
	spacing := nvdSpacingNoKey
	if c.apiKey != "" {
		spacing = nvdSpacingWithKey
	}
	wait := time.Until(c.lastReq.Add(spacing))
	c.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

// Lookup fetches a single CVE record from NVD v2.0. 404 returns (nil, nil).
func (c *nvdClient) Lookup(ctx context.Context, cveID string) (*nvdRecord, error) {
	if cveID == "" {
		return nil, nil
	}
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = nvdEndpoint
	}
	url := endpoint + "?cveId=" + cveID
	backoff := time.Second
	for {
		if err := c.rateWait(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("nvd: new request: %w", err)
		}
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}
		c.mu.Lock()
		c.lastReq = time.Now()
		c.mu.Unlock()
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("nvd: do: %w", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			_ = resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("nvd: read: %w", err)
			}
			var parsed nvdRespV2
			if err := json.Unmarshal(data, &parsed); err != nil {
				return nil, fmt.Errorf("nvd: decode: %w", err)
			}
			return foldNVDResp(parsed, cveID), nil
		case http.StatusNotFound:
			_ = resp.Body.Close()
			return nil, nil
		case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
			retry := parseRetryAfter(resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
			if retry <= 0 {
				retry = backoff
			}
			if retry > nvdMaxBackoff {
				retry = nvdMaxBackoff
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retry):
			}
			backoff *= 2
			if backoff > nvdMaxBackoff {
				backoff = nvdMaxBackoff
			}
			continue
		default:
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return nil, fmt.Errorf("nvd: status %d: %s", resp.StatusCode, string(b))
		}
	}
}

func foldNVDResp(r nvdRespV2, cveID string) *nvdRecord {
	if len(r.Vulnerabilities) == 0 {
		return nil
	}
	v := r.Vulnerabilities[0].CVE
	rec := &nvdRecord{CVEID: cveID}
	if v.ID != "" {
		rec.CVEID = v.ID
	}
	// CWE: filter "en" descriptions only.
	for _, w := range v.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && d.Value != "" {
				rec.CWE = append(rec.CWE, d.Value)
			}
		}
	}
	// CVSS v3 — prefer 3.1 over 3.0.
	if len(v.Metrics.CVSSMetricV31) > 0 {
		rec.CVSSv3Vector = v.Metrics.CVSSMetricV31[0].CVSSData.VectorString
		rec.CVSSv3Score = v.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	} else if len(v.Metrics.CVSSMetricV30) > 0 {
		rec.CVSSv3Vector = v.Metrics.CVSSMetricV30[0].CVSSData.VectorString
		rec.CVSSv3Score = v.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
	}
	for _, ref := range v.References {
		rec.References = append(rec.References, ref.URL)
	}
	if v.Published != "" {
		if t, err := time.Parse(time.RFC3339, v.Published); err == nil {
			rec.Published = t
		}
	}
	return rec
}
