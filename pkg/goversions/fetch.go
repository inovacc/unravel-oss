package goversions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const userAgent = "unravel-goversions/1"

// HTTPSources is the live Sources implementation. Base URLs are injectable for tests.
type HTTPSources struct {
	Client   *http.Client
	DLBase   string // https://go.dev
	VulnBase string // https://vuln.go.dev
	DocBase  string // https://go.dev
}

// NewHTTPSources returns sources pointed at the real go.dev endpoints.
func NewHTTPSources() *HTTPSources {
	return &HTTPSources{
		Client:   &http.Client{Timeout: 30 * time.Second},
		DLBase:   "https://go.dev",
		VulnBase: "https://vuln.go.dev",
		DocBase:  "https://go.dev",
	}
}

func (s *HTTPSources) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB cap
}

// Downloads fetches and parses go.dev/dl?mode=json&include=all.
func (s *HTTPSources) Downloads(ctx context.Context) ([]Release, error) {
	b, err := s.get(ctx, s.DLBase+"/dl/?mode=json&include=all")
	if err != nil {
		return nil, err
	}
	return ParseDownloads(b)
}

// ReleaseMeta fetches and parses the release-history page.
func (s *HTTPSources) ReleaseMeta(ctx context.Context) (map[string]ReleaseMeta, error) {
	b, err := s.get(ctx, s.DocBase+"/doc/devel/release")
	if err != nil {
		return nil, err
	}
	return ParseReleaseHistory(b), nil
}

// Vulns fetches the vuln.go.dev modules index, then fetches each stdlib/toolchain entry.
func (s *HTTPSources) Vulns(ctx context.Context) ([]Vuln, error) {
	b, err := s.get(ctx, s.VulnBase+"/index/modules.json")
	if err != nil {
		return nil, err
	}
	var mods []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(b, &mods); err != nil {
		return nil, fmt.Errorf("parse modules.json: %w", err)
	}
	ids := map[string]bool{}
	for _, m := range mods {
		if m.Path == "stdlib" || m.Path == "toolchain" {
			for _, v := range m.Vulns {
				ids[v.ID] = true
			}
		}
	}
	var out []Vuln
	for id := range ids {
		ob, err := s.get(ctx, s.VulnBase+"/ID/"+id+".json")
		if err != nil {
			continue // skip a single bad entry, keep going
		}
		v, err := ParseOSV(ob)
		if err == nil && len(v.Affected) > 0 {
			out = append(out, v)
		}
	}
	return out, nil
}
