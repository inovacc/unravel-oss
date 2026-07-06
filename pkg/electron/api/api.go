/*
Copyright (c) 2026 Security Research
*/
package api

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// Finding is a detected API endpoint.
type Finding struct {
	URL     string `json:"url"`
	Purpose string `json:"purpose"`
}

// strictURLRe matches https?:// URLs whose host is composed of lowercase
// alphanumerics, dots, and dashes only and whose path stops at the first
// whitespace, quote, backtick, paren, bracket, brace, semicolon, or comma.
var strictURLRe = regexp.MustCompile(`https?://[a-z0-9.\-]+(?:/[^\s'"` + "`" + `)\];,}<>]*)?`)

func trimTrailing(u string) string {
	return strings.TrimRight(u, "'\"`)];,.\n\r\t ")
}

func dedupKey(scheme, host, path string) string {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return scheme + "://" + strings.ToLower(host) + "/" + strings.Join(segs, "/")
}

// Find searches content for API endpoints. Post BUG-07 fix: strict regex,
// denylist filter, dedup by (scheme,host,2-segment path), purpose classify.
func Find(content string, urlPattern manifest.URLPattern, classifications []manifest.Classification) []Finding {
	return FindWithBrand(content, urlPattern, classifications, nil)
}

// FindWithBrand applies a per-app brand allowlist that overrides denylist.
func FindWithBrand(content string, urlPattern manifest.URLPattern, classifications []manifest.Classification, brands []string) []Finding {
	var findings []Finding

	matches := strictURLRe.FindAllString(content, -1)
	seen := make(map[string]bool)

	brandLower := make([]string, 0, len(brands))
	for _, b := range brands {
		b = strings.TrimSpace(strings.ToLower(b))
		if b != "" {
			brandLower = append(brandLower, b)
		}
	}

	for _, raw := range matches {
		u := trimTrailing(raw)
		if u == "" || strings.Contains(u, "$") {
			continue
		}
		if u == "https://" || u == "http://" {
			continue
		}

		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			continue
		}
		host := parsed.Host
		hostLower := strings.ToLower(host)
		// Reject obvious junk: hosts with no dot ("localhost", "unix", "12345"),
		// hosts whose final label is < 2 chars (e.g. "f.a.k").
		if !strings.Contains(host, ".") {
			continue
		}
		if isJunkHost(host) {
			continue
		}

		brandHit := false
		for _, b := range brandLower {
			if strings.Contains(hostLower, b) {
				brandHit = true
				break
			}
		}

		if !brandHit && denyHost(host) {
			continue
		}

		excluded := false
		for _, ex := range urlPattern.Exclude {
			if ex == "" {
				continue
			}
			if strings.Contains(strings.ToLower(u), strings.ToLower(ex)) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		key := dedupKey(parsed.Scheme, host, parsed.Path)
		if seen[key] {
			continue
		}
		seen[key] = true

		purpose := string(classifyPurpose(parsed.Scheme, host, parsed.Path))
		// Brand-fallback: if host contains a brand token and no rule matched,
		// treat as PurposeAPI (the app's own brand domain).
		if purpose == string(PurposeUnknown) && brandHit {
			purpose = string(PurposeAPI)
		}
		if purpose == string(PurposeUnknown) {
			urlLower := strings.ToLower(u)
			for _, c := range classifications {
				matched := false
				for _, kw := range c.Keywords {
					if strings.Contains(urlLower, strings.ToLower(kw)) {
						purpose = c.Purpose
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if purpose == "" || purpose == string(PurposeUnknown) {
				purpose = "Unknown"
			}
		}

		findings = append(findings, Finding{URL: u, Purpose: purpose})
	}

	return findings
}
