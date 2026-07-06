/*
Copyright © 2026 Security Research
*/
package snapshot

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ExtractedURLs holds categorized URLs found in extension source files.
type ExtractedURLs struct {
	ExtensionID string
	URLs        []SourceURL
}

var urlRegex = regexp.MustCompile(`https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`)

// noiseDomains are domains to skip during extraction (common infrastructure, not extension-specific).
var noiseDomains = map[string]bool{
	"www.w3.org": true, "w3.org": true, "schemas.xmlsoap.org": true,
	"www.google.com": true, "google.com": true,
	"fonts.googleapis.com": true, "fonts.gstatic.com": true, "www.gstatic.com": true,
	"apis.google.com": true, "www.googleapis.com": true, "ajax.googleapis.com": true,
	"accounts.google.com": true, "ssl.gstatic.com": true,
	"www.facebook.com": true, "facebook.com": true,
	"connect.facebook.net": true, "graph.facebook.com": true,
	"twitter.com": true, "platform.twitter.com": true,
	"cdn.jsdelivr.net": true, "cdnjs.cloudflare.com": true, "unpkg.com": true,
	"github.com": true, "raw.githubusercontent.com": true,
	"chrome.google.com": true, "clients2.google.com": true,
	"update.googleapis.com": true, "developer.chrome.com": true,
	"chromium.org": true, "creativecommons.org": true, "opensource.org": true,
	"mozilla.org": true, "developer.mozilla.org": true,
	"localhost": true, "127.0.0.1": true,
	"example.com": true, "www.example.com": true,
	"schema.org": true, "www.schema.org": true,
	"jquery.com": true, "code.jquery.com": true,
	"reactjs.org": true, "vuejs.org": true, "angular.io": true,
	"nodejs.org": true, "npmjs.com": true, "www.npmjs.com": true, "registry.npmjs.org": true,
	"sentry.io": true, "bugsnag.com": true,
}

func categorizeURL(u *url.URL) string {
	host := u.Host
	path := u.Path

	switch {
	case strings.Contains(host, "cdn") || strings.Contains(host, "static") ||
		strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") ||
		strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".woff"):
		return "cdn"
	case strings.Contains(host, "analytics") || strings.Contains(host, "tracking") ||
		strings.Contains(host, "pixel") || strings.Contains(host, "metrics") ||
		strings.Contains(host, "telemetry") || strings.Contains(host, "segment") ||
		strings.Contains(host, "mixpanel") || strings.Contains(host, "amplitude") ||
		strings.Contains(host, "hotjar") || strings.Contains(host, "fullstory"):
		return "tracking"
	case strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") || strings.Contains(path, "/v3/") ||
		strings.Contains(path, "/graphql") || strings.Contains(path, "/rest/"):
		return "api"
	case strings.Contains(path, "/config") || strings.HasSuffix(path, ".json") ||
		strings.Contains(path, "/settings"):
		return "config"
	case strings.Contains(path, "/iframe") || strings.Contains(path, "/embed") ||
		strings.Contains(path, "/widget"):
		return "iframe"
	default:
		return "other"
	}
}

// ExtractURLsFromExtension scans extension source files for URLs.
func ExtractURLsFromExtension(extID, extDir string) (*ExtractedURLs, error) {
	result := &ExtractedURLs{ExtensionID: extID}
	seen := make(map[string]bool)

	err := filepath.Walk(extDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".json" && ext != ".html" && ext != ".htm" && ext != ".css" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(extDir, path)
		matches := urlRegex.FindAllString(string(data), -1)

		for _, raw := range matches {
			raw = strings.TrimRight(raw, `"');,>}]\`)
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Host == "" {
				continue
			}

			host := strings.ToLower(parsed.Host)
			if noiseDomains[host] {
				continue
			}

			sourceType := "regex"
			category := categorizeURL(parsed)
			key := raw + "|" + sourceType
			if seen[key] {
				continue
			}
			seen[key] = true

			result.URLs = append(result.URLs, SourceURL{
				ExtensionID: extID,
				URL:         raw,
				Host:        host,
				Category:    category,
				SourceFile:  relPath,
				SourceType:  sourceType,
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk extension dir: %w", err)
	}

	manifestPath := filepath.Join(extDir, "manifest.json")
	manifestData, err := readManifestBounded(manifestPath)
	if err == nil {
		extractManifestURLs(extID, manifestData, result, seen)
	}

	slog.Info("extracted URLs from extension", "ext", extID, "total", len(result.URLs))

	return result, nil
}

func extractManifestURLs(extID string, data []byte, result *ExtractedURLs, seen map[string]bool) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}

	for _, field := range []string{"host_permissions", "permissions"} {
		if perms, ok := m[field].([]any); ok {
			for _, p := range perms {
				s, ok := p.(string)
				if !ok || !strings.Contains(s, "://") {
					continue
				}
				s = strings.Replace(s, "*://", "https://", 1)
				s = strings.Replace(s, "/*", "/", 1)
				s = strings.TrimRight(s, "*")
				parsed, err := url.Parse(s)
				if err != nil || parsed.Host == "" {
					continue
				}
				host := strings.TrimPrefix(strings.ToLower(parsed.Host), "*.")
				if noiseDomains[host] {
					continue
				}
				key := s + "|host_permission"
				if seen[key] {
					continue
				}
				seen[key] = true
				result.URLs = append(result.URLs, SourceURL{
					ExtensionID: extID,
					URL:         s,
					Host:        host,
					Category:    "api",
					SourceFile:  "manifest.json",
					SourceType:  "host_permission",
				})
			}
		}
	}

	if csp, ok := m["content_security_policy"].(string); ok {
		extractCSPURLs(extID, csp, result, seen)
	}
	if cspObj, ok := m["content_security_policy"].(map[string]any); ok {
		for _, v := range cspObj {
			if s, ok := v.(string); ok {
				extractCSPURLs(extID, s, result, seen)
			}
		}
	}
}

func extractCSPURLs(extID, csp string, result *ExtractedURLs, seen map[string]bool) {
	for directive := range strings.SplitSeq(csp, ";") {
		directive = strings.TrimSpace(directive)
		if !strings.HasPrefix(directive, "connect-src") {
			continue
		}
		for _, token := range strings.Fields(directive)[1:] {
			if !strings.HasPrefix(token, "http") {
				continue
			}
			parsed, err := url.Parse(token)
			if err != nil || parsed.Host == "" {
				continue
			}
			host := strings.ToLower(parsed.Host)
			if noiseDomains[host] {
				continue
			}
			key := token + "|csp_connect"
			if seen[key] {
				continue
			}
			seen[key] = true
			result.URLs = append(result.URLs, SourceURL{
				ExtensionID: extID,
				URL:         token,
				Host:        host,
				Category:    "api",
				SourceFile:  "manifest.json",
				SourceType:  "csp_connect",
			})
		}
	}
}
