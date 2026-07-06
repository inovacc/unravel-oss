package snapshot

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestCategorizeURL(t *testing.T) {
	tests := []struct {
		rawURL   string
		expected string
	}{
		{"https://cdn.example.com/lib.js", "cdn"},
		{"https://static.example.com/img.png", "cdn"},
		{"https://example.com/styles.css", "cdn"},
		{"https://example.com/icon.svg", "cdn"},
		{"https://example.com/font.woff", "cdn"},
		{"https://analytics.example.com/track", "tracking"},
		{"https://tracking.example.com/pixel", "tracking"},
		{"https://metrics.example.com/v1", "tracking"},
		{"https://mixpanel.example.com/track", "tracking"},
		{"https://hotjar.example.com/rec", "tracking"},
		{"https://example.com/api/v1/users", "api"},
		{"https://example.com/v2/products", "api"},
		{"https://example.com/graphql", "api"},
		{"https://example.com/rest/data", "api"},
		{"https://example.com/config/settings.json", "config"},
		{"https://example.com/settings", "config"},
		{"https://example.com/iframe/widget", "iframe"},
		{"https://example.com/embed/player", "iframe"},
		{"https://example.com/widget/show", "iframe"},
		{"https://example.com/page", "other"},
		{"https://example.com/", "other"},
	}

	for _, tc := range tests {
		t.Run(tc.rawURL, func(t *testing.T) {
			parsed, _ := url.Parse(tc.rawURL)
			got := categorizeURL(parsed)
			if got != tc.expected {
				t.Errorf("categorizeURL(%s) = %q, want %q", tc.rawURL, got, tc.expected)
			}
		})
	}
}

func TestExtractURLsFromExtension(t *testing.T) {
	dir := t.TempDir()

	// Create a JS file with URLs
	jsContent := `
		fetch("https://api.myservice.com/v1/data");
		const img = "https://cdn.myservice.com/logo.png";
		const noise = "https://www.w3.org/2000/svg"; // should be filtered
	`
	if err := os.WriteFile(filepath.Join(dir, "content.js"), []byte(jsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create manifest with host_permissions
	manifest := `{
		"name": "Test",
		"host_permissions": ["*://api.custom-backend.com/*"],
		"content_security_policy": {
			"extension_pages": "connect-src https://ws.myservice.com https://api2.myservice.com"
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractURLsFromExtension("test-ext", dir)
	if err != nil {
		t.Fatalf("ExtractURLsFromExtension: %v", err)
	}

	if result.ExtensionID != "test-ext" {
		t.Errorf("ExtensionID = %q", result.ExtensionID)
	}

	// Should have URLs from JS + manifest host_permissions + CSP
	urlMap := make(map[string]SourceURL)
	for _, u := range result.URLs {
		urlMap[u.URL] = u
	}

	// JS regex URLs
	if _, ok := urlMap["https://api.myservice.com/v1/data"]; !ok {
		t.Error("missing api.myservice.com URL from JS")
	}
	if _, ok := urlMap["https://cdn.myservice.com/logo.png"]; !ok {
		t.Error("missing cdn.myservice.com URL from JS")
	}

	// Noise should be filtered
	for _, u := range result.URLs {
		if u.Host == "www.w3.org" {
			t.Error("noise domain www.w3.org was not filtered")
		}
	}

	// Host permissions
	found := false
	for _, u := range result.URLs {
		if u.SourceType == "host_permission" && u.Host == "api.custom-backend.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing host_permission URL")
	}

	// CSP connect-src
	cspFound := 0
	for _, u := range result.URLs {
		if u.SourceType == "csp_connect" {
			cspFound++
		}
	}
	if cspFound != 2 {
		t.Errorf("expected 2 CSP URLs, got %d", cspFound)
	}
}

func TestExtractURLsFromExtension_SkipsDotDirs(t *testing.T) {
	dir := t.TempDir()

	// Create .git directory with a JS file — should be skipped
	gitDir := filepath.Join(dir, ".git")
	_ = os.MkdirAll(gitDir, 0o755)
	_ = os.WriteFile(filepath.Join(gitDir, "config.js"), []byte(`fetch("https://shouldbeskipped.com/api")`), 0o644)

	// node_modules should also be skipped
	nmDir := filepath.Join(dir, "node_modules")
	_ = os.MkdirAll(nmDir, 0o755)
	_ = os.WriteFile(filepath.Join(nmDir, "lib.js"), []byte(`fetch("https://alsoSkipped.com/api")`), 0o644)

	result, err := ExtractURLsFromExtension("test", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range result.URLs {
		if u.Host == "shouldbeskipped.com" || u.Host == "alsoskipped.com" {
			t.Errorf("URL from skipped directory was included: %s", u.URL)
		}
	}
}

func TestExtractURLsFromExtension_SkipsNonCodeFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "image.png"), []byte(`https://hidden-in-binary.com/api`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data.xml"), []byte(`https://hidden-in-xml.com/api`), 0o644)

	result, err := ExtractURLsFromExtension("test", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.URLs) != 0 {
		t.Errorf("expected 0 URLs from non-code files, got %d", len(result.URLs))
	}
}

func TestExtractURLsFromExtension_Dedup(t *testing.T) {
	dir := t.TempDir()
	js := `fetch("https://api.dedup-test.com/v1"); fetch("https://api.dedup-test.com/v1");`
	_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte(js), 0o644)

	result, err := ExtractURLsFromExtension("test", dir)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, u := range result.URLs {
		if u.URL == "https://api.dedup-test.com/v1" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduped URL, got %d", count)
	}
}

func TestExtractManifestURLs_V2CSPString(t *testing.T) {
	dir := t.TempDir()
	manifest := `{
		"name": "Test",
		"content_security_policy": "connect-src https://backend.test.com"
	}`
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644)

	result, err := ExtractURLsFromExtension("test", dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, u := range result.URLs {
		if u.SourceType == "csp_connect" && u.Host == "backend.test.com" {
			found = true
		}
	}
	if !found {
		t.Error("missing CSP URL from v2 string format")
	}
}

func TestExtractManifestURLs_WildcardPermission(t *testing.T) {
	dir := t.TempDir()
	manifest := `{
		"name": "Test",
		"permissions": ["*://*.wildcard-api.com/*"]
	}`
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644)

	result, err := ExtractURLsFromExtension("test", dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, u := range result.URLs {
		if u.SourceType == "host_permission" {
			found = true
		}
	}
	if !found {
		t.Error("missing wildcard permission URL")
	}
}

func TestExtractURLsFromExtension_HTMLFiles(t *testing.T) {
	dir := t.TempDir()
	html := `<script src="https://myapi.special-domain.com/v1/init.js"></script>`
	_ = os.WriteFile(filepath.Join(dir, "popup.html"), []byte(html), 0o644)

	result, err := ExtractURLsFromExtension("test", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.URLs) == 0 {
		t.Error("expected URLs from HTML file")
	}
}
