package snapshot

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHAREntries(t *testing.T) {
	har := map[string]any{
		"log": map[string]any{
			"entries": []any{
				map[string]any{
					"request":  map[string]any{"method": "GET", "url": "https://api.example.com/v1/data"},
					"response": map[string]any{"status": 200, "content": map[string]any{"size": 1024, "mimeType": "application/json"}},
				},
				map[string]any{
					"request":  map[string]any{"method": "POST", "url": "https://tracking.example.com/pixel"},
					"response": map[string]any{"status": 204, "content": map[string]any{"size": 0, "mimeType": ""}},
				},
			},
		},
	}
	data, _ := json.Marshal(har)
	entries, err := parseHAREntries(data)
	if err != nil {
		t.Fatalf("parseHAREntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Method != "GET" || entries[0].URL != "https://api.example.com/v1/data" {
		t.Errorf("entry[0] = %+v", entries[0])
	}
	if entries[1].Status != 204 {
		t.Errorf("entry[1].Status = %d", entries[1].Status)
	}
}

func TestParseHAREntries_Empty(t *testing.T) {
	data := []byte(`{"log":{"entries":[]}}`)
	entries, err := parseHAREntries(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0, got %d", len(entries))
	}
}

func TestParseHAREntries_InvalidJSON(t *testing.T) {
	_, err := parseHAREntries([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMatchURLs(t *testing.T) {
	tests := []struct {
		name     string
		src, har string
		want     string
	}{
		{"exact", "https://api.test.com/v1/data?key=123", "https://api.test.com/v1/data?key=123", "exact"},
		{"host_path", "https://api.test.com/v1", "https://api.test.com/v1/data", "host_path"},
		{"host_only", "https://api.test.com/", "https://api.test.com/anything", "host_only"},
		{"host_only_empty_path", "https://api.test.com", "https://api.test.com/foo", "host_only"},
		{"no_match", "https://api.test.com/v2/users", "https://api.test.com/v1/data", ""},
		{"different_query", "https://api.test.com/v1/data?a=1", "https://api.test.com/v1/data?b=2", "host_path"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srcU, _ := url.Parse(tc.src)
			harU, _ := url.Parse(tc.har)
			got := matchURLs(srcU, harU)
			if got != tc.want {
				t.Errorf("matchURLs(%s, %s) = %q, want %q", tc.src, tc.har, got, tc.want)
			}
		})
	}
}

func TestMapURLs(t *testing.T) {
	sourceURLs := &ExtractedURLs{
		ExtensionID: "ext1",
		URLs: []SourceURL{
			{ExtensionID: "ext1", URL: "https://api.honey.io/v1/coupons", Host: "api.honey.io", Category: "api", SourceType: "regex"},
			{ExtensionID: "ext1", URL: "https://unmatched.com/api", Host: "unmatched.com", Category: "api", SourceType: "regex"},
		},
	}
	harEntries := []harEntry{
		{Method: "GET", URL: "https://api.honey.io/v1/coupons?store=amazon", Status: 200, ContentType: "application/json", ResponseSize: 2048},
		{Method: "GET", URL: "https://cdn.amazon.com/images/logo.png", Status: 200},
	}

	mappings := mapURLs("ext1", 1, sourceURLs, harEntries)
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	m := mappings[0]
	if m.SourceURL != "https://api.honey.io/v1/coupons" {
		t.Errorf("SourceURL = %s", m.SourceURL)
	}
	if m.HARURL != "https://api.honey.io/v1/coupons?store=amazon" {
		t.Errorf("HARURL = %s", m.HARURL)
	}
	if m.MatchType != "host_path" {
		t.Errorf("MatchType = %s", m.MatchType)
	}
}

func TestMapURLs_SubdomainMatch(t *testing.T) {
	sourceURLs := &ExtractedURLs{
		ExtensionID: "ext1",
		URLs: []SourceURL{
			{ExtensionID: "ext1", URL: "https://honey.io/", Host: "honey.io", Category: "api", SourceType: "regex"},
		},
	}
	harEntries := []harEntry{
		{Method: "GET", URL: "https://api.honey.io/v1/check", Status: 200},
	}

	mappings := mapURLs("ext1", 1, sourceURLs, harEntries)
	if len(mappings) != 1 {
		t.Fatalf("expected subdomain match, got %d mappings", len(mappings))
	}
	if mappings[0].MatchType != "host_only" {
		t.Errorf("expected host_only, got %s", mappings[0].MatchType)
	}
}

func TestMapURLs_Empty(t *testing.T) {
	mappings := mapURLs("ext1", 1, &ExtractedURLs{}, nil)
	if len(mappings) != 0 {
		t.Errorf("expected 0 mappings, got %d", len(mappings))
	}
}

func TestLoadCSV(t *testing.T) {
	csvContent := "Extension Name,Chrome Web Store Link\nHoney,https://chrome.google.com/webstore/detail/honey/bmnlcjabgnpnenekpadlanbbkooimhnj\nKeepa,https://chrome.google.com/webstore/detail/keepa/neebplgakaahbhdphmkckjjcegoiijjo\n"
	csvPath := filepath.Join(t.TempDir(), "extensions.csv")
	if err := os.WriteFile(csvPath, []byte(csvContent), 0o644); err != nil {
		t.Fatal(err)
	}

	exts, err := LoadCSV(csvPath)
	if err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}
	if exts[0].Name != "Honey" {
		t.Errorf("name = %q", exts[0].Name)
	}
	if exts[0].ID != "bmnlcjabgnpnenekpadlanbbkooimhnj" {
		t.Errorf("id = %q", exts[0].ID)
	}
}

func TestLoadCSV_NotFound(t *testing.T) {
	_, err := LoadCSV("/nonexistent/file.csv")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadCSV_ShortRows(t *testing.T) {
	// CSV with inconsistent field count returns parse error
	csvContent := "Name,Link\nOnlyName\n"
	csvPath := filepath.Join(t.TempDir(), "ext.csv")
	_ = os.WriteFile(csvPath, []byte(csvContent), 0o644)

	_, err := LoadCSV(csvPath)
	if err == nil {
		t.Fatal("expected error for inconsistent CSV fields")
	}
}

func TestLoadCSV_TrailingSlash(t *testing.T) {
	csvContent := "Name,Link\nTest,https://chrome.google.com/webstore/detail/test/abcdefghijklmnop/\n"
	csvPath := filepath.Join(t.TempDir(), "ext.csv")
	_ = os.WriteFile(csvPath, []byte(csvContent), 0o644)

	exts, err := LoadCSV(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(exts) != 1 || exts[0].ID != "abcdefghijklmnop" {
		t.Errorf("expected ID=abcdefghijklmnop, got %v", exts)
	}
}
