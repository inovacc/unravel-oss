/* Copyright (c) 2026 Security Research */
package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestFind(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		urlPattern      manifest.URLPattern
		classifications []manifest.Classification
		wantLen         int
		wantFirst       *Finding
	}{
		{
			name:    "finds URLs and classifies them via host heuristic",
			content: `fetch("https://api.discord.com/users")`,
			classifications: []manifest.Classification{
				{Keywords: []string{"users"}, Purpose: "API"},
			},
			wantLen:   1,
			wantFirst: &Finding{URL: "https://api.discord.com/users", Purpose: "api"},
		},
		{
			name:       "manifest exclude drops URL",
			content:    `fetch("https://internal.corp.test/api")`,
			urlPattern: manifest.URLPattern{Exclude: []string{"internal"}},
			wantLen:    0,
		},
		{
			name:    "deduplicates URLs by (scheme,host,2-segment path)",
			content: `fetch("https://api.test.io/v1/a"); fetch("https://api.test.io/v1/a");`,
			wantLen: 1,
		},
		{
			name:    "manifest classification used when host heuristic returns Unknown",
			content: `link "https://discord.com/community"`,
			classifications: []manifest.Classification{
				{Keywords: []string{"community"}, Purpose: "Community"},
			},
			wantLen:   1,
			wantFirst: &Finding{URL: "https://discord.com/community", Purpose: "Community"},
		},
		{
			name:    "no matches returns empty",
			content: "no urls here",
			wantLen: 0,
		},
		{
			name:      "trailing punctuation is trimmed",
			content:   `url: "https://api.discord.com/path";`,
			wantLen:   1,
			wantFirst: &Finding{URL: "https://api.discord.com/path", Purpose: "api"},
		},
		{
			name:    "denylist drops spec hosts",
			content: `// see https://crbug.com/12345 and https://www.w3.org/TR/foo`,
			wantLen: 0,
		},
		{
			name:    "denylist drops github.com refs",
			content: `// https://github.com/electron/electron/issues/12345`,
			wantLen: 0,
		},
		{
			name:    "template placeholder leak rejected",
			content: `const x = "https://$";`,
			wantLen: 0,
		},
		{
			name:      "websocket host classified",
			content:   `connect("https://gateway.discord.gg/?v=10")`,
			wantLen:   1,
			wantFirst: &Finding{URL: "https://gateway.discord.gg/?v=10", Purpose: "websocket"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Find(tt.content, tt.urlPattern, tt.classifications)
			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d; findings: %+v", len(got), tt.wantLen, got)
			}
			if tt.wantFirst != nil && len(got) > 0 {
				if got[0].URL != tt.wantFirst.URL {
					t.Errorf("URL = %q, want %q", got[0].URL, tt.wantFirst.URL)
				}
				if got[0].Purpose != tt.wantFirst.Purpose {
					t.Errorf("Purpose = %q, want %q", got[0].Purpose, tt.wantFirst.Purpose)
				}
			}
		})
	}
}

func TestDenyHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"www.github.com", true},
		{"crbug.com", true},
		{"fetch.spec.whatwg.org", true},
		{"foo.googlesource.com", true},
		{"api.discord.com", false},
		{"discord.com", false},
		{"GITHUB.COM", true},
	}
	for _, c := range cases {
		if got := denyHost(c.host); got != c.want {
			t.Errorf("denyHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestClassifyPurpose(t *testing.T) {
	cases := []struct {
		scheme, host, path string
		want               Purpose
	}{
		{"https", "api.discord.com", "/v9/users", PurposeAPI},
		{"https", "gateway.discord.gg", "/", PurposeWebsocket},
		{"https", "sentry.io", "/api/123/store", PurposeTelemetry},
		{"https", "auth.discord.gg", "/", PurposeAuth},
		{"https", "cdn.discordapp.com", "/avatars/x.png", PurposeCDN},
		{"https", "releases.discord.com", "/v1/latest", PurposeUpdate},
		{"https", "discord.com", "/about", PurposeUnknown},
	}
	for _, c := range cases {
		if got := classifyPurpose(c.scheme, c.host, c.path); got != c.want {
			t.Errorf("classifyPurpose(%s,%s,%s) = %s, want %s",
				c.scheme, c.host, c.path, got, c.want)
		}
	}
}

func TestFindWithBrand_OverridesDenylist(t *testing.T) {
	content := `repo "https://github.com/discord/api"`
	got := FindWithBrand(content, manifest.URLPattern{}, nil, []string{"discord"})
	if len(got) != 0 {
		t.Errorf("brand not in host should not override; got %+v", got)
	}
	got = FindWithBrand(content, manifest.URLPattern{}, nil, []string{"github"})
	if len(got) != 1 {
		t.Fatalf("brand-in-host should bypass denylist; got %+v", got)
	}
}

// --- Discord ASAR live regression (BUG-07) ---

type discordGolden struct {
	FixturePathEnv     string `json:"fixture_path_env"`
	DefaultFixturePath string `json:"default_fixture_path"`
	CountMax           int    `json:"count_max"`
	MinClassifiedPct   int    `json:"min_classified_pct"`
}

func loadDiscordFixture(t *testing.T) (string, *discordGolden) {
	t.Helper()
	if testing.Short() {
		t.Skip("short mode")
	}
	raw, err := os.ReadFile("testdata/discord_endpoints.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g discordGolden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	path := os.Getenv(g.FixturePathEnv)
	if path == "" {
		path = g.DefaultFixturePath
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("Discord ASAR fixture not available at %q (set %s)", path, g.FixturePathEnv)
	}
	return path, &g
}

func extractAllJS(t *testing.T, asarPath string) string {
	t.Helper()
	f, header, _, dataOffset, err := asar.OpenAndParse(asarPath)
	if err != nil {
		t.Fatalf("open asar: %v", err)
	}
	defer func() { _ = f.Close() }()

	files := asar.CollectFiles(header.Files, "")
	var sb strings.Builder
	for _, fe := range files {
		if fe.IsDir || fe.Unpacked {
			continue
		}
		if !strings.HasSuffix(fe.Path, ".js") {
			continue
		}
		if fe.Size == 0 {
			continue
		}
		buf, err := asar.ReadFileContent(f, dataOffset, fe.Offset, fe.Size)
		if err != nil {
			continue
		}
		sb.Write(buf)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func TestExtract_DiscordASAR_BelowNoiseCeiling(t *testing.T) {
	path, g := loadDiscordFixture(t)
	js := extractAllJS(t, path)
	got := FindWithBrand(js, manifest.URLPattern{}, nil, []string{"discord"})
	if len(got) > g.CountMax {
		t.Errorf("Discord endpoint count = %d, want ≤ %d", len(got), g.CountMax)
	}
	t.Logf("Discord endpoint count: %d (ceiling %d, pre-fix %d)", len(got), g.CountMax, 1732)
}

func TestExtract_DiscordASAR_NoDenylistedHosts(t *testing.T) {
	path, _ := loadDiscordFixture(t)
	js := extractAllJS(t, path)
	got := FindWithBrand(js, manifest.URLPattern{}, nil, []string{"discord"})
	for _, f := range got {
		u := f.URL
		u = strings.TrimPrefix(u, "https://")
		u = strings.TrimPrefix(u, "http://")
		host := u
		if i := strings.IndexAny(u, "/?#"); i >= 0 {
			host = u[:i]
		}
		if denyHost(host) {
			t.Errorf("denylisted host leaked through: %s", f.URL)
		}
	}
}

func TestExtract_DiscordASAR_PurposeCoverage(t *testing.T) {
	path, g := loadDiscordFixture(t)
	js := extractAllJS(t, path)
	got := FindWithBrand(js, manifest.URLPattern{}, nil, []string{"discord"})
	if len(got) == 0 {
		t.Fatal("no endpoints extracted")
	}
	classified := 0
	for _, f := range got {
		if f.Purpose != "Unknown" && f.Purpose != "" {
			classified++
		}
	}
	pct := classified * 100 / len(got)
	if pct < g.MinClassifiedPct {
		t.Errorf("classified pct = %d%%, want ≥ %d%% (%d/%d)", pct, g.MinClassifiedPct, classified, len(got))
	}
	t.Logf("Discord classified: %d/%d (%d%%)", classified, len(got), pct)
}
