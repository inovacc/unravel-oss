/*
Copyright (c) 2026 Security Research
*/

package network

import (
	"archive/zip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

func TestClassifyDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected DomainCategory
	}{
		// Analytics
		{"google-analytics.com", CategoryAnalytics},
		{"www.google-analytics.com", CategoryAnalytics},
		{"firebase.googleapis.com", CategoryAnalytics},
		{"mixpanel.com", CategoryAnalytics},
		{"amplitude.com", CategoryAnalytics},
		{"segment.io", CategoryAnalytics},
		{"crashlytics.com", CategoryAnalytics},

		// Ads
		{"doubleclick.net", CategoryAds},
		{"admob.com", CategoryAds},
		{"googlesyndication.com", CategoryAds},
		{"adjust.com", CategoryAds},
		{"mopub.com", CategoryAds},
		{"appsflyer.com", CategoryAds},

		// CDN
		{"cloudfront.net", CategoryCDN},
		{"d111111abcdef8.cloudfront.net", CategoryCDN},
		{"akamai.net", CategoryCDN},
		{"fastly.net", CategoryCDN},
		{"cdn.example.com", CategoryCDN},
		{"cloudflare.com", CategoryCDN},

		// Cloud
		{"amazonaws.com", CategoryCloud},
		{"s3.amazonaws.com", CategoryCloud},
		{"googleapis.com", CategoryCloud},
		{"azure.com", CategoryCloud},
		{"firebaseio.com", CategoryCloud},
		{"appspot.com", CategoryCloud},

		// Social
		{"facebook.com", CategorySocial},
		{"www.facebook.com", CategorySocial},
		{"twitter.com", CategorySocial},
		{"instagram.com", CategorySocial},
		{"linkedin.com", CategorySocial},

		// Internal
		{"localhost", CategoryInternal},
		{"example.local", CategoryInternal},
		{"api.internal", CategoryInternal},
		{"127.0.0.1", CategoryInternal},
		{"::1", CategoryInternal},
		{"10.0.0.1", CategoryInternal},
		{"192.168.1.1", CategoryInternal},
		{"172.16.0.1", CategoryInternal},

		// Unknown
		{"example.com", CategoryUnknown},
		{"myapi.example.org", CategoryUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := ClassifyDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("ClassifyDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestParseNetworkSecurityConfig(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </domain-config>
</network-security-config>`)

	config, err := ParseNetworkSecurityConfig(xmlData)
	if err != nil {
		t.Fatalf("ParseNetworkSecurityConfig() error = %v", err)
	}

	if config == nil {
		t.Fatal("ParseNetworkSecurityConfig() returned nil config")
	}

	if !config.Present {
		t.Error("config.Present = false, want true")
	}

	// Check base config
	if config.BaseConfig == nil {
		t.Fatal("config.BaseConfig = nil, want non-nil")
	}

	if config.BaseConfig.CleartextPermitted == nil {
		t.Fatal("config.BaseConfig.CleartextPermitted = nil, want non-nil")
	}

	if *config.BaseConfig.CleartextPermitted != false {
		t.Errorf("config.BaseConfig.CleartextPermitted = %v, want false", *config.BaseConfig.CleartextPermitted)
	}

	if len(config.BaseConfig.TrustAnchors) != 1 || config.BaseConfig.TrustAnchors[0] != "system" {
		t.Errorf("config.BaseConfig.TrustAnchors = %v, want [system]", config.BaseConfig.TrustAnchors)
	}

	// Check domain config
	if len(config.DomainConfigs) != 1 {
		t.Fatalf("len(config.DomainConfigs) = %d, want 1", len(config.DomainConfigs))
	}

	dc := config.DomainConfigs[0]

	if len(dc.Domains) != 1 {
		t.Fatalf("len(dc.Domains) = %d, want 1", len(dc.Domains))
	}

	if dc.Domains[0].Domain != "example.com" {
		t.Errorf("dc.Domains[0].Domain = %q, want %q", dc.Domains[0].Domain, "example.com")
	}

	if !dc.Domains[0].IncludeSubdomains {
		t.Error("dc.Domains[0].IncludeSubdomains = false, want true")
	}

	if dc.PinSet == nil {
		t.Fatal("dc.PinSet = nil, want non-nil")
	}

	if dc.PinSet.Expiration != "2026-01-01" {
		t.Errorf("dc.PinSet.Expiration = %q, want %q", dc.PinSet.Expiration, "2026-01-01")
	}

	if len(dc.PinSet.Pins) != 1 {
		t.Fatalf("len(dc.PinSet.Pins) = %d, want 1", len(dc.PinSet.Pins))
	}
}

func TestDetectPinning(t *testing.T) {
	tests := []struct {
		name        string
		dexStrings  []string
		wantSources []string
	}{
		{
			name: "OkHttp patterns",
			dexStrings: []string{
				"okhttp3/CertificatePinner",
				"sha256/AAAAAAAAAAAAAAAA",
			},
			wantSources: []string{"okhttp"},
		},
		{
			name: "TrustManager patterns",
			dexStrings: []string{
				"javax/net/ssl/TrustManagerFactory",
				"javax/net/ssl/X509TrustManager",
			},
			wantSources: []string{"trustmanager"},
		},
		{
			name: "Multiple sources",
			dexStrings: []string{
				"okhttp3/CertificatePinner",
				"javax/net/ssl/TrustManagerFactory",
			},
			wantSources: []string{"okhttp", "trustmanager"},
		},
		{
			name:        "No pinning",
			dexStrings:  []string{"some", "random", "strings"},
			wantSources: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use empty apkPath since we're only testing DEX string detection
			result := DetectPinning("", tt.dexStrings)

			if result == nil {
				t.Fatal("DetectPinning() returned nil")
			}

			expectedHasPinning := len(tt.wantSources) > 0
			if result.HasPinning != expectedHasPinning {
				t.Errorf("result.HasPinning = %v, want %v", result.HasPinning, expectedHasPinning)
			}

			if len(result.Sources) != len(tt.wantSources) {
				t.Errorf("len(result.Sources) = %d, want %d", len(result.Sources), len(tt.wantSources))
			}

			for _, wantSource := range tt.wantSources {
				if !slices.Contains(result.Sources, wantSource) {
					t.Errorf("result.Sources missing %q", wantSource)
				}
			}
		})
	}
}

func createTestAPK(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return apkPath
}

func TestDetermineCleartextAllowed(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	tests := []struct {
		name   string
		config *NetworkSecConfig
		want   bool
	}{
		{"nil config", nil, true},
		{"nil BaseConfig", &NetworkSecConfig{}, true},
		{"nil CleartextPermitted", &NetworkSecConfig{BaseConfig: &BaseConfig{}}, true},
		{"cleartext false", &NetworkSecConfig{BaseConfig: &BaseConfig{CleartextPermitted: boolPtr(false)}}, false},
		{"cleartext true", &NetworkSecConfig{BaseConfig: &BaseConfig{CleartextPermitted: boolPtr(true)}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineCleartextAllowed(tt.config)
			if got != tt.want {
				t.Errorf("determineCleartextAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineSource(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{Strings: []string{"https://api.example.com/v1"}},
		},
	}

	tests := []struct {
		name      string
		str       string
		dexResult *dex.ParseResult
		want      string
	}{
		{"dex string", "https://api.example.com/v1", dexResult, "dex_strings"},
		{"assets string", "found in assets/ dir", nil, "assets"},
		{"resources string", "found in res/ dir", nil, "resources"},
		{"unknown string", "some random content", nil, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineSource(tt.str, tt.dexResult)
			if got != tt.want {
				t.Errorf("determineSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShouldScanFile(t *testing.T) {
	tests := []struct {
		name string
		file *zip.File
		want bool
	}{
		{
			"assets json",
			&zip.File{FileHeader: zip.FileHeader{Name: "assets/config.json"}},
			true,
		},
		{
			"assets xml",
			&zip.File{FileHeader: zip.FileHeader{Name: "assets/data.xml"}},
			true,
		},
		{
			"res xml",
			&zip.File{FileHeader: zip.FileHeader{Name: "res/values/strings.xml"}},
			true,
		},
		{
			"classes.dex not scanned",
			&zip.File{FileHeader: zip.FileHeader{Name: "classes.dex"}},
			false,
		},
		{
			"assets image not scanned",
			&zip.File{FileHeader: zip.FileHeader{Name: "assets/image.png"}},
			false,
		},
		{
			"assets huge file not scanned",
			&zip.File{FileHeader: zip.FileHeader{Name: "assets/huge.json", UncompressedSize64: 2 * 1024 * 1024}},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldScanFile(tt.file)
			if got != tt.want {
				t.Errorf("shouldScanFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindNetworkSecConfig(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		xmlContent := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false"/>
</network-security-config>`

		apkPath := createTestAPK(t, map[string]string{
			"res/xml/network_security_config.xml": xmlContent,
		})

		data, err := FindNetworkSecConfig(apkPath)
		if err != nil {
			t.Fatalf("FindNetworkSecConfig() error = %v", err)
		}
		if data == nil {
			t.Fatal("FindNetworkSecConfig() returned nil data, want non-nil")
		}
		if !strings.Contains(string(data), "cleartextTrafficPermitted") {
			t.Error("returned data does not contain expected XML content")
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		apkPath := createTestAPK(t, map[string]string{
			"assets/config.json": `{}`,
		})

		data, err := FindNetworkSecConfig(apkPath)
		if err != nil {
			t.Fatalf("FindNetworkSecConfig() error = %v", err)
		}
		if data != nil {
			t.Errorf("FindNetworkSecConfig() = %v, want nil", data)
		}
	})
}

func TestScanAPK_WithURLs(t *testing.T) {
	apkPath := createTestAPK(t, map[string]string{
		"assets/config.json": `{"api": "https://api.example.com/v1/users"}`,
	})

	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Strings: []string{
					"https://cdn.cloudflare.com/lib.js",
					"https://google-analytics.com/collect",
				},
			},
		},
	}

	result, err := ScanAPK(apkPath, dexResult)
	if err != nil {
		t.Fatalf("ScanAPK() error = %v", err)
	}

	if result.TotalURLs < 3 {
		t.Errorf("TotalURLs = %d, want >= 3", result.TotalURLs)
	}
	if result.TotalDomains < 3 {
		t.Errorf("TotalDomains = %d, want >= 3", result.TotalDomains)
	}
	if !result.CleartextAllowed {
		t.Error("CleartextAllowed = false, want true (no NSC config)")
	}
}

func TestScanAPK_NoDexResult(t *testing.T) {
	apkPath := createTestAPK(t, map[string]string{
		"assets/config.json": `{"url": "https://example.com/api"}`,
	})

	result, err := ScanAPK(apkPath, nil)
	if err != nil {
		t.Fatalf("ScanAPK() error = %v", err)
	}

	if result.TotalURLs != 1 {
		t.Errorf("TotalURLs = %d, want 1", result.TotalURLs)
	}
}

func TestParseNetworkSecurityConfig_CleartextTrue(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>`)

	config, err := ParseNetworkSecurityConfig(xmlData)
	if err != nil {
		t.Fatalf("ParseNetworkSecurityConfig() error = %v", err)
	}
	if config == nil {
		t.Fatal("ParseNetworkSecurityConfig() returned nil")
	}
	if config.BaseConfig == nil || config.BaseConfig.CleartextPermitted == nil {
		t.Fatal("BaseConfig or CleartextPermitted is nil")
	}
	if *config.BaseConfig.CleartextPermitted != true {
		t.Errorf("CleartextPermitted = %v, want true", *config.BaseConfig.CleartextPermitted)
	}
}

func TestParseNetworkSecurityConfig_BinaryXML(t *testing.T) {
	data := []byte{0x03, 0x00, 0x08, 0x00}

	config, err := ParseNetworkSecurityConfig(data)
	if err != nil {
		t.Fatalf("ParseNetworkSecurityConfig() error = %v, want nil", err)
	}
	if config != nil {
		t.Errorf("ParseNetworkSecurityConfig() = %v, want nil", config)
	}
}
