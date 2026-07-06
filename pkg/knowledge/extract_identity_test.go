// Platform-tag granularity (P62 / DEPT-01 / D-62-PLATFORM-TAGS-ARE-LOAD-BEARING):
//
// extract_identity.go emits granular Windows platform tags — "windows-msix" for
// MSIX/UWP packages and "windows-pe" for .NET PE binaries. These literals are
// LOAD-BEARING — multiple production paths key off the exact string:
//
//   - identity resolver registry (pkg/knowledge/kb/identity/resolvers/uwp/uwp.go:29
//     calls identity.Register("windows-msix", ...))
//   - allowed-platforms set (pkg/knowledge/kb/identity/fingerprint.go:35-36)
//   - KB classify schema (pkg/knowledge/kb/component/classify/classify_integration_test.go:36)
//   - identity unit + integration tests asserting "windows-msix" / "windows-pe"
//
// Collapsing to bare "windows" would break resolver dispatch, fail allowlist
// checks, and change the platform field of knowledge.json (D-10 byte-shape
// violation). The 3 tests in this file (UWP, Electron, DotNet) had stale
// "windows" expectations pre-dating P38's UWP-coverage work; they were
// updated to match production. TestExtract_Identity_PlatformTagsAreGranular
// (below) codifies the load-bearing decision so future "simplification"
// attempts fail loudly.
package knowledge

import (
	"testing"

	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/ios"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

func TestExtract_Identity_Android(t *testing.T) {
	dr := &dissect.DissectResult{
		Path:         "/x/fdroid.apk",
		ManifestInfo: &androidmanifest.Manifest{Package: "org.fdroid.fdroid"},
	}
	platform, packageID, displayName, publisher := extractIdentity(dr)
	if platform != "android" {
		t.Errorf("platform = %q, want android", platform)
	}
	if packageID != "org.fdroid.fdroid" {
		t.Errorf("packageID = %q, want org.fdroid.fdroid", packageID)
	}
	if displayName != "org.fdroid.fdroid" {
		t.Errorf("displayName = %q, want org.fdroid.fdroid", displayName)
	}
	if publisher != "" {
		t.Errorf("publisher = %q, want empty", publisher)
	}
}

func TestExtract_Identity_Empty(t *testing.T) {
	dr := &dissect.DissectResult{Path: "/tmp/x.bin"}
	platform, packageID, displayName, publisher := extractIdentity(dr)
	if platform != "" || packageID != "" || displayName != "" || publisher != "" {
		t.Errorf("expected all empty, got (%q, %q, %q, %q)", platform, packageID, displayName, publisher)
	}
}

func TestExtract_Identity_UWP(t *testing.T) {
	dr := &dissect.DissectResult{
		Path: "/x/wa.msix",
		MSIXInfo: &msix.InfoResult{
			PackageName:          "5319275A.WhatsAppDesktop",
			Publisher:            "CN=WhatsApp LLC",
			PublisherDisplayName: "WhatsApp",
		},
	}
	platform, packageID, displayName, publisher := extractIdentity(dr)
	if platform != "windows-msix" {
		t.Errorf("platform = %q, want windows-msix", platform)
	}
	if packageID != "5319275A.WhatsAppDesktop" {
		t.Errorf("packageID = %q", packageID)
	}
	if displayName != "WhatsApp" {
		t.Errorf("displayName = %q, want WhatsApp", displayName)
	}
	if publisher != "CN=WhatsApp LLC" {
		t.Errorf("publisher = %q", publisher)
	}
}

// TestExtract_Identity_Electron exercises the Electron+MSIX collision (Teams shape):
// MSIX must win over Electron AppInfo per D-35-MSIX-WINS-FOR-ELECTRON.
func TestExtract_Identity_Electron(t *testing.T) {
	dr := &dissect.DissectResult{
		Path: "/x/teams.msix",
		MSIXInfo: &msix.InfoResult{
			PackageName:          "MSTeams_8wekyb3d8bbwe",
			Publisher:            "CN=Microsoft Corporation",
			PublisherDisplayName: "Microsoft Teams",
		},
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{Name: "teams", Type: "electron", DisplayName: "Teams"},
		},
		BinaryInfo: &binary.Info{Type: "pe"},
	}
	platform, packageID, displayName, publisher := extractIdentity(dr)
	if platform != "windows-msix" {
		t.Errorf("platform = %q, want windows-msix (MSIX wins over Electron per D-35-MSIX-WINS-FOR-ELECTRON)", platform)
	}
	if packageID != "MSTeams_8wekyb3d8bbwe" {
		t.Errorf("packageID = %q (MSIX must win over Electron AppInfo.Name=teams)", packageID)
	}
	if displayName != "Microsoft Teams" {
		t.Errorf("displayName = %q, want 'Microsoft Teams'", displayName)
	}
	if publisher != "CN=Microsoft Corporation" {
		t.Errorf("publisher = %q", publisher)
	}
}

func TestExtract_Identity_iOS(t *testing.T) {
	dr := &dissect.DissectResult{
		Path: "/x/app.ipa",
		IPAInfo: &ios.IPAInfo{
			BundleID:    "com.example.app",
			BundleName:  "Example",
			SigningInfo: &ios.SigningInfo{TeamID: "ABCD1234"},
		},
	}
	platform, packageID, displayName, publisher := extractIdentity(dr)
	if platform != "ios" {
		t.Errorf("platform = %q, want ios", platform)
	}
	if packageID != "com.example.app" {
		t.Errorf("packageID = %q", packageID)
	}
	if displayName != "Example" {
		t.Errorf("displayName = %q", displayName)
	}
	if publisher != "ABCD1234" {
		t.Errorf("publisher = %q", publisher)
	}

	// Nil SigningInfo → empty publisher.
	dr2 := &dissect.DissectResult{
		Path:    "/x/b.ipa",
		IPAInfo: &ios.IPAInfo{BundleID: "com.b", BundleName: ""},
	}
	_, _, dn, pub := extractIdentity(dr2)
	if pub != "" {
		t.Errorf("nil-signinginfo publisher = %q, want empty", pub)
	}
	if dn != "com.b" {
		t.Errorf("displayName fallback = %q, want com.b (BundleID)", dn)
	}
}

func TestExtract_Identity_DotNet(t *testing.T) {
	dr := &dissect.DissectResult{
		Path:       "/x/app.exe",
		DotnetDeps: &dotnet.DepsResult{},
		BinaryInfo: &binary.Info{Type: "pe", ProductName: "MyApp"},
	}
	platform, packageID, displayName, publisher := extractIdentity(dr)
	if platform != "windows-pe" {
		t.Errorf("platform = %q, want windows-pe (.NET PE per D-62-PLATFORM-TAGS-ARE-LOAD-BEARING)", platform)
	}
	if packageID != "MyApp" {
		t.Errorf("packageID = %q", packageID)
	}
	if displayName != "MyApp" {
		t.Errorf("displayName = %q", displayName)
	}
	if publisher != "" {
		t.Errorf("publisher = %q, want empty", publisher)
	}

	// Empty ProductName → no fallback inference.
	dr2 := &dissect.DissectResult{
		Path:       "/x/empty.exe",
		DotnetDeps: &dotnet.DepsResult{},
		BinaryInfo: &binary.Info{Type: "pe", ProductName: ""},
	}
	pl, pid, dn, pub := extractIdentity(dr2)
	if pl != "" || pid != "" || dn != "" || pub != "" {
		t.Errorf("empty ProductName must not fallback: got (%q,%q,%q,%q)", pl, pid, dn, pub)
	}
}

// TestExtract_Identity_V2_Parity proves Extract and ExtractWithOptions yield
// identical identity fields for the same input — single-helper guarantee
// (D-35-V2-PARITY).
func TestExtract_Identity_V2_Parity(t *testing.T) {
	cases := []struct {
		name string
		dr   *dissect.DissectResult
	}{
		{
			name: "apk",
			dr: &dissect.DissectResult{
				Path:         "/x/a.apk",
				ManifestInfo: &androidmanifest.Manifest{Package: "org.example"},
			},
		},
		{
			name: "uwp",
			dr: &dissect.DissectResult{
				Path: "/x/a.msix",
				MSIXInfo: &msix.InfoResult{
					PackageName:          "Foo.Bar",
					Publisher:            "CN=X",
					PublisherDisplayName: "Foo",
				},
			},
		},
		{
			name: "ios",
			dr: &dissect.DissectResult{
				Path: "/x/a.ipa",
				IPAInfo: &ios.IPAInfo{
					BundleID:    "com.x",
					BundleName:  "X",
					SigningInfo: &ios.SigningInfo{TeamID: "TEAM"},
				},
			},
		},
		{
			name: "dotnet",
			dr: &dissect.DissectResult{
				Path:       "/x/a.exe",
				DotnetDeps: &dotnet.DepsResult{},
				BinaryInfo: &binary.Info{Type: "pe", ProductName: "MyApp"},
			},
		},
		{
			name: "electron-msix",
			dr: &dissect.DissectResult{
				Path: "/x/teams.msix",
				MSIXInfo: &msix.InfoResult{
					PackageName:          "MSTeams_8wekyb3d8bbwe",
					Publisher:            "CN=Microsoft",
					PublisherDisplayName: "Teams",
				},
				AppAnalysis: &app.Result{
					AppInfo: app.AppInfoResult{Name: "teams", Type: "electron", DisplayName: "Teams"},
				},
				BinaryInfo: &binary.Info{Type: "pe"},
			},
		},
		{
			name: "empty",
			dr:   &dissect.DissectResult{Path: "/x/unknown.bin"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kr1 := Extract(tc.dr)
			kr2 := ExtractWithOptions(tc.dr, ExtractOptions{})
			if kr1.Platform != kr2.Platform {
				t.Errorf("Platform: Extract=%q ExtractWithOptions=%q", kr1.Platform, kr2.Platform)
			}
			if kr1.PackageID != kr2.PackageID {
				t.Errorf("PackageID: Extract=%q ExtractWithOptions=%q", kr1.PackageID, kr2.PackageID)
			}
			if kr1.DisplayName != kr2.DisplayName {
				t.Errorf("DisplayName: Extract=%q ExtractWithOptions=%q", kr1.DisplayName, kr2.DisplayName)
			}
			if kr1.Publisher != kr2.Publisher {
				t.Errorf("Publisher: Extract=%q ExtractWithOptions=%q", kr1.Publisher, kr2.Publisher)
			}
		})
	}
}

// TestExtract_Identity_PlatformTagsAreGranular codifies the load-bearing
// decision (D-62-PLATFORM-TAGS-ARE-LOAD-BEARING) that Windows artifacts emit
// granular tags ("windows-msix" or "windows-pe") rather than collapsing to
// bare "windows". A bare "windows" tag would break:
//
//   - identity resolver dispatch (resolvers/uwp/uwp.go registers "windows-msix")
//   - allowlist gate in fingerprint.go
//   - KB schema literals stored in classify integration tests
//   - downstream knowledge.json platform field (D-10 byte-shape)
//
// Any future contributor tempted to "simplify" the tags must update this test
// in lockstep with the production change AND the downstream consumers above.
func TestExtract_Identity_PlatformTagsAreGranular(t *testing.T) {
	cases := []struct {
		name     string
		dr       *dissect.DissectResult
		wantTag  string
		wantBare string // explicit "must NOT collapse to" sentinel
	}{
		{
			name: "msix",
			dr: &dissect.DissectResult{
				Path:     "/x/a.msix",
				MSIXInfo: &msix.InfoResult{PackageName: "Foo.Bar"},
			},
			wantTag:  "windows-msix",
			wantBare: "windows",
		},
		{
			name: "electron-msix",
			dr: &dissect.DissectResult{
				Path: "/x/teams.msix",
				MSIXInfo: &msix.InfoResult{
					PackageName:          "MSTeams_8wekyb3d8bbwe",
					PublisherDisplayName: "Microsoft Teams",
				},
				AppAnalysis: &app.Result{
					AppInfo: app.AppInfoResult{Name: "teams", Type: "electron"},
				},
				BinaryInfo: &binary.Info{Type: "pe"},
			},
			wantTag:  "windows-msix",
			wantBare: "windows",
		},
		{
			name: "dotnet-pe",
			dr: &dissect.DissectResult{
				Path:       "/x/app.exe",
				DotnetDeps: &dotnet.DepsResult{},
				BinaryInfo: &binary.Info{Type: "pe", ProductName: "MyApp"},
			},
			wantTag:  "windows-pe",
			wantBare: "windows",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			platform, _, _, _ := extractIdentity(tc.dr)
			if platform == tc.wantBare {
				t.Fatalf("platform collapsed to bare %q — must remain granular %q "+
					"(see file header for D-62-PLATFORM-TAGS-ARE-LOAD-BEARING and "+
					"resolvers/uwp/uwp.go:29 + fingerprint.go:35-36 consumers)",
					tc.wantBare, tc.wantTag)
			}
			if platform != tc.wantTag {
				t.Errorf("platform = %q, want %q (granular tag is a registry key)",
					platform, tc.wantTag)
			}
		})
	}
}
