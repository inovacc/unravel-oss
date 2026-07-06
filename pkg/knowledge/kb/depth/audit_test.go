/*
Copyright (c) 2026 Security Research
*/

package depth

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// fakeView is a minimal AndroidCoverageView used by audit tests so this
// package never imports pkg/knowledge (depth must remain a leaf to avoid
// the import cycle once KnowledgeResult.DepthCovered references Dimension).
type fakeView struct {
	pkg         bool
	dexClasses  int
	dexMethods  int
	nativeLibs  int
	resources   int
	telemetry   int
	kotlin      int
	framework   bool
	secrets     int
	network     int
	obfuscation bool
	permissions int
}

func (f fakeView) AndroidPackagePresent() bool       { return f.pkg }
func (f fakeView) AndroidDEXClasses() int            { return f.dexClasses }
func (f fakeView) AndroidDEXMethods() int            { return f.dexMethods }
func (f fakeView) AndroidNativeLibCount() int        { return f.nativeLibs }
func (f fakeView) AndroidResourcesCount() int        { return f.resources }
func (f fakeView) AndroidTelemetrySDKsCount() int    { return f.telemetry }
func (f fakeView) AndroidKotlinFeatureCount() int    { return f.kotlin }
func (f fakeView) AndroidFrameworkPresent() bool     { return f.framework }
func (f fakeView) AndroidSecretsCount() int          { return f.secrets }
func (f fakeView) AndroidNetworkEndpointsCount() int { return f.network }
func (f fakeView) AndroidObfuscationPresent() bool   { return f.obfuscation }
func (f fakeView) AndroidPermissionsCount() int      { return f.permissions }

func TestAuditAndroid_Empty(t *testing.T) {
	t.Run("nil_dissect_result", func(t *testing.T) {
		got := AuditAndroid(nil, fakeView{})
		if got != nil {
			t.Errorf("expected nil slice, got %v", got)
		}
	})
	t.Run("nil_view", func(t *testing.T) {
		got := AuditAndroid(&dissect.DissectResult{}, nil)
		if got != nil {
			t.Errorf("expected nil slice, got %v", got)
		}
	})
}

func TestAuditAndroid_AllZero(t *testing.T) {
	dr := &dissect.DissectResult{}
	view := fakeView{}
	got := AuditAndroid(dr, view)
	if len(got) != 12 {
		t.Fatalf("expected 12 dimensions, got %d", len(got))
	}
	for _, d := range got {
		if d.Total != 0 || d.Covered != 0 || d.Ratio != 0 {
			t.Errorf("dimension %q expected all-zero, got covered=%d total=%d ratio=%v",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
		if !RatioOK(d) {
			t.Errorf("dimension %q failed RatioOK on absent (total=0)", d.Name)
		}
	}
}

func TestAuditAndroid_PartialCoverage(t *testing.T) {
	dr := &dissect.DissectResult{
		ManifestInfo: &androidmanifest.Manifest{
			Package: "org.example.app",
			Permissions: []androidmanifest.Permission{
				{Name: "android.permission.INTERNET"},
				{Name: "android.permission.CAMERA"},
				{Name: "android.permission.READ_CONTACTS"},
				{Name: "android.permission.ACCESS_FINE_LOCATION"},
				{Name: "android.permission.RECORD_AUDIO"},
			},
			Components: []androidmanifest.Component{
				{Name: "MainActivity"},
				{Name: "DataService"},
				{Name: "BootReceiver"},
			},
		},
		DEXAnalysis: &dex.ParseResult{
			TotalClasses: 100,
			TotalMethods: 500,
		},
	}

	// Wire-up state: manifest + dex partially propagated.
	view := fakeView{
		pkg:         true,
		dexClasses:  40,  // only 40 of 100 propagated
		dexMethods:  500, // all methods propagated
		permissions: 5,   // all permissions propagated
	}

	got := AuditAndroid(dr, view)
	if len(got) != 12 {
		t.Fatalf("expected 12 dimensions, got %d", len(got))
	}

	byName := map[string]Dimension{}
	for _, d := range got {
		byName[d.Name] = d
	}

	if d := byName["manifest"]; d.Total != 1 || d.Covered != 1 || d.Ratio != 1.0 {
		t.Errorf("manifest: %+v want covered=1 total=1 ratio=1.0", d)
	}
	if d := byName["dex_classes"]; d.Total != 100 || d.Covered != 40 || d.Ratio != 0.4 {
		t.Errorf("dex_classes: %+v want covered=40 total=100 ratio=0.4", d)
	}
	if d := byName["dex_methods"]; d.Total != 500 || d.Covered != 500 || d.Ratio != 1.0 {
		t.Errorf("dex_methods: %+v want covered=500 total=500 ratio=1.0", d)
	}
	if d := byName["permissions"]; d.Total != 5 || d.Covered != 5 || d.Ratio != 1.0 {
		t.Errorf("permissions: %+v want covered=5 total=5 ratio=1.0", d)
	}
}

func TestAuditAndroid_DimensionOrderStable(t *testing.T) {
	canonical := []string{
		"manifest",
		"dex_classes",
		"dex_methods",
		"native_libs",
		"resources_xml",
		"telemetry_sdks",
		"kotlin_features",
		"framework",
		"secrets",
		"network_endpoints",
		"obfuscation_signals",
		"permissions",
	}
	got := AuditAndroid(&dissect.DissectResult{}, fakeView{})
	if len(got) != len(canonical) {
		t.Fatalf("expected %d dimensions, got %d", len(canonical), len(got))
	}
	for i, want := range canonical {
		if got[i].Name != want {
			t.Errorf("position %d: got %q want %q", i, got[i].Name, want)
		}
	}
	// Loud-failure rule: any dimension with total>0 and ratio==0 fails RatioOK.
	for _, d := range got {
		if !RatioOK(d) {
			t.Errorf("dimension %q failed RatioOK; covered=%d total=%d ratio=%v",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
	}
}
