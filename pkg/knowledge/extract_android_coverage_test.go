/*
Copyright (c) 2026 Security Research
*/

package knowledge

import (
	"reflect"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/framework"
	"github.com/inovacc/unravel-oss/pkg/android/kotlin"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/resources"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
)

// drAndroidWithManifest builds a minimal android-shaped DissectResult.
func drAndroidWithManifest(perms ...string) *dissect.DissectResult {
	mp := []androidmanifest.Permission{}
	for _, p := range perms {
		mp = append(mp, androidmanifest.Permission{Name: p})
	}
	return &dissect.DissectResult{
		Path: "/x/test.apk",
		ManifestInfo: &androidmanifest.Manifest{
			Package:     "com.example",
			Permissions: mp,
		},
	}
}

// extractCoverage drives the legacy + new wire-up against dr and returns
// the resulting kr (Platform pre-set to "android").
func extractCoverage(t *testing.T, dr *dissect.DissectResult) *KnowledgeResult {
	t.Helper()
	kr := &KnowledgeResult{Platform: "android"}
	if a := extractAndroid(dr); a != nil {
		kr.Android = a
	}
	extractAndroidCoverage(dr, kr)
	return kr
}

func TestExtractAndroid_ManifestPermissions(t *testing.T) {
	dr := drAndroidWithManifest(
		"android.permission.INTERNET",
		"android.permission.CAMERA",
		"android.permission.READ_CONTACTS",
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.RECORD_AUDIO",
	)
	kr := extractCoverage(t, dr)
	if kr.Android == nil {
		t.Fatal("kr.Android nil; legacy extractAndroid did not populate")
	}
	if got := len(kr.Android.Permissions); got != 5 {
		t.Errorf("Android.Permissions: got %d want 5", got)
	}
}

func TestExtractAndroid_DexClasses(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.DEXAnalysis = &dex.ParseResult{
		TotalClasses: 3,
		DexFiles: []dex.DexFile{
			{
				Name: "classes.dex",
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/x/A;", Superclass: "Ljava/lang/Object;"},
					{ClassName: "Lcom/x/B;", Superclass: "Ljava/lang/Object;"},
					{ClassName: "Lcom/x/C;", Superclass: "Ljava/lang/Object;"},
				},
			},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.DexClasses); got != 3 {
		t.Errorf("DexClasses: got %d want 3", got)
	}
}

func TestExtractAndroid_DexMethods(t *testing.T) {
	dr := drAndroidWithManifest()
	methods := make([]dex.MethodRef, 12)
	for i := range methods {
		methods[i] = dex.MethodRef{ClassName: "Lcom/x/A;", Name: "m"}
	}
	dr.DEXAnalysis = &dex.ParseResult{
		TotalMethods: 12,
		DexFiles:     []dex.DexFile{{Name: "classes.dex", Methods: methods}},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.DexMethods); got != 12 {
		t.Errorf("DexMethods: got %d want 12", got)
	}
}

func TestExtractAndroid_NativeLibs(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.NativeAnalysis = &native.ScanResult{
		Libraries: []native.LibraryInfo{
			{Name: "libfoo.so", ABI: "arm64-v8a", Size: 1024},
			{Name: "libbar.so", ABI: "armeabi-v7a", Size: 512},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.NativeLibs); got != 2 {
		t.Errorf("NativeLibs: got %d want 2", got)
	}
}

func TestExtractAndroid_Resources(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.ResourceAnalysis = &resources.ScanResult{
		TotalAssets: 4,
		Assets: []resources.AssetInfo{
			{Path: "assets/a.html", Category: resources.AssetWebView, Size: 100},
			{Path: "assets/db.sqlite", Category: resources.AssetDatabase, Size: 200},
			{Path: "assets/cfg.json", Category: resources.AssetConfig, Size: 50},
			{Path: "assets/cert.pem", Category: resources.AssetCertificate, Size: 25},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.Resources); got != 4 {
		t.Errorf("Android.Resources: got %d want 4", got)
	}
}

func TestExtractAndroid_Telemetry(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.TelemetryAnalysis = &telemetry.ScanResult{
		SDKs: []telemetry.SDKInfo{
			{Name: "Firebase", Category: telemetry.CategoryAnalytics},
			{Name: "AdMob", Category: telemetry.CategoryAds},
			{Name: "Crashlytics", Category: telemetry.CategoryCrash},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.Telemetry); got != 3 {
		t.Errorf("Android.Telemetry: got %d want 3", got)
	}
}

func TestExtractAndroid_Kotlin(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.KotlinAnalysis = &kotlin.ScanResult{
		HasKotlin: true,
		Features: []kotlin.FeatureInfo{
			{Name: "coroutines", Detected: true},
			{Name: "compose", Detected: true},
			{Name: "serialization", Detected: false},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.KotlinFeatures); got != 2 {
		t.Errorf("Android.KotlinFeatures: got %d want 2 (only detected ones)", got)
	}
}

func TestExtractAndroid_Framework(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.FrameworkAnalysis = &framework.ScanResult{
		Framework: "Flutter",
		Flutter:   &framework.FlutterInfo{EngineVersion: "3.0", DartVersion: "3.0"},
	}
	kr := extractCoverage(t, dr)
	if kr.Android.Framework == nil || kr.Android.Framework.Name != "Flutter" {
		t.Errorf("Android.Framework: got %+v want Name=Flutter", kr.Android.Framework)
	}
}

func TestExtractAndroid_Secrets(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.Secrets = &secret.ScanResult{
		Findings: []secret.Finding{
			{Type: secret.SecretType("api_key"), File: "assets/cfg.json", Confidence: "high"},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.Secrets); got != 1 {
		t.Errorf("Android.Secrets: got %d want 1", got)
	}
}

func TestExtractAndroid_Network(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.NetworkAnalysis = &network.ScanResult{
		Endpoints: []network.EndpointInfo{
			{URL: "https://api.example.com/v1", Scheme: "https", Host: "api.example.com", Path: "/v1"},
			{URL: "https://cdn.example.com/asset", Scheme: "https", Host: "cdn.example.com", Path: "/asset"},
		},
	}
	kr := extractCoverage(t, dr)
	if got := len(kr.Android.Network); got != 2 {
		t.Errorf("Android.Network: got %d want 2", got)
	}
}

func TestExtractAndroid_Obfuscation(t *testing.T) {
	dr := drAndroidWithManifest()
	dr.ObfuscationAnalysis = &obfuscation.Result{
		Type:       obfuscation.ObfProGuard,
		Confidence: 85,
	}
	kr := extractCoverage(t, dr)
	if kr.Android.Obfuscation == nil || kr.Android.Obfuscation.Type != "proguard" {
		t.Errorf("Android.Obfuscation: got %+v want Type=proguard", kr.Android.Obfuscation)
	}
}

func TestExtractAndroid_SourceFiles_PathOnly(t *testing.T) {
	// SourceFile struct must NOT serialize Content (per D-37-SOURCE-FILES-PATH-INDEX).
	st := reflect.TypeOf(SourceFile{})
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		tag := f.Tag.Get("json")
		// Content has json:"-" — that's the path-only contract.
		if f.Name == "Content" && tag != "-" {
			t.Errorf("SourceFile.Content has json tag %q; expected \"-\" (path-only per D-37)", tag)
		}
	}
}

func TestExtractAndroid_NoOpOnNonAndroidPlatform(t *testing.T) {
	dr := drAndroidWithManifest("android.permission.INTERNET")
	kr := &KnowledgeResult{Platform: "windows"}
	extractAndroidCoverage(dr, kr)
	if kr.Android != nil {
		t.Errorf("Android should be nil on non-android platform; got %+v", kr.Android)
	}
}

func TestExtractAndroid_NoOpOnNilAppAnalysis(t *testing.T) {
	dr := &dissect.DissectResult{Path: "/x/test.bin"} // no ManifestInfo, no AppAnalysis
	kr := &KnowledgeResult{Platform: "android"}
	// Should not panic. Android stays nil.
	extractAndroidCoverage(dr, kr)
	if kr.Android != nil {
		t.Errorf("Android: %+v want nil (no upstream android signals)", kr.Android)
	}
}

func TestExtractAndroid_RatioOK_ViaAuditAndroid(t *testing.T) {
	dr := drAndroidWithManifest("android.permission.INTERNET", "android.permission.CAMERA")
	dr.DEXAnalysis = &dex.ParseResult{
		TotalClasses: 2,
		TotalMethods: 4,
		DexFiles: []dex.DexFile{
			{
				Name:    "classes.dex",
				Classes: []dex.ClassDef{{ClassName: "A"}, {ClassName: "B"}},
				Methods: []dex.MethodRef{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}},
			},
		},
	}
	kr := extractCoverage(t, dr)

	dims := depth.AuditAndroid(dr, androidCoverageView{kr: kr})
	if len(dims) != 12 {
		t.Fatalf("expected 12 dimensions, got %d", len(dims))
	}
	for _, d := range dims {
		if d.Total > 0 && d.Ratio == 0 {
			t.Errorf("dimension %q failed RatioOK: covered=%d total=%d ratio=%v",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
	}
}
