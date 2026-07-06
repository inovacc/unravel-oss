/*
Copyright (c) 2026 Security Research
*/

package telemetry

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/manifest"
)

func TestDetectSDKs(t *testing.T) {
	tests := []struct {
		name     string
		classes  []string
		wantSDK  string
		wantCat  SDKCategory
		wantConf float64
	}{
		{
			name:     "Firebase Analytics - single class",
			classes:  []string{"com/google/firebase/analytics/FirebaseAnalytics"},
			wantSDK:  "Firebase Analytics",
			wantCat:  CategoryAnalytics,
			wantConf: 70.0,
		},
		{
			name: "Firebase Analytics - multiple classes",
			classes: []string{
				"com/google/firebase/analytics/FirebaseAnalytics",
				"com/google/firebase/analytics/connector/AnalyticsConnector",
			},
			wantSDK:  "Firebase Analytics",
			wantCat:  CategoryAnalytics,
			wantConf: 90.0,
		},
		{
			name:     "AdMob",
			classes:  []string{"com/google/android/gms/ads/AdView"},
			wantSDK:  "AdMob",
			wantCat:  CategoryAds,
			wantConf: 70.0,
		},
		{
			name:     "AppsFlyer",
			classes:  []string{"com/appsflyer/AppsFlyerLib"},
			wantSDK:  "AppsFlyer",
			wantCat:  CategoryAttribution,
			wantConf: 70.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dexClasses := make([]dex.ClassDef, len(tt.classes))
			for i, className := range tt.classes {
				dexClasses[i] = dex.ClassDef{ClassName: className}
			}

			dexResult := &dex.ParseResult{
				DexFiles: []dex.DexFile{
					{Classes: dexClasses},
				},
			}

			sdks := DetectSDKs(dexResult)

			if len(sdks) == 0 {
				t.Fatal("expected at least one SDK to be detected")
			}

			found := false
			for _, sdk := range sdks {
				if sdk.Name == tt.wantSDK {
					found = true
					if sdk.Category != tt.wantCat {
						t.Errorf("category = %v, want %v", sdk.Category, tt.wantCat)
					}
					if sdk.Confidence != tt.wantConf {
						t.Errorf("confidence = %v, want %v", sdk.Confidence, tt.wantConf)
					}
					if len(sdk.Evidence) == 0 {
						t.Error("expected evidence to be populated")
					}
					break
				}
			}

			if !found {
				t.Errorf("SDK %q not found in results", tt.wantSDK)
			}
		})
	}
}

func TestDetectSDKs_NoMatch(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "com/example/myapp/MainActivity"},
					{ClassName: "com/example/myapp/Utils"},
				},
			},
		},
	}

	sdks := DetectSDKs(dexResult)

	if len(sdks) != 0 {
		t.Errorf("expected no SDKs, got %d", len(sdks))
	}
}

func TestDetectStealth(t *testing.T) {
	tests := []struct {
		name       string
		manifest   *manifest.Manifest
		dexClasses []string
		wantType   string
		wantRisk   string
	}{
		{
			name: "Accessibility Service",
			manifest: &manifest.Manifest{
				Components: []manifest.Component{
					{
						Type: "service",
						Name: "com.example.MyAccessibilityService",
						IntentFilters: []manifest.IntentFilter{
							{
								Actions: []string{"android.accessibilityservice.AccessibilityService"},
							},
						},
					},
				},
			},
			wantType: "accessibility",
			wantRisk: "high",
		},
		{
			name: "System Alert Window",
			manifest: &manifest.Manifest{
				Permissions: []manifest.Permission{
					{Name: "android.permission.SYSTEM_ALERT_WINDOW"},
				},
			},
			wantType: "overlay",
			wantRisk: "high",
		},
		{
			name: "Device Admin",
			manifest: &manifest.Manifest{
				Components: []manifest.Component{
					{
						Type: "receiver",
						Name: "com.example.DeviceAdminReceiver",
						IntentFilters: []manifest.IntentFilter{
							{
								Actions: []string{"android.app.action.DEVICE_ADMIN_ENABLED"},
							},
						},
					},
				},
			},
			wantType: "device_admin",
			wantRisk: "high",
		},
		{
			name: "Usage Stats",
			manifest: &manifest.Manifest{
				Permissions: []manifest.Permission{
					{Name: "android.permission.PACKAGE_USAGE_STATS"},
				},
			},
			wantType: "usage_stats",
			wantRisk: "medium",
		},
		{
			name: "SMS Interception",
			manifest: &manifest.Manifest{
				Permissions: []manifest.Permission{
					{Name: "android.permission.RECEIVE_SMS"},
					{Name: "android.permission.READ_SMS"},
				},
				Components: []manifest.Component{
					{
						Type: "receiver",
						Name: "com.example.SMSReceiver",
						IntentFilters: []manifest.IntentFilter{
							{
								Actions: []string{"android.provider.Telephony.SMS_RECEIVED"},
							},
						},
					},
				},
			},
			wantType: "sms_interception",
			wantRisk: "high",
		},
		{
			name: "Background Location",
			manifest: &manifest.Manifest{
				Permissions: []manifest.Permission{
					{Name: "android.permission.ACCESS_BACKGROUND_LOCATION"},
				},
			},
			wantType: "background_location",
			wantRisk: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dexResult *dex.ParseResult
			if len(tt.dexClasses) > 0 {
				dexClasses := make([]dex.ClassDef, len(tt.dexClasses))
				for i, className := range tt.dexClasses {
					dexClasses[i] = dex.ClassDef{ClassName: className}
				}
				dexResult = &dex.ParseResult{
					DexFiles: []dex.DexFile{
						{Classes: dexClasses},
					},
				}
			}

			features := DetectStealth(tt.manifest, dexResult)

			if len(features) == 0 {
				t.Fatal("expected at least one stealth feature to be detected")
			}

			found := false
			for _, f := range features {
				if f.Type == tt.wantType {
					found = true
					if f.Risk != tt.wantRisk {
						t.Errorf("risk = %v, want %v", f.Risk, tt.wantRisk)
					}
					if f.Description == "" {
						t.Error("expected description to be populated")
					}
					if f.Component == "" {
						t.Error("expected component to be populated")
					}
					break
				}
			}

			if !found {
				t.Errorf("stealth feature type %q not found in results", tt.wantType)
			}
		})
	}
}

func TestScanAPK(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "com/google/firebase/analytics/FirebaseAnalytics"},
					{ClassName: "com/google/android/gms/ads/AdView"},
				},
			},
		},
	}

	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.SYSTEM_ALERT_WINDOW"},
			{Name: "android.permission.PACKAGE_USAGE_STATS"},
		},
	}

	result := ScanAPK(dexResult, m)

	if result.TotalSDKs != 2 {
		t.Errorf("TotalSDKs = %d, want 2", result.TotalSDKs)
	}

	if !result.HasAnalytics {
		t.Error("expected HasAnalytics to be true")
	}

	if !result.HasAds {
		t.Error("expected HasAds to be true")
	}

	if !result.HasStealth {
		t.Error("expected HasStealth to be true")
	}

	if len(result.SDKs) != 2 {
		t.Errorf("len(SDKs) = %d, want 2", len(result.SDKs))
	}

	if len(result.StealthFeatures) == 0 {
		t.Error("expected stealth features to be detected")
	}
}

func TestDetectSDKs_AllCategories(t *testing.T) {
	tests := []struct {
		name    string
		classes []string
		wantSDK string
		wantCat SDKCategory
	}{
		{
			name:    "Crash - Sentry",
			classes: []string{"io/sentry/android/SentryAndroid"},
			wantSDK: "Sentry",
			wantCat: CategoryCrash,
		},
		{
			name:    "Crash - Firebase Crashlytics",
			classes: []string{"com/google/firebase/crashlytics/FirebaseCrashlytics"},
			wantSDK: "Firebase Crashlytics",
			wantCat: CategoryCrash,
		},
		{
			name:    "Push - OneSignal",
			classes: []string{"com/onesignal/OneSignal"},
			wantSDK: "OneSignal",
			wantCat: CategoryPush,
		},
		{
			name:    "Push - Firebase Cloud Messaging",
			classes: []string{"com/google/firebase/messaging/FirebaseMessaging"},
			wantSDK: "Firebase Cloud Messaging",
			wantCat: CategoryPush,
		},
		{
			name:    "Attribution - Adjust",
			classes: []string{"com/adjust/sdk/Adjust"},
			wantSDK: "Adjust",
			wantCat: CategoryAttribution,
		},
		{
			name:    "Attribution - Branch",
			classes: []string{"io/branch/referral/Branch"},
			wantSDK: "Branch",
			wantCat: CategoryAttribution,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dexClasses := make([]dex.ClassDef, len(tt.classes))
			for i, cn := range tt.classes {
				dexClasses[i] = dex.ClassDef{ClassName: cn}
			}

			sdks := DetectSDKs(&dex.ParseResult{
				DexFiles: []dex.DexFile{{Classes: dexClasses}},
			})

			found := false
			for _, sdk := range sdks {
				if sdk.Name == tt.wantSDK {
					found = true
					if sdk.Category != tt.wantCat {
						t.Errorf("category = %v, want %v", sdk.Category, tt.wantCat)
					}
					break
				}
			}
			if !found {
				t.Errorf("SDK %q not found", tt.wantSDK)
			}
		})
	}
}

func TestDetectSDKs_ConfidenceThresholds(t *testing.T) {
	t.Run("single evidence = 70%", func(t *testing.T) {
		sdks := DetectSDKs(&dex.ParseResult{
			DexFiles: []dex.DexFile{{
				Classes: []dex.ClassDef{
					{ClassName: "com/mixpanel/android/Mixpanel"},
				},
			}},
		})

		for _, sdk := range sdks {
			if sdk.Name == "Mixpanel" {
				if sdk.Confidence != 70.0 {
					t.Errorf("single evidence confidence = %v, want 70", sdk.Confidence)
				}
				return
			}
		}
		t.Error("Mixpanel not found")
	})

	t.Run("multiple evidence = 90%", func(t *testing.T) {
		sdks := DetectSDKs(&dex.ParseResult{
			DexFiles: []dex.DexFile{{
				Classes: []dex.ClassDef{
					{ClassName: "com/mixpanel/android/Mixpanel"},
					{ClassName: "com/mixpanel/android/MixpanelAPI"},
				},
			}},
		})

		for _, sdk := range sdks {
			if sdk.Name == "Mixpanel" {
				if sdk.Confidence != 90.0 {
					t.Errorf("multiple evidence confidence = %v, want 90", sdk.Confidence)
				}
				return
			}
		}
		t.Error("Mixpanel not found")
	})
}

func TestDetectSDKs_MultiDEX(t *testing.T) {
	sdks := DetectSDKs(&dex.ParseResult{
		DexFiles: []dex.DexFile{
			{Classes: []dex.ClassDef{{ClassName: "com/google/firebase/analytics/FirebaseAnalytics"}}},
			{Classes: []dex.ClassDef{{ClassName: "io/sentry/android/SentryAndroid"}}},
		},
	})

	names := make(map[string]bool)
	for _, sdk := range sdks {
		names[sdk.Name] = true
	}

	if !names["Firebase Analytics"] {
		t.Error("expected Firebase Analytics from first DEX")
	}
	if !names["Sentry"] {
		t.Error("expected Sentry from second DEX")
	}
}

func TestDetectStealth_OverlayViaDEX(t *testing.T) {
	m := &manifest.Manifest{}
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Methods: []dex.MethodRef{
				{ClassName: "LWindowManager$TYPE_APPLICATION_OVERLAY;", Name: "addView"},
			},
		}},
	}

	features := DetectStealth(m, dexResult)

	found := false
	for _, f := range features {
		if f.Type == "overlay" {
			found = true
			if f.Risk != "high" {
				t.Errorf("risk = %v, want high", f.Risk)
			}
		}
	}
	if !found {
		t.Error("expected overlay detection via DEX method class name")
	}
}

func TestDetectStealth_ScreenCaptureViaDEX(t *testing.T) {
	m := &manifest.Manifest{}
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Landroid/media/projection/MediaProjectionManager;"},
			},
		}},
	}

	features := DetectStealth(m, dexResult)

	found := false
	for _, f := range features {
		if f.Type == "screen_capture" {
			found = true
			if f.Component != "MediaProjectionManager" {
				t.Errorf("component = %v, want MediaProjectionManager", f.Component)
			}
		}
	}
	if !found {
		t.Error("expected screen_capture detection via DEX class")
	}
}

func TestDetectStealth_SMSReceiverWithPermission(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.RECEIVE_SMS"},
		},
		Components: []manifest.Component{
			{
				Type: "receiver",
				Name: "com.example.MySMSReceiver",
				IntentFilters: []manifest.IntentFilter{
					{Actions: []string{"android.provider.Telephony.SMS_RECEIVED"}},
				},
			},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "sms_interception" {
			found = true
			if f.Component != "com.example.MySMSReceiver" {
				t.Errorf("component = %v, want com.example.MySMSReceiver", f.Component)
			}
		}
	}
	if !found {
		t.Error("expected sms_interception detection")
	}
}

func TestDetectStealth_InstallPackages(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.REQUEST_INSTALL_PACKAGES"},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "install_packages" {
			found = true
			if f.Risk != "medium" {
				t.Errorf("risk = %v, want medium", f.Risk)
			}
		}
	}
	if !found {
		t.Error("expected install_packages detection")
	}
}

func TestDetectStealth_AccessibilityViaDEX(t *testing.T) {
	m := &manifest.Manifest{}
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lcom/example/MyAccessibilityService;"},
			},
		}},
	}

	features := DetectStealth(m, dexResult)

	found := false
	for _, f := range features {
		if f.Type == "accessibility" {
			found = true
			if f.Description != "Custom accessibility service implementation detected" {
				t.Errorf("unexpected description: %s", f.Description)
			}
		}
	}
	if !found {
		t.Error("expected accessibility detection via DEX class")
	}
}

func TestDetectStealth_AccessibilityViaDEX_AlreadyFromManifest(t *testing.T) {
	m := &manifest.Manifest{
		Components: []manifest.Component{
			{
				Type: "service",
				Name: "com.example.MyAccessibilityService",
				IntentFilters: []manifest.IntentFilter{
					{Actions: []string{"android.accessibilityservice.AccessibilityService"}},
				},
			},
		},
	}
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lcom/example/MyAccessibilityService;"},
			},
		}},
	}

	features := DetectStealth(m, dexResult)

	count := 0
	for _, f := range features {
		if f.Type == "accessibility" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 accessibility feature, got %d", count)
	}
}

func TestDetectStealth_DeviceAdminViaPermission(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.BIND_DEVICE_ADMIN"},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "device_admin" {
			found = true
			if f.Component != "BIND_DEVICE_ADMIN" {
				t.Errorf("component = %v, want BIND_DEVICE_ADMIN", f.Component)
			}
		}
	}
	if !found {
		t.Error("expected device_admin via BIND_DEVICE_ADMIN permission")
	}
}

func TestDetectStealth_DeviceAdminBothIntentAndPerm(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.BIND_DEVICE_ADMIN"},
		},
		Components: []manifest.Component{
			{
				Type: "receiver",
				Name: "com.example.AdminReceiver",
				IntentFilters: []manifest.IntentFilter{
					{Actions: []string{"android.app.action.DEVICE_ADMIN_ENABLED"}},
				},
			},
		},
	}

	features := DetectStealth(m, nil)

	count := 0
	for _, f := range features {
		if f.Type == "device_admin" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 device_admin feature (dedup), got %d", count)
	}
}

func TestDetectStealth_SMSPermWithoutReceiver(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.RECEIVE_SMS"},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "sms_interception" && f.Component == "SMS permissions" {
			found = true
		}
	}
	if !found {
		t.Error("expected sms_interception fallback without receiver")
	}
}

func TestDetectStealth_CallInterceptionWithReceiver(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.PROCESS_OUTGOING_CALLS"},
		},
		Components: []manifest.Component{
			{
				Type: "receiver",
				Name: "com.example.CallReceiver",
				IntentFilters: []manifest.IntentFilter{
					{Actions: []string{"android.intent.action.NEW_OUTGOING_CALL"}},
				},
			},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "call_interception" && f.Component == "com.example.CallReceiver" {
			found = true
		}
	}
	if !found {
		t.Error("expected call_interception with receiver component")
	}
}

func TestDetectStealth_CallInterceptionWithoutReceiver(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.READ_CALL_LOG"},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "call_interception" && f.Component == "Call permissions" {
			found = true
		}
	}
	if !found {
		t.Error("expected call_interception fallback without receiver")
	}
}

func TestDetectStealth_ScreenCaptureViaPermission(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.CAPTURE_VIDEO_OUTPUT"},
		},
	}

	features := DetectStealth(m, nil)

	found := false
	for _, f := range features {
		if f.Type == "screen_capture" {
			found = true
		}
	}
	if !found {
		t.Error("expected screen_capture via permission")
	}
}

func TestDetectStealth_ScreenCaptureBothPermAndDEX(t *testing.T) {
	m := &manifest.Manifest{
		Permissions: []manifest.Permission{
			{Name: "android.permission.CAPTURE_VIDEO_OUTPUT"},
		},
	}
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Landroid/media/projection/MediaProjectionManager;"},
			},
		}},
	}

	features := DetectStealth(m, dexResult)

	count := 0
	for _, f := range features {
		if f.Type == "screen_capture" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 screen_capture (dedup), got %d", count)
	}
}

func TestDetectSDKs_Nil(t *testing.T) {
	sdks := DetectSDKs(nil)
	if sdks != nil {
		t.Errorf("expected nil for nil dexResult, got %d", len(sdks))
	}
}

func TestDetectSDKs_EvidenceCap(t *testing.T) {
	classes := make([]dex.ClassDef, 10)
	for i := range classes {
		classes[i] = dex.ClassDef{ClassName: "com/google/firebase/analytics/Class" + string(rune('A'+i))}
	}

	sdks := DetectSDKs(&dex.ParseResult{
		DexFiles: []dex.DexFile{{Classes: classes}},
	})

	for _, sdk := range sdks {
		if sdk.Name == "Firebase Analytics" {
			if len(sdk.Evidence) > 5 {
				t.Errorf("evidence should be capped at 5, got %d", len(sdk.Evidence))
			}
			return
		}
	}
	t.Error("Firebase Analytics not found")
}

func TestDetectStealth_NilManifest(t *testing.T) {
	features := DetectStealth(nil, nil)
	if features != nil {
		t.Errorf("expected nil for nil manifest, got %d features", len(features))
	}
}
