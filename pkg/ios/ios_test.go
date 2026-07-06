package ios

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseXMLPlist
// ---------------------------------------------------------------------------

func TestParseXMLPlist(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
		check   func(t *testing.T, m map[string]any)
	}{
		{
			name: "valid plist with string, integer, bool",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.app</string>
	<key>CFBundleVersion</key>
	<string>42</string>
	<key>LSRequiresIPhoneOS</key>
	<true/>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				if m["CFBundleIdentifier"] != "com.example.app" {
					t.Errorf("CFBundleIdentifier = %v, want com.example.app", m["CFBundleIdentifier"])
				}
				if m["CFBundleVersion"] != "42" {
					t.Errorf("CFBundleVersion = %v, want 42", m["CFBundleVersion"])
				}
				if m["LSRequiresIPhoneOS"] != true {
					t.Errorf("LSRequiresIPhoneOS = %v, want true", m["LSRequiresIPhoneOS"])
				}
			},
		},
		{
			name: "integer and real values",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Count</key>
	<integer>99</integer>
	<key>Price</key>
	<real>3.14</real>
	<key>Disabled</key>
	<false/>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				if m["Count"] != int64(99) {
					t.Errorf("Count = %v (%T), want int64(99)", m["Count"], m["Count"])
				}
				f, ok := m["Price"].(float64)
				if !ok || f != 3.14 {
					t.Errorf("Price = %v, want 3.14", m["Price"])
				}
				if m["Disabled"] != false {
					t.Errorf("Disabled = %v, want false", m["Disabled"])
				}
			},
		},
		{
			name: "nested dict",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Nested</key>
	<dict>
		<key>Inner</key>
		<string>value</string>
	</dict>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				nested, ok := m["Nested"].(map[string]any)
				if !ok {
					t.Fatal("Nested is not a map")
				}
				if nested["Inner"] != "value" {
					t.Errorf("Nested.Inner = %v, want value", nested["Inner"])
				}
			},
		},
		{
			name: "array values",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>UIDeviceFamily</key>
	<array>
		<integer>1</integer>
		<integer>2</integer>
	</array>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				arr, ok := m["UIDeviceFamily"].([]any)
				if !ok {
					t.Fatal("UIDeviceFamily is not an array")
				}
				if len(arr) != 2 {
					t.Fatalf("array len = %d, want 2", len(arr))
				}
				if arr[0] != int64(1) || arr[1] != int64(2) {
					t.Errorf("array = %v, want [1, 2]", arr)
				}
			},
		},
		{
			name: "data element with base64",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Blob</key>
	<data>SGVsbG8=</data>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				if m["Blob"] != "Hello" {
					t.Errorf("Blob = %q, want Hello", m["Blob"])
				}
			},
		},
		{
			name: "date element treated as string",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Created</key>
	<date>2025-01-01T00:00:00Z</date>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				if m["Created"] != "2025-01-01T00:00:00Z" {
					t.Errorf("Created = %v, want 2025-01-01T00:00:00Z", m["Created"])
				}
			},
		},
		{
			name:    "empty data",
			data:    "",
			wantErr: "plist data too short",
		},
		{
			name:    "too short data",
			data:    "abc",
			wantErr: "plist data too short",
		},
		{
			name:    "binary plist magic",
			data:    "bplist00deadbeef",
			wantErr: "binary plist format not supported",
		},
		{
			name:    "malformed XML",
			data:    "<?xml version=\"1.0\"?><plist><dict><key>bad",
			wantErr: "xml unmarshal",
		},
		{
			name: "no root dict",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
</plist>`,
			wantErr: "no root <dict> found",
		},
		{
			name: "empty dict",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				if len(m) != 0 {
					t.Errorf("expected empty map, got %d entries", len(m))
				}
			},
		},
		{
			name: "URL schemes nested structure",
			data: `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>myapp</string>
				<string>myapp-callback</string>
			</array>
		</dict>
	</array>
</dict>
</plist>`,
			check: func(t *testing.T, m map[string]any) {
				urlTypes, ok := m["CFBundleURLTypes"].([]any)
				if !ok || len(urlTypes) != 1 {
					t.Fatal("CFBundleURLTypes missing or wrong length")
				}
				dict, ok := urlTypes[0].(map[string]any)
				if !ok {
					t.Fatal("first URL type is not a dict")
				}
				schemes, ok := dict["CFBundleURLSchemes"].([]any)
				if !ok || len(schemes) != 2 {
					t.Fatal("CFBundleURLSchemes missing or wrong length")
				}
				if schemes[0] != "myapp" || schemes[1] != "myapp-callback" {
					t.Errorf("schemes = %v, want [myapp, myapp-callback]", schemes)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseXMLPlist([]byte(tt.data))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DescribePermission
// ---------------------------------------------------------------------------

func TestDescribePermission(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"NSCameraUsageDescription", "Camera access"},
		{"NSMicrophoneUsageDescription", "Microphone access"},
		{"NSLocationWhenInUseUsageDescription", "Location (when in use)"},
		{"NSLocationAlwaysUsageDescription", "Location (always)"},
		{"NSPhotoLibraryUsageDescription", "Photo library access"},
		{"NSContactsUsageDescription", "Contacts access"},
		{"NSCalendarsUsageDescription", "Calendar access"},
		{"NSFaceIDUsageDescription", "Face ID authentication"},
		{"NSUserTrackingUsageDescription", "App tracking transparency"},
		{"NFCReaderUsageDescription", "NFC tag reading"},
		{"NSBluetoothAlwaysUsageDescription", "Bluetooth access"},
		{"NSLocalNetworkUsageDescription", "Local network discovery"},
		{"NSHealthShareUsageDescription", "HealthKit data reading"},
		{"NSMotionUsageDescription", "Motion and fitness data"},
		{"NSSpeechRecognitionUsageDescription", "Speech recognition"},
		{"NSSiriUsageDescription", "Siri integration"},
		{"NSHomeKitUsageDescription", "HomeKit access"},
		{"NSFocusStatusUsageDescription", "Focus status access"},
		{"NSLocationTemporaryUsageDescriptionDictionary", "Temporary precise location"},
		// Unknown key
		{"NSCustomThing", "NSCustomThing (unknown)"},
		{"SomeRandomKey", "SomeRandomKey (unknown)"},
		{"", " (unknown)"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := DescribePermission(tt.key)
			if got != tt.want {
				t.Errorf("DescribePermission(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helper: build a minimal IPA ZIP in memory
// ---------------------------------------------------------------------------

// buildIPA creates a minimal IPA ZIP archive with the given Info.plist content
// and optional extra files. Returns the path to the temp file.
func buildIPA(t *testing.T, plistXML string, extras map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	ipaPath := filepath.Join(dir, "test.ipa")

	f, err := os.Create(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)

	// Add the Payload/Test.app/ directory entry
	_, err = zw.Create("Payload/Test.app/")
	if err != nil {
		t.Fatal(err)
	}

	// Write Info.plist
	if plistXML != "" {
		w, err := zw.Create("Payload/Test.app/Info.plist")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(plistXML)); err != nil {
			t.Fatal(err)
		}
	}

	// Write extra files
	for name, data := range extras {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	return ipaPath
}

// minimalPlist returns a minimal valid Info.plist with the given bundle ID.
func minimalPlist(bundleID string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>` + bundleID + `</string>
	<key>CFBundleName</key>
	<string>TestApp</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>100</string>
	<key>MinimumOSVersion</key>
	<string>15.0</string>
	<key>CFBundleExecutable</key>
	<string>TestApp</string>
	<key>LSRequiresIPhoneOS</key>
	<true/>
	<key>UIDeviceFamily</key>
	<array>
		<integer>1</integer>
		<integer>2</integer>
	</array>
</dict>
</plist>`
}

// ---------------------------------------------------------------------------
// Info (IPA parsing)
// ---------------------------------------------------------------------------

func TestInfo(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
		check   func(t *testing.T, info *IPAInfo)
	}{
		{
			name: "valid minimal IPA",
			setup: func(t *testing.T) string {
				return buildIPA(t, minimalPlist("com.test.myapp"), nil)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if info.BundleID != "com.test.myapp" {
					t.Errorf("BundleID = %q, want com.test.myapp", info.BundleID)
				}
				if info.BundleName != "TestApp" {
					t.Errorf("BundleName = %q, want TestApp", info.BundleName)
				}
				if info.Version != "1.0" {
					t.Errorf("Version = %q, want 1.0", info.Version)
				}
				if info.BuildVersion != "100" {
					t.Errorf("BuildVersion = %q, want 100", info.BuildVersion)
				}
				if info.MinimumOS != "15.0" {
					t.Errorf("MinimumOS = %q, want 15.0", info.MinimumOS)
				}
				if info.Platform != "iphoneos" {
					t.Errorf("Platform = %q, want iphoneos", info.Platform)
				}
				if len(info.DeviceFamily) != 2 {
					t.Errorf("DeviceFamily len = %d, want 2", len(info.DeviceFamily))
				}
			},
		},
		{
			name: "IPA with frameworks and code signature",
			setup: func(t *testing.T) string {
				extras := map[string][]byte{
					"Payload/Test.app/Frameworks/MyLib.framework/MyLib": []byte("binary"),
					"Payload/Test.app/_CodeSignature/CodeResources":     []byte("<xml/>"),
					"Payload/Test.app/embedded.mobileprovision":         []byte("fake-provision"),
				}
				return buildIPA(t, minimalPlist("com.test.fw"), extras)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if len(info.Frameworks) != 1 || info.Frameworks[0] != "MyLib" {
					t.Errorf("Frameworks = %v, want [MyLib]", info.Frameworks)
				}
				if !info.SigningInfo.HasCodeSignature {
					t.Error("expected HasCodeSignature = true")
				}
				if !info.HasProvisioning {
					t.Error("expected HasProvisioning = true")
				}
			},
		},
		{
			name: "IPA with permissions",
			setup: func(t *testing.T) string {
				plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.test.perms</string>
	<key>CFBundleName</key>
	<string>PermsApp</string>
	<key>NSCameraUsageDescription</key>
	<string>We need your camera</string>
	<key>NSMicrophoneUsageDescription</key>
	<string>We need your mic</string>
</dict>
</plist>`
				return buildIPA(t, plist, nil)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if len(info.Permissions) < 2 {
					t.Fatalf("Permissions len = %d, want >= 2", len(info.Permissions))
				}
				found := map[string]bool{}
				for _, p := range info.Permissions {
					found[p.Key] = true
					if p.Key == "NSCameraUsageDescription" {
						if p.Usage != "We need your camera" {
							t.Errorf("camera usage = %q", p.Usage)
						}
						if p.Description != "Camera access" {
							t.Errorf("camera description = %q", p.Description)
						}
					}
				}
				if !found["NSCameraUsageDescription"] {
					t.Error("missing NSCameraUsageDescription")
				}
				if !found["NSMicrophoneUsageDescription"] {
					t.Error("missing NSMicrophoneUsageDescription")
				}
			},
		},
		{
			name: "IPA with URL schemes",
			setup: func(t *testing.T) string {
				plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.test.url</string>
	<key>CFBundleName</key>
	<string>URLApp</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>myscheme</string>
				<string>myscheme-callback</string>
			</array>
		</dict>
	</array>
</dict>
</plist>`
				return buildIPA(t, plist, nil)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if len(info.URLSchemes) != 2 {
					t.Fatalf("URLSchemes len = %d, want 2", len(info.URLSchemes))
				}
				if info.URLSchemes[0] != "myscheme" || info.URLSchemes[1] != "myscheme-callback" {
					t.Errorf("URLSchemes = %v", info.URLSchemes)
				}
			},
		},
		{
			name: "IPA with DTPlatformName",
			setup: func(t *testing.T) string {
				plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.test.platform</string>
	<key>CFBundleName</key>
	<string>PlatApp</string>
	<key>DTPlatformName</key>
	<string>iphoneos</string>
</dict>
</plist>`
				return buildIPA(t, plist, nil)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if info.Platform != "iphoneos" {
					t.Errorf("Platform = %q, want iphoneos", info.Platform)
				}
			},
		},
		{
			name: "IPA with iPad-only device family",
			setup: func(t *testing.T) string {
				plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.test.ipad</string>
	<key>CFBundleName</key>
	<string>iPadApp</string>
	<key>UIDeviceFamily</key>
	<array>
		<integer>2</integer>
	</array>
</dict>
</plist>`
				return buildIPA(t, plist, nil)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if info.Platform != "ipados" {
					t.Errorf("Platform = %q, want ipados", info.Platform)
				}
				if len(info.DeviceFamily) != 1 || info.DeviceFamily[0] != "iPad" {
					t.Errorf("DeviceFamily = %v, want [iPad]", info.DeviceFamily)
				}
			},
		},
		{
			name: "IPA with CFBundleDisplayName preferred over CFBundleName",
			setup: func(t *testing.T) string {
				plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.test.names</string>
	<key>CFBundleName</key>
	<string>ShortName</string>
	<key>CFBundleDisplayName</key>
	<string>Display Name</string>
</dict>
</plist>`
				return buildIPA(t, plist, nil)
			},
			check: func(t *testing.T, info *IPAInfo) {
				if info.BundleName != "Display Name" {
					t.Errorf("BundleName = %q, want 'Display Name'", info.BundleName)
				}
			},
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.ipa")
			},
			wantErr: "open IPA",
		},
		{
			name: "non-ZIP file",
			setup: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "notzip.ipa")
				if err := os.WriteFile(p, []byte("this is not a zip"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: "open IPA",
		},
		{
			name: "ZIP without Payload dir (no .app bundle)",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				p := filepath.Join(dir, "noapp.ipa")
				f, err := os.Create(p)
				if err != nil {
					t.Fatal(err)
				}
				zw := zip.NewWriter(f)
				w, _ := zw.Create("SomeDir/file.txt")
				_, _ = w.Write([]byte("data"))
				_ = zw.Close()
				_ = f.Close()
				return p
			},
			wantErr: "no .app bundle found",
		},
		{
			name: "IPA without Info.plist",
			setup: func(t *testing.T) string {
				return buildIPA(t, "", nil)
			},
			wantErr: "read Info.plist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			info, err := Info(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, info)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (ipaPath, outDir string)
		wantErr string
		check   func(t *testing.T, result *ExtractResult, outDir string)
	}{
		{
			name: "extract minimal IPA",
			setup: func(t *testing.T) (string, string) {
				ipa := buildIPA(t, minimalPlist("com.test.extract"), map[string][]byte{
					"Payload/Test.app/Assets.car": []byte("fake-assets"),
				})
				return ipa, filepath.Join(t.TempDir(), "out")
			},
			check: func(t *testing.T, result *ExtractResult, outDir string) {
				if result.Files == 0 {
					t.Error("expected Files > 0")
				}
				if result.AppBundle == "" {
					t.Error("expected AppBundle to be set")
				}
				// Verify Info.plist was extracted
				plistPath := filepath.Join(result.AppBundle, "Info.plist")
				if _, err := os.Stat(plistPath); err != nil {
					t.Errorf("Info.plist not extracted: %v", err)
				}
			},
		},
		{
			name: "extract non-existent file",
			setup: func(t *testing.T) (string, string) {
				return filepath.Join(t.TempDir(), "missing.ipa"), t.TempDir()
			},
			wantErr: "open IPA",
		},
		{
			name: "extract non-ZIP file",
			setup: func(t *testing.T) (string, string) {
				p := filepath.Join(t.TempDir(), "bad.ipa")
				_ = os.WriteFile(p, []byte("not a zip"), 0o644)
				return p, t.TempDir()
			},
			wantErr: "open IPA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipaPath, outDir := tt.setup(t)
			result, err := Extract(ipaPath, outDir)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result, outDir)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseMachOFromReader
// ---------------------------------------------------------------------------

func TestParseMachOFromReader(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "random bytes",
			data:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			wantErr: true,
		},
		{
			name:    "truncated header",
			data:    []byte{0xFE, 0xED, 0xFA, 0xCE}, // Mach-O magic but nothing else
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			_, err := ParseMachOFromReader(r)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Internal helpers tested through public API
// ---------------------------------------------------------------------------

func TestExtractPermissions(t *testing.T) {
	plistXML := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.test.perms</string>
	<key>CFBundleName</key>
	<string>PermsApp</string>
	<key>NSCameraUsageDescription</key>
	<string>Camera needed</string>
	<key>NFCReaderUsageDescription</key>
	<string>NFC needed</string>
	<key>NSLocationTemporaryUsageDescriptionDictionary</key>
	<dict>
		<key>Purpose</key>
		<string>temp location</string>
	</dict>
</dict>
</plist>`

	m, err := ParseXMLPlist([]byte(plistXML))
	if err != nil {
		t.Fatal(err)
	}

	perms := extractPermissions(m)
	keys := map[string]bool{}
	for _, p := range perms {
		keys[p.Key] = true
	}

	if !keys["NSCameraUsageDescription"] {
		t.Error("missing NSCameraUsageDescription")
	}
	if !keys["NFCReaderUsageDescription"] {
		t.Error("missing NFCReaderUsageDescription (NFC special case)")
	}
	if !keys["NSLocationTemporaryUsageDescriptionDictionary"] {
		t.Error("missing NSLocationTemporaryUsageDescriptionDictionary (dict-based)")
	}
}

func TestExtractURLSchemes(t *testing.T) {
	tests := []struct {
		name  string
		plist map[string]any
		want  int
	}{
		{
			name:  "no URL types key",
			plist: map[string]any{},
			want:  0,
		},
		{
			name:  "URL types is not array",
			plist: map[string]any{"CFBundleURLTypes": "not-array"},
			want:  0,
		},
		{
			name: "URL type item is not dict",
			plist: map[string]any{
				"CFBundleURLTypes": []any{"not-a-dict"},
			},
			want: 0,
		},
		{
			name: "URL type dict without schemes",
			plist: map[string]any{
				"CFBundleURLTypes": []any{
					map[string]any{"CFBundleURLName": "test"},
				},
			},
			want: 0,
		},
		{
			name: "valid schemes",
			plist: map[string]any{
				"CFBundleURLTypes": []any{
					map[string]any{
						"CFBundleURLSchemes": []any{"app1", "app2"},
					},
				},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractURLSchemes(tt.plist)
			if len(got) != tt.want {
				t.Errorf("extractURLSchemes() returned %d schemes, want %d", len(got), tt.want)
			}
		})
	}
}

func TestDetectPlatform(t *testing.T) {
	tests := []struct {
		name  string
		plist map[string]any
		want  string
	}{
		{
			name:  "DTPlatformName present",
			plist: map[string]any{"DTPlatformName": "iphoneos"},
			want:  "iphoneos",
		},
		{
			name:  "LSRequiresIPhoneOS true",
			plist: map[string]any{"LSRequiresIPhoneOS": true},
			want:  "iphoneos",
		},
		{
			name: "iPad-only family",
			plist: map[string]any{
				"UIDeviceFamily": []any{int64(2)},
			},
			want: "ipados",
		},
		{
			name:  "empty plist defaults to iphoneos",
			plist: map[string]any{},
			want:  "iphoneos",
		},
		{
			name:  "LSRequiresIPhoneOS false",
			plist: map[string]any{"LSRequiresIPhoneOS": false},
			want:  "iphoneos",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPlatform(tt.plist)
			if got != tt.want {
				t.Errorf("detectPlatform() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveDeviceFamilies(t *testing.T) {
	tests := []struct {
		name  string
		plist map[string]any
		want  []string
	}{
		{
			name:  "no UIDeviceFamily",
			plist: map[string]any{},
			want:  nil,
		},
		{
			name: "iPhone and iPad",
			plist: map[string]any{
				"UIDeviceFamily": []any{int64(1), int64(2)},
			},
			want: []string{"iPhone", "iPad"},
		},
		{
			name: "Apple TV",
			plist: map[string]any{
				"UIDeviceFamily": []any{int64(3)},
			},
			want: []string{"Apple TV"},
		},
		{
			name: "unknown family ID",
			plist: map[string]any{
				"UIDeviceFamily": []any{int64(99)},
			},
			want: []string{"Unknown (99)"},
		},
		{
			name: "Vision Pro",
			plist: map[string]any{
				"UIDeviceFamily": []any{int64(7)},
			},
			want: []string{"Apple Vision Pro"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveDeviceFamilies(tt.plist)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAppBundleName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Payload/MyApp.app/", "MyApp"},
		{"Payload/Test.app/", "Test"},
		{"Payload/", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := appBundleName(tt.input)
			if got != tt.want {
				t.Errorf("appBundleName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPlistString(t *testing.T) {
	m := map[string]any{
		"str":    "hello",
		"num":    int64(42),
		"nested": map[string]any{"k": "v"},
	}

	if got := plistString(m, "str"); got != "hello" {
		t.Errorf("plistString(str) = %q, want hello", got)
	}
	if got := plistString(m, "num"); got != "" {
		t.Errorf("plistString(num) = %q, want empty", got)
	}
	if got := plistString(m, "missing"); got != "" {
		t.Errorf("plistString(missing) = %q, want empty", got)
	}
}

func TestPlistIntArray(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want []int64
	}{
		{
			name: "missing key",
			m:    map[string]any{},
			key:  "k",
			want: nil,
		},
		{
			name: "not an array",
			m:    map[string]any{"k": "string"},
			key:  "k",
			want: nil,
		},
		{
			name: "int64 values",
			m:    map[string]any{"k": []any{int64(1), int64(2)}},
			key:  "k",
			want: []int64{1, 2},
		},
		{
			name: "float64 values (converted)",
			m:    map[string]any{"k": []any{float64(3), float64(4)}},
			key:  "k",
			want: []int64{3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plistIntArray(tt.m, tt.key)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VerifyCodeSign
// ---------------------------------------------------------------------------

func TestVerifyCodeSign(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr string
		check   func(t *testing.T, cs *CodeSignInfo)
	}{
		{
			name: "IPA with code signature",
			setup: func(t *testing.T) string {
				extras := map[string][]byte{
					"Payload/Test.app/_CodeSignature/CodeResources": []byte("<xml/>"),
				}
				return buildIPA(t, minimalPlist("com.test.signed"), extras)
			},
			check: func(t *testing.T, cs *CodeSignInfo) {
				if !cs.IsSigned {
					t.Error("expected IsSigned = true")
				}
			},
		},
		{
			name: "IPA without code signature",
			setup: func(t *testing.T) string {
				return buildIPA(t, minimalPlist("com.test.unsigned"), nil)
			},
			check: func(t *testing.T, cs *CodeSignInfo) {
				if cs.IsSigned {
					t.Error("expected IsSigned = false")
				}
			},
		},
		{
			name: "non-existent file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.ipa")
			},
			wantErr: "open IPA",
		},
		{
			name: "ZIP without .app bundle",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				p := filepath.Join(dir, "noapp.ipa")
				f, _ := os.Create(p)
				zw := zip.NewWriter(f)
				w, _ := zw.Create("Other/file.txt")
				_, _ = w.Write([]byte("data"))
				_ = zw.Close()
				_ = f.Close()
				return p
			},
			wantErr: "no .app bundle found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			cs, err := VerifyCodeSign(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractPlistFromProvision (indirectly through VerifyCodeSign)
// ---------------------------------------------------------------------------

func TestVerifyCodeSignWithEntitlements(t *testing.T) {
	entXML := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>com.apple.developer.team-identifier</key>
	<string>TEAM123</string>
	<key>application-identifier</key>
	<string>TEAM123.com.test.app</string>
</dict>
</plist>`

	extras := map[string][]byte{
		"Payload/Test.app/_CodeSignature/CodeResources":         []byte("<xml/>"),
		"Payload/Test.app/archived-expanded-entitlements.xcent": []byte(entXML),
	}
	ipaPath := buildIPA(t, minimalPlist("com.test.ent"), extras)

	cs, err := VerifyCodeSign(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.HasEntitlements {
		t.Error("expected HasEntitlements = true")
	}
	if cs.TeamID != "TEAM123" {
		t.Errorf("TeamID = %q, want TEAM123", cs.TeamID)
	}
}

func TestMachoVersionString(t *testing.T) {
	tests := []struct {
		v    uint32
		want string
	}{
		{0x000F0000, "15.0"},
		{0x000F0200, "15.2"},
		{0x000F0201, "15.2.1"},
		{0x00100000, "16.0"},
	}

	for _, tt := range tests {
		got := machoVersionString(tt.v)
		if got != tt.want {
			t.Errorf("machoVersionString(0x%08X) = %q, want %q", tt.v, got, tt.want)
		}
	}
}
