/*
Copyright (c) 2026 Security Research
*/
package manifest

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestParseAXML_TooShort(t *testing.T) {
	_, err := ParseAXML([]byte{0x03, 0x00})
	if err == nil {
		t.Fatal("expected error for data too short")
	}
}

func TestParseAXML_InvalidMagic(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 0xFFFF)
	binary.LittleEndian.Uint16(data[2:4])
	binary.LittleEndian.PutUint32(data[4:8], 16)

	_, err := ParseAXML(data)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestParseAXML_MinimalValid(t *testing.T) {
	axml := buildTestAXML()

	m, err := ParseAXML(axml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Package != "com.test.app" {
		t.Errorf("expected package 'com.test.app', got %q", m.Package)
	}

	if m.VersionCode != 42 {
		t.Errorf("expected versionCode 42, got %d", m.VersionCode)
	}

	if m.VersionName != "1.2.3" {
		t.Errorf("expected versionName '1.2.3', got %q", m.VersionName)
	}

	if m.MinSDK != 21 {
		t.Errorf("expected minSdk 21, got %d", m.MinSDK)
	}

	if m.TargetSDK != 34 {
		t.Errorf("expected targetSdk 34, got %d", m.TargetSDK)
	}
}

func TestParseAXML_Permissions(t *testing.T) {
	axml := buildTestAXML()

	m, err := ParseAXML(axml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(m.Permissions))
	}

	found := map[string]string{}
	for _, p := range m.Permissions {
		found[p.Name] = p.RiskLevel
	}

	if found["android.permission.INTERNET"] != "normal" {
		t.Errorf("expected INTERNET to be 'normal', got %q", found["android.permission.INTERNET"])
	}

	if found["android.permission.CAMERA"] != "dangerous" {
		t.Errorf("expected CAMERA to be 'dangerous', got %q", found["android.permission.CAMERA"])
	}
}

func TestParseAXML_SecurityFlags(t *testing.T) {
	axml := buildTestAXML()

	m, err := ParseAXML(axml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !m.Security.Debuggable {
		t.Error("expected debuggable to be true")
	}

	if m.Security.AllowBackup {
		t.Error("expected allowBackup to be false")
	}
}

func TestParseAXML_Components(t *testing.T) {
	axml := buildTestAXML()

	m, err := ParseAXML(axml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(m.Components))
	}

	comp := m.Components[0]
	if comp.Name != "com.test.app.MainActivity" {
		t.Errorf("expected activity name 'com.test.app.MainActivity', got %q", comp.Name)
	}

	if comp.Type != ComponentActivity {
		t.Errorf("expected type 'activity', got %q", comp.Type)
	}
}

func TestParseAPK_NotFound(t *testing.T) {
	_, err := ParseAPK("/nonexistent/test.apk")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestParseAPK_NoManifest(t *testing.T) {
	apkPath := filepath.Join(t.TempDir(), "no_manifest.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	w, _ := zw.Create("classes.dex")
	_, _ = w.Write([]byte("dex\n035\x00"))
	_ = zw.Close()
	_ = f.Close()

	_, err = ParseAPK(apkPath)
	if err == nil {
		t.Fatal("expected error for APK without manifest")
	}
}

func TestParseAPK_WithManifest(t *testing.T) {
	axml := buildTestAXML()

	apkPath := filepath.Join(t.TempDir(), "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	w, _ := zw.Create("AndroidManifest.xml")
	_, _ = w.Write(axml)
	_ = zw.Close()
	_ = f.Close()

	m, err := ParseAPK(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Package != "com.test.app" {
		t.Errorf("expected package 'com.test.app', got %q", m.Package)
	}
}

func TestClassifyPermission(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"android.permission.CAMERA", "dangerous"},
		{"android.permission.INTERNET", "normal"},
		{"android.permission.INSTALL_PACKAGES", "signature"},
		{"com.custom.permission.DO_STUFF", "unknown"},
		{"android.permission.READ_EXTERNAL_STORAGE", "dangerous"},
		{"android.permission.VIBRATE", "normal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyPermission(tt.name)
			if got != tt.expected {
				t.Errorf("ClassifyPermission(%q) = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

func TestParseAXML_WithFeatureAndService(t *testing.T) {
	axml := buildTestAXMLWithFeature()

	m, err := ParseAXML(axml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(m.Features) != 1 {
		t.Fatalf("expected 1 feature, got %d", len(m.Features))
	}
	if m.Features[0] != "android.hardware.camera" {
		t.Errorf("expected feature 'android.hardware.camera', got %q", m.Features[0])
	}

	// Check for service and receiver components
	serviceFound := false
	receiverFound := false
	for _, c := range m.Components {
		if c.Type == ComponentService {
			serviceFound = true
		}
		if c.Type == ComponentReceiver {
			receiverFound = true
		}
	}
	if !serviceFound {
		t.Error("expected a service component")
	}
	if !receiverFound {
		t.Error("expected a receiver component")
	}
}

func TestParseAXML_UTF16StringPool(t *testing.T) {
	// Build a minimal AXML with UTF-16 string pool
	strs := []string{
		"",          // 0
		"manifest",  // 1
		"package",   // 2
		"com.utf16", // 3
	}

	spChunk := buildUTF16StringPoolChunk(strs)
	ridChunk := buildResourceIDChunk([]uint32{0, 0, 0, 0})

	var xmlChunks []byte
	// <manifest package="com.utf16">
	xmlChunks = append(xmlChunks, buildElementStart(-1, 1, []testAttr{
		{nsIdx: -1, nameIdx: 2, valueStrIdx: 3, valueType: typeString, valueData: 3},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 1)...)

	totalSize := 8 + len(spChunk) + len(ridChunk) + len(xmlChunks)
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], chunkResXMLType)
	binary.LittleEndian.PutUint16(header[2:4], 8)
	binary.LittleEndian.PutUint32(header[4:8], uint32(totalSize))

	var buf []byte
	buf = append(buf, header...)
	buf = append(buf, spChunk...)
	buf = append(buf, ridChunk...)
	buf = append(buf, xmlChunks...)

	m, err := ParseAXML(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Package != "com.utf16" {
		t.Errorf("expected package 'com.utf16', got %q", m.Package)
	}
}

func TestDecodeUTF16String(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"too short", []byte{0x01}, ""},
		{"simple ascii", func() []byte {
			// charLen=5, then UTF-16LE "hello", then null
			b := make([]byte, 2+5*2+2)
			binary.LittleEndian.PutUint16(b[0:2], 5)
			for i, c := range "hello" {
				binary.LittleEndian.PutUint16(b[2+i*2:], uint16(c))
			}
			return b
		}(), "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeUTF16String(tt.data)
			if got != tt.want {
				t.Errorf("decodeUTF16String = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAXML_WithNetworkSecurityConfig(t *testing.T) {
	// Build AXML with application having networkSecurityConfig (reference type),
	// usesCleartextTraffic, and an exported provider with permission
	strs := []string{
		"", // 0
		"http://schemas.android.com/apk/res/android", // 1
		"manifest",                // 2
		"package",                 // 3
		"com.test.nsc",            // 4
		"application",             // 5
		"debuggable",              // 6
		"allowBackup",             // 7
		"usesCleartextTraffic",    // 8
		"networkSecurityConfig",   // 9
		"provider",                // 10
		"name",                    // 11
		"com.test.nsc.MyProvider", // 12
		"exported",                // 13
		"permission",              // 14
		"com.test.READ",           // 15
		"android",                 // 16
	}

	resourceIDs := []uint32{
		0, 0, 0, 0, 0, 0,
		attrDebuggable,            // 6
		attrAllowBackup,           // 7
		attrUsesCleartextTraffic,  // 8
		attrNetworkSecurityConfig, // 9
		0,                         // 10
		attrName,                  // 11
		0,                         // 12
		attrExported,              // 13
		attrPermission,            // 14
		0,                         // 15
		0,                         // 16
	}

	spChunk := buildStringPoolChunk(strs)
	ridChunk := buildResourceIDChunk(resourceIDs)

	var xmlChunks []byte
	xmlChunks = append(xmlChunks, buildNamespaceChunk(chunkXMLNamespaceStart, 16, 1)...)

	// <manifest>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 2, []testAttr{
		{nsIdx: -1, nameIdx: 3, valueStrIdx: 4, valueType: typeString, valueData: 4},
	})...)

	// <application debuggable=false allowBackup=true usesCleartextTraffic=true networkSecurityConfig=@ref>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 5, []testAttr{
		{nsIdx: 1, nameIdx: 6, valueStrIdx: -1, valueType: typeBool, valueData: 0},
		{nsIdx: 1, nameIdx: 7, valueStrIdx: -1, valueType: typeBool, valueData: 0xFFFFFFFF},
		{nsIdx: 1, nameIdx: 8, valueStrIdx: -1, valueType: typeBool, valueData: 0xFFFFFFFF},
		{nsIdx: 1, nameIdx: 9, valueStrIdx: -1, valueType: typeReference, valueData: 0x7F0A0001},
	})...)

	// <provider name="..." exported="true" permission="com.test.READ"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 10, []testAttr{
		{nsIdx: 1, nameIdx: 11, valueStrIdx: 12, valueType: typeString, valueData: 12},
		{nsIdx: 1, nameIdx: 13, valueStrIdx: -1, valueType: typeBool, valueData: 0xFFFFFFFF},
		{nsIdx: 1, nameIdx: 14, valueStrIdx: 15, valueType: typeString, valueData: 15},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 10)...)

	// </application>
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 5)...)
	// </manifest>
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 2)...)
	xmlChunks = append(xmlChunks, buildNamespaceChunk(chunkXMLNamespaceEnd, 16, 1)...)

	totalSize := 8 + len(spChunk) + len(ridChunk) + len(xmlChunks)
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], chunkResXMLType)
	binary.LittleEndian.PutUint16(header[2:4], 8)
	binary.LittleEndian.PutUint32(header[4:8], uint32(totalSize))

	var buf []byte
	buf = append(buf, header...)
	buf = append(buf, spChunk...)
	buf = append(buf, ridChunk...)
	buf = append(buf, xmlChunks...)

	m, err := ParseAXML(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.Security.UsesCleartextTraffic != true {
		t.Error("expected usesCleartextTraffic=true")
	}
	if m.Security.NetworkSecurityConfig != true {
		t.Error("expected networkSecurityConfig=true (reference attr)")
	}
	if len(m.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(m.Components))
	}
	if m.Components[0].Type != ComponentProvider {
		t.Errorf("expected provider, got %s", m.Components[0].Type)
	}
	if m.Components[0].Permission != "com.test.READ" {
		t.Errorf("expected permission 'com.test.READ', got %q", m.Components[0].Permission)
	}
	if m.Components[0].Exported == nil || !*m.Components[0].Exported {
		t.Error("expected exported=true")
	}
}

func TestDecodeUTF8String_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"too short", []byte{0x01}, ""},
		{"zero length", []byte{0x00, 0x00}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeUTF8String(tt.data)
			if got != tt.want {
				t.Errorf("decodeUTF8String = %q, want %q", got, tt.want)
			}
		})
	}
}

// buildUTF16StringPoolChunk creates a UTF-16 string pool chunk.
func buildUTF16StringPoolChunk(strs []string) []byte {
	stringCount := len(strs)

	var stringData []byte
	offsets := make([]uint32, stringCount)

	for i, s := range strs {
		offsets[i] = uint32(len(stringData))
		// UTF-16 format: charLen (2 bytes), data (charLen*2 bytes), null (2 bytes)
		sLen := len(s)
		var entry []byte
		lenBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBytes, uint16(sLen))
		entry = append(entry, lenBytes...)
		for _, c := range s {
			cb := make([]byte, 2)
			binary.LittleEndian.PutUint16(cb, uint16(c))
			entry = append(entry, cb...)
		}
		entry = append(entry, 0, 0) // null terminator
		stringData = append(stringData, entry...)
	}

	headerSize := 28
	offsetsSize := stringCount * 4
	stringsStart := headerSize + offsetsSize
	chunkSize := stringsStart + len(stringData)

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkStringPool)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(stringCount))
	binary.LittleEndian.PutUint32(buf[12:16], 0) // style count
	binary.LittleEndian.PutUint32(buf[16:20], 0) // flags: UTF-16 (no UTF-8 flag)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(stringsStart))
	binary.LittleEndian.PutUint32(buf[24:28], 0)

	for i, off := range offsets {
		binary.LittleEndian.PutUint32(buf[headerSize+i*4:], off)
	}

	copy(buf[stringsStart:], stringData)

	return buf
}

// buildTestAXMLWithFeature creates AXML with uses-feature, service, and receiver.
func buildTestAXMLWithFeature() []byte {
	strings := []string{
		"", // 0
		"http://schemas.android.com/apk/res/android", // 1
		"manifest",                     // 2
		"package",                      // 3
		"com.test.features",            // 4
		"uses-feature",                 // 5
		"name",                         // 6
		"android.hardware.camera",      // 7
		"application",                  // 8
		"service",                      // 9
		"com.test.features.MyService",  // 10
		"receiver",                     // 11
		"com.test.features.MyReceiver", // 12
		"android",                      // 13
		"debuggable",                   // 14
		"allowBackup",                  // 15
	}

	resourceIDs := []uint32{
		0, 0, 0, 0, 0, 0,
		attrName, // 6: "name"
		0, 0, 0, 0, 0, 0, 0,
		attrDebuggable,  // 14
		attrAllowBackup, // 15
	}

	var buf []byte
	spChunk := buildStringPoolChunk(strings)
	ridChunk := buildResourceIDChunk(resourceIDs)

	var xmlChunks []byte

	// Namespace
	xmlChunks = append(xmlChunks, buildNamespaceChunk(chunkXMLNamespaceStart, 13, 1)...)

	// <manifest package="com.test.features">
	xmlChunks = append(xmlChunks, buildElementStart(-1, 2, []testAttr{
		{nsIdx: -1, nameIdx: 3, valueStrIdx: 4, valueType: typeString, valueData: 4},
	})...)

	// <uses-feature android:name="android.hardware.camera"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 5, []testAttr{
		{nsIdx: 1, nameIdx: 6, valueStrIdx: 7, valueType: typeString, valueData: 7},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 5)...)

	// <application>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 8, []testAttr{
		{nsIdx: 1, nameIdx: 14, valueStrIdx: -1, valueType: typeBool, valueData: 0},
		{nsIdx: 1, nameIdx: 15, valueStrIdx: -1, valueType: typeBool, valueData: 0},
	})...)

	// <service android:name="com.test.features.MyService"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 9, []testAttr{
		{nsIdx: 1, nameIdx: 6, valueStrIdx: 10, valueType: typeString, valueData: 10},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 9)...)

	// <receiver android:name="com.test.features.MyReceiver"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 11, []testAttr{
		{nsIdx: 1, nameIdx: 6, valueStrIdx: 12, valueType: typeString, valueData: 12},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 11)...)

	// </application>
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 8)...)

	// </manifest>
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 2)...)

	xmlChunks = append(xmlChunks, buildNamespaceChunk(chunkXMLNamespaceEnd, 13, 1)...)

	totalSize := 8 + len(spChunk) + len(ridChunk) + len(xmlChunks)
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], chunkResXMLType)
	binary.LittleEndian.PutUint16(header[2:4], 8)
	binary.LittleEndian.PutUint32(header[4:8], uint32(totalSize))

	buf = append(buf, header...)
	buf = append(buf, spChunk...)
	buf = append(buf, ridChunk...)
	buf = append(buf, xmlChunks...)

	return buf
}

// --- AXML builder for test fixtures ---

// buildTestAXML creates a minimal but valid binary XML fixture that represents:
//
//	<manifest package="com.test.app" versionCode="42" versionName="1.2.3">
//	  <uses-sdk minSdkVersion="21" targetSdkVersion="34"/>
//	  <uses-permission android:name="android.permission.INTERNET"/>
//	  <uses-permission android:name="android.permission.CAMERA"/>
//	  <application android:debuggable="true" android:allowBackup="false">
//	    <activity android:name="com.test.app.MainActivity"/>
//	  </application>
//	</manifest>
func buildTestAXML() []byte {
	// String pool entries (order matters — indices are used by elements).
	strings := []string{
		"", // 0
		"http://schemas.android.com/apk/res/android", // 1 (android namespace URI)
		"manifest",                    // 2
		"package",                     // 3
		"com.test.app",                // 4
		"versionCode",                 // 5
		"versionName",                 // 6
		"1.2.3",                       // 7
		"uses-sdk",                    // 8
		"minSdkVersion",               // 9
		"targetSdkVersion",            // 10
		"uses-permission",             // 11
		"name",                        // 12
		"android.permission.INTERNET", // 13
		"android.permission.CAMERA",   // 14
		"application",                 // 15
		"debuggable",                  // 16
		"allowBackup",                 // 17
		"activity",                    // 18
		"com.test.app.MainActivity",   // 19
		"android",                     // 20 (namespace prefix)
	}

	// Resource IDs — parallel to string pool entries where applicable.
	// Each string index maps to an Android resource ID (0 if not applicable).
	resourceIDs := []uint32{
		0,                    // 0: ""
		0,                    // 1: namespace URI
		0,                    // 2: "manifest"
		0,                    // 3: "package"
		0,                    // 4: package value
		attrVersionCode,      // 5: "versionCode"
		attrVersionName,      // 6: "versionName"
		0,                    // 7: version value
		0,                    // 8: "uses-sdk"
		attrMinSdkVersion,    // 9: "minSdkVersion"
		attrTargetSdkVersion, // 10: "targetSdkVersion"
		0,                    // 11: "uses-permission"
		attrName,             // 12: "name"
		0,                    // 13: perm value
		0,                    // 14: perm value
		0,                    // 15: "application"
		attrDebuggable,       // 16: "debuggable"
		attrAllowBackup,      // 17: "allowBackup"
		0,                    // 18: "activity"
		0,                    // 19: activity name value
		0,                    // 20: namespace prefix
	}

	var buf []byte

	// Build string pool chunk.
	spChunk := buildStringPoolChunk(strings)

	// Build resource ID table chunk.
	ridChunk := buildResourceIDChunk(resourceIDs)

	// Build XML chunks.
	var xmlChunks []byte

	// Namespace start: prefix=20("android"), uri=1
	xmlChunks = append(xmlChunks, buildNamespaceChunk(chunkXMLNamespaceStart, 20, 1)...)

	// <manifest package="com.test.app" versionCode="42" versionName="1.2.3">
	xmlChunks = append(xmlChunks, buildElementStart(-1, 2, []testAttr{
		{nsIdx: -1, nameIdx: 3, valueStrIdx: 4, valueType: typeString, valueData: 4}, // package
		{nsIdx: 1, nameIdx: 5, valueStrIdx: -1, valueType: typeInt, valueData: 42},   // versionCode
		{nsIdx: 1, nameIdx: 6, valueStrIdx: 7, valueType: typeString, valueData: 7},  // versionName
	})...)

	// <uses-sdk minSdkVersion="21" targetSdkVersion="34"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 8, []testAttr{
		{nsIdx: 1, nameIdx: 9, valueStrIdx: -1, valueType: typeInt, valueData: 21},  // minSdkVersion
		{nsIdx: 1, nameIdx: 10, valueStrIdx: -1, valueType: typeInt, valueData: 34}, // targetSdkVersion
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 8)...)

	// <uses-permission android:name="android.permission.INTERNET"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 11, []testAttr{
		{nsIdx: 1, nameIdx: 12, valueStrIdx: 13, valueType: typeString, valueData: 13},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 11)...)

	// <uses-permission android:name="android.permission.CAMERA"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 11, []testAttr{
		{nsIdx: 1, nameIdx: 12, valueStrIdx: 14, valueType: typeString, valueData: 14},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 11)...)

	// <application android:debuggable="true" android:allowBackup="false">
	xmlChunks = append(xmlChunks, buildElementStart(-1, 15, []testAttr{
		{nsIdx: 1, nameIdx: 16, valueStrIdx: -1, valueType: typeBool, valueData: 0xFFFFFFFF}, // debuggable=true
		{nsIdx: 1, nameIdx: 17, valueStrIdx: -1, valueType: typeBool, valueData: 0},          // allowBackup=false
	})...)

	// <activity android:name="com.test.app.MainActivity"/>
	xmlChunks = append(xmlChunks, buildElementStart(-1, 18, []testAttr{
		{nsIdx: 1, nameIdx: 12, valueStrIdx: 19, valueType: typeString, valueData: 19},
	})...)
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 18)...)

	// </application>
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 15)...)

	// </manifest>
	xmlChunks = append(xmlChunks, buildElementEnd(-1, 2)...)

	// Namespace end.
	xmlChunks = append(xmlChunks, buildNamespaceChunk(chunkXMLNamespaceEnd, 20, 1)...)

	// Assemble the full AXML document.
	totalSize := 8 + len(spChunk) + len(ridChunk) + len(xmlChunks)

	// File header: type=0x0003, headerSize=8, totalSize
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], chunkResXMLType)
	binary.LittleEndian.PutUint16(header[2:4], 8) // header size
	binary.LittleEndian.PutUint32(header[4:8], uint32(totalSize))

	buf = append(buf, header...)
	buf = append(buf, spChunk...)
	buf = append(buf, ridChunk...)
	buf = append(buf, xmlChunks...)

	return buf
}

type testAttr struct {
	nsIdx       int32
	nameIdx     int32
	valueStrIdx int32
	valueType   uint32
	valueData   uint32
}

// buildStringPoolChunk creates a UTF-8 string pool chunk.
func buildStringPoolChunk(strs []string) []byte {
	stringCount := len(strs)

	// Calculate string data.
	var stringData []byte

	offsets := make([]uint32, stringCount)

	for i, s := range strs {
		offsets[i] = uint32(len(stringData))
		// UTF-8 format: charLen (1 byte), byteLen (1 byte), data, null.
		sLen := len(s)
		if sLen > 127 {
			stringData = append(stringData, byte(0x80|sLen>>8), byte(sLen&0xFF))
			stringData = append(stringData, byte(0x80|sLen>>8), byte(sLen&0xFF))
		} else {
			stringData = append(stringData, byte(sLen)) // char length
			stringData = append(stringData, byte(sLen)) // byte length
		}

		stringData = append(stringData, []byte(s)...)
		stringData = append(stringData, 0) // null terminator
	}

	// Chunk layout:
	// Header: type(2) + headerSize(2) + chunkSize(4) = 8
	// stringCount(4) + styleCount(4) + flags(4) + stringsStart(4) + stylesStart(4) = 20
	// offsets: stringCount * 4
	// string data

	headerSize := 28
	offsetsSize := stringCount * 4
	stringsStart := headerSize + offsetsSize

	chunkSize := stringsStart + len(stringData)

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkStringPool)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(stringCount))
	binary.LittleEndian.PutUint32(buf[12:16], 0)                    // style count
	binary.LittleEndian.PutUint32(buf[16:20], 1<<8)                 // flags: UTF-8
	binary.LittleEndian.PutUint32(buf[20:24], uint32(stringsStart)) // strings start
	binary.LittleEndian.PutUint32(buf[24:28], 0)                    // styles start

	for i, off := range offsets {
		binary.LittleEndian.PutUint32(buf[headerSize+i*4:], off)
	}

	copy(buf[stringsStart:], stringData)

	return buf
}

// buildResourceIDChunk creates a resource ID map chunk.
func buildResourceIDChunk(ids []uint32) []byte {
	headerSize := 8
	chunkSize := headerSize + len(ids)*4

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkResourceIDTable)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	for i, id := range ids {
		binary.LittleEndian.PutUint32(buf[headerSize+i*4:], id)
	}

	return buf
}

// buildNamespaceChunk creates a namespace start or end chunk.
func buildNamespaceChunk(chunkType uint16, prefixIdx, uriIdx int32) []byte {
	headerSize := 16
	chunkSize := headerSize + 8 // ext: prefix(4) + uri(4)

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkType)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))
	// lineNumber and comment at header[8:16] left as zero.

	binary.LittleEndian.PutUint32(buf[headerSize:], uint32(prefixIdx))
	binary.LittleEndian.PutUint32(buf[headerSize+4:], uint32(uriIdx))

	return buf
}

// buildElementStart creates an element start chunk.
func buildElementStart(nsIdx, nameIdx int32, attrs []testAttr) []byte {
	headerSize := 16
	// ext: ns(4) + name(4) + attrStart(2) + attrSize(2) + attrCount(2) + idIdx(2) + classIdx(2) + styleIdx(2) = 20
	extSize := 20
	attrSize := 20 // per attribute: ns(4) + name(4) + rawValue(4) + typedValue(8)
	chunkSize := headerSize + extSize + len(attrs)*attrSize

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkXMLElementStart)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	// ext
	off := headerSize
	binary.LittleEndian.PutUint32(buf[off:], uint32(nsIdx))
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(nameIdx))
	binary.LittleEndian.PutUint16(buf[off+8:], uint16(extSize))   // attributeStart (relative to ext start)
	binary.LittleEndian.PutUint16(buf[off+10:], uint16(attrSize)) // attributeSize
	binary.LittleEndian.PutUint16(buf[off+12:], uint16(len(attrs)))

	// Attributes.
	for i, a := range attrs {
		aOff := headerSize + extSize + i*attrSize
		binary.LittleEndian.PutUint32(buf[aOff:], uint32(a.nsIdx))
		binary.LittleEndian.PutUint32(buf[aOff+4:], uint32(a.nameIdx))
		binary.LittleEndian.PutUint32(buf[aOff+8:], uint32(a.valueStrIdx))
		// TypedValue: size(2) + res0(1) + dataType(1) + data(4)
		binary.LittleEndian.PutUint16(buf[aOff+12:], 8) // size = 8
		buf[aOff+14] = 0                                // res0
		buf[aOff+15] = byte(a.valueType)                // dataType
		binary.LittleEndian.PutUint32(buf[aOff+16:], a.valueData)
	}

	return buf
}

// buildElementEnd creates an element end chunk.
func buildElementEnd(nsIdx, nameIdx int32) []byte {
	headerSize := 16
	extSize := 8 // ns(4) + name(4)
	chunkSize := headerSize + extSize

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkXMLElementEnd)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	binary.LittleEndian.PutUint32(buf[headerSize:], uint32(nsIdx))
	binary.LittleEndian.PutUint32(buf[headerSize+4:], uint32(nameIdx))

	return buf
}
