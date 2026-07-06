/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestAnalyzeAndroid_ATS_ReconciledAPKInfo_PermissionsAndComponents reproduces
// the Critical defect found in code review of commit 1730bdb7: in ATS /
// large-APK streaming mode (Run() auto-enables ATS for APK/AAB/XAPK/APKS/APKM
// via opts.TeardownDir), the "apk_info" step's clear callback
// (func() { r.APKInfo = nil }) fires as soon as the apk_info step completes —
// BEFORE manifest_info/kotlin_detection/native_analysis run. reconcileAPKInfo
// is called inside those later step closures, but by then r.APKInfo is nil,
// so its nil-guard makes every call a no-op. The manifest's permissions and
// components never reach the FINAL emitted APKInfo under ATS mode, even
// though they reach it fine in non-ATS/in-memory mode (which is why the
// existing reconcileAPKInfo unit tests, which never drive ATS, passed).
//
// This test drives the real production entrypoint (Run(), with an explicit
// TeardownDir to force ATS deterministically) against a fixture APK whose
// AndroidManifest.xml is a real, parseable binary AXML carrying 2 permissions
// and 1 component — then asserts the FINAL DissectResult.APKInfo (as ATS
// produces it, via the same reloadSummaryStepsForPrompt() flush-reload path
// Run() itself uses) carries those permissions/components.
func TestAnalyzeAndroid_ATS_ReconciledAPKInfo_PermissionsAndComponents(t *testing.T) {
	apkPath := createManifestAPKForATSTest(t)

	result, err := Run(apkPath, Options{
		TeardownDir: t.TempDir(),
		NoCache:     true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.APKInfo == nil {
		t.Fatal("expected non-nil APKInfo in final ATS result")
	}

	if len(result.APKInfo.Permissions) == 0 {
		t.Error("expected APKInfo.Permissions to carry reconciled manifest permissions under ATS mode, got empty")
	} else {
		found := false
		for _, p := range result.APKInfo.Permissions {
			if p.Name == "android.permission.CAMERA" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected APKInfo.Permissions to include android.permission.CAMERA, got %+v", result.APKInfo.Permissions)
		}
	}

	if len(result.APKInfo.Components) == 0 {
		t.Error("expected APKInfo.Components to carry reconciled manifest components under ATS mode, got empty")
	} else {
		found := false
		for _, c := range result.APKInfo.Components {
			if c.Name == "com.test.app.MainActivity" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected APKInfo.Components to include com.test.app.MainActivity, got %+v", result.APKInfo.Components)
		}
	}
}

// createManifestAPKForATSTest builds a fixture APK containing a real, binary
// AXML AndroidManifest.xml (package com.test.app, 2 permissions, 1 activity
// component) plus a minimal classes.dex entry, so androidmanifest.ParseAPK
// (the "manifest_info" step) actually succeeds and populates
// ManifestInfo.Permissions/.Components for reconcileAPKInfo to fold onto
// APKInfo.
func createManifestAPKForATSTest(t *testing.T) string {
	t.Helper()

	apkPath := filepath.Join(t.TempDir(), "manifest-test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(buildATSTestAXML()); err != nil {
		t.Fatal(err)
	}

	w, err = zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("dex\n035\x00")); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return apkPath
}

// --- Minimal binary AXML builder (mirrors
// pkg/android/manifest/manifest_test.go's buildTestAXML, duplicated here
// since those helpers are unexported test-only symbols in another package).
// Produces: package com.test.app, versionCode 42, versionName 1.2.3,
// minSdk 21, targetSdk 34, uses-permission INTERNET + CAMERA, one
// application/activity component (com.test.app.MainActivity).

const (
	atsChunkResXMLType        = 0x0003
	atsChunkStringPool        = 0x0001
	atsChunkResourceIDTable   = 0x0180
	atsChunkXMLNamespaceStart = 0x0100
	atsChunkXMLNamespaceEnd   = 0x0101
	atsChunkXMLElementStart   = 0x0102
	atsChunkXMLElementEnd     = 0x0103

	atsTypeString = 0x03
	atsTypeInt    = 0x10
	atsTypeBool   = 0x12

	atsAttrVersionCode      = 0x0101021b
	atsAttrVersionName      = 0x0101021c
	atsAttrMinSdkVersion    = 0x0101020c
	atsAttrTargetSdkVersion = 0x01010270
	atsAttrName             = 0x01010003
	atsAttrDebuggable       = 0x0101000f
	atsAttrAllowBackup      = 0x01010280
)

type atsTestAttr struct {
	nsIdx       int32
	nameIdx     int32
	valueStrIdx int32
	valueType   uint32
	valueData   uint32
}

func buildATSTestAXML() []byte {
	strs := []string{
		"", // 0
		"http://schemas.android.com/apk/res/android", // 1
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
		"android",                     // 20
	}

	resourceIDs := []uint32{
		0, 0, 0, 0, 0,
		atsAttrVersionCode,
		atsAttrVersionName,
		0, 0,
		atsAttrMinSdkVersion,
		atsAttrTargetSdkVersion,
		0,
		atsAttrName,
		0, 0, 0,
		atsAttrDebuggable,
		atsAttrAllowBackup,
		0, 0, 0,
	}

	spChunk := buildATSStringPoolChunk(strs)
	ridChunk := buildATSResourceIDChunk(resourceIDs)

	var xmlChunks []byte

	xmlChunks = append(xmlChunks, buildATSNamespaceChunk(atsChunkXMLNamespaceStart, 20, 1)...)

	xmlChunks = append(xmlChunks, buildATSElementStart(-1, 2, []atsTestAttr{
		{nsIdx: -1, nameIdx: 3, valueStrIdx: 4, valueType: atsTypeString, valueData: 4},
		{nsIdx: 1, nameIdx: 5, valueStrIdx: -1, valueType: atsTypeInt, valueData: 42},
		{nsIdx: 1, nameIdx: 6, valueStrIdx: 7, valueType: atsTypeString, valueData: 7},
	})...)

	xmlChunks = append(xmlChunks, buildATSElementStart(-1, 8, []atsTestAttr{
		{nsIdx: 1, nameIdx: 9, valueStrIdx: -1, valueType: atsTypeInt, valueData: 21},
		{nsIdx: 1, nameIdx: 10, valueStrIdx: -1, valueType: atsTypeInt, valueData: 34},
	})...)
	xmlChunks = append(xmlChunks, buildATSElementEnd(-1, 8)...)

	xmlChunks = append(xmlChunks, buildATSElementStart(-1, 11, []atsTestAttr{
		{nsIdx: 1, nameIdx: 12, valueStrIdx: 13, valueType: atsTypeString, valueData: 13},
	})...)
	xmlChunks = append(xmlChunks, buildATSElementEnd(-1, 11)...)

	xmlChunks = append(xmlChunks, buildATSElementStart(-1, 11, []atsTestAttr{
		{nsIdx: 1, nameIdx: 12, valueStrIdx: 14, valueType: atsTypeString, valueData: 14},
	})...)
	xmlChunks = append(xmlChunks, buildATSElementEnd(-1, 11)...)

	xmlChunks = append(xmlChunks, buildATSElementStart(-1, 15, []atsTestAttr{
		{nsIdx: 1, nameIdx: 16, valueStrIdx: -1, valueType: atsTypeBool, valueData: 0xFFFFFFFF},
		{nsIdx: 1, nameIdx: 17, valueStrIdx: -1, valueType: atsTypeBool, valueData: 0},
	})...)

	xmlChunks = append(xmlChunks, buildATSElementStart(-1, 18, []atsTestAttr{
		{nsIdx: 1, nameIdx: 12, valueStrIdx: 19, valueType: atsTypeString, valueData: 19},
	})...)
	xmlChunks = append(xmlChunks, buildATSElementEnd(-1, 18)...)

	xmlChunks = append(xmlChunks, buildATSElementEnd(-1, 15)...)
	xmlChunks = append(xmlChunks, buildATSElementEnd(-1, 2)...)

	xmlChunks = append(xmlChunks, buildATSNamespaceChunk(atsChunkXMLNamespaceEnd, 20, 1)...)

	totalSize := 8 + len(spChunk) + len(ridChunk) + len(xmlChunks)

	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], atsChunkResXMLType)
	binary.LittleEndian.PutUint16(header[2:4], 8)
	binary.LittleEndian.PutUint32(header[4:8], uint32(totalSize))

	var buf []byte
	buf = append(buf, header...)
	buf = append(buf, spChunk...)
	buf = append(buf, ridChunk...)
	buf = append(buf, xmlChunks...)

	return buf
}

func buildATSStringPoolChunk(strs []string) []byte {
	stringCount := len(strs)

	var stringData []byte
	offsets := make([]uint32, stringCount)

	for i, s := range strs {
		offsets[i] = uint32(len(stringData))
		sLen := len(s)
		if sLen > 127 {
			stringData = append(stringData, byte(0x80|sLen>>8), byte(sLen&0xFF))
			stringData = append(stringData, byte(0x80|sLen>>8), byte(sLen&0xFF))
		} else {
			stringData = append(stringData, byte(sLen))
			stringData = append(stringData, byte(sLen))
		}
		stringData = append(stringData, []byte(s)...)
		stringData = append(stringData, 0)
	}

	headerSize := 28
	offsetsSize := stringCount * 4
	stringsStart := headerSize + offsetsSize
	chunkSize := stringsStart + len(stringData)

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], atsChunkStringPool)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(stringCount))
	binary.LittleEndian.PutUint32(buf[12:16], 0)
	binary.LittleEndian.PutUint32(buf[16:20], 1<<8)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(stringsStart))
	binary.LittleEndian.PutUint32(buf[24:28], 0)

	for i, off := range offsets {
		binary.LittleEndian.PutUint32(buf[headerSize+i*4:], off)
	}

	copy(buf[stringsStart:], stringData)

	return buf
}

func buildATSResourceIDChunk(ids []uint32) []byte {
	headerSize := 8
	chunkSize := headerSize + len(ids)*4

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], atsChunkResourceIDTable)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	for i, id := range ids {
		binary.LittleEndian.PutUint32(buf[headerSize+i*4:], id)
	}

	return buf
}

func buildATSNamespaceChunk(chunkType uint16, prefixIdx, uriIdx int32) []byte {
	headerSize := 16
	chunkSize := headerSize + 8

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], chunkType)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	binary.LittleEndian.PutUint32(buf[headerSize:], uint32(prefixIdx))
	binary.LittleEndian.PutUint32(buf[headerSize+4:], uint32(uriIdx))

	return buf
}

func buildATSElementStart(nsIdx, nameIdx int32, attrs []atsTestAttr) []byte {
	headerSize := 16
	extSize := 20
	attrSize := 20
	chunkSize := headerSize + extSize + len(attrs)*attrSize

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], atsChunkXMLElementStart)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	off := headerSize
	binary.LittleEndian.PutUint32(buf[off:], uint32(nsIdx))
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(nameIdx))
	binary.LittleEndian.PutUint16(buf[off+8:], uint16(extSize))
	binary.LittleEndian.PutUint16(buf[off+10:], uint16(attrSize))
	binary.LittleEndian.PutUint16(buf[off+12:], uint16(len(attrs)))

	for i, a := range attrs {
		aOff := headerSize + extSize + i*attrSize
		binary.LittleEndian.PutUint32(buf[aOff:], uint32(a.nsIdx))
		binary.LittleEndian.PutUint32(buf[aOff+4:], uint32(a.nameIdx))
		binary.LittleEndian.PutUint32(buf[aOff+8:], uint32(a.valueStrIdx))
		binary.LittleEndian.PutUint16(buf[aOff+12:], 8)
		buf[aOff+14] = 0
		buf[aOff+15] = byte(a.valueType)
		binary.LittleEndian.PutUint32(buf[aOff+16:], a.valueData)
	}

	return buf
}

func buildATSElementEnd(nsIdx, nameIdx int32) []byte {
	headerSize := 16
	extSize := 8
	chunkSize := headerSize + extSize

	buf := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(buf[0:2], atsChunkXMLElementEnd)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(headerSize))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))

	binary.LittleEndian.PutUint32(buf[headerSize:], uint32(nsIdx))
	binary.LittleEndian.PutUint32(buf[headerSize+4:], uint32(nameIdx))

	return buf
}
