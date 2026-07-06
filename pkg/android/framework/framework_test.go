/*
Copyright (c) 2026 Security Research
*/

package framework

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// createTestAPK builds a minimal ZIP at path with the given file entries.
func createTestAPK(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, data := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanAPK_NoFramework(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"classes.dex":           {0x64, 0x65, 0x78},
		"AndroidManifest.xml":   {0x00},
		"lib/arm64-v8a/libc.so": {0x7f},
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "" {
		t.Errorf("expected empty framework, got %q", result.Framework)
	}
	if result.Flutter != nil || result.ReactNative != nil || result.Xamarin != nil {
		t.Error("expected all framework infos to be nil")
	}
}

func TestScanAPK_Flutter(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libflutter.so":              {0x7f},
		"lib/arm64-v8a/libapp.so":                  {0x7f},
		"lib/armeabi-v7a/libflutter.so":            {0x7f},
		"assets/flutter_assets/AssetManifest.json": []byte(`{}`),
		"assets/flutter_assets/fonts/material":     {0x00},
	})

	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lio/flutter/embedding/engine/FlutterEngine;"},
				{ClassName: "Lio/flutter/plugins/camera/CameraPlugin;"},
			},
		}},
	}

	result, err := ScanAPK(apk, dexResult)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Flutter" {
		t.Errorf("expected Flutter, got %q", result.Framework)
	}
	if result.Flutter == nil {
		t.Fatal("expected FlutterInfo")
	}
	if !result.Flutter.HasAssetManifest {
		t.Error("expected HasAssetManifest")
	}
	if len(result.Flutter.NativeLibs) < 2 {
		t.Errorf("expected at least 2 native libs, got %d", len(result.Flutter.NativeLibs))
	}
	if len(result.Flutter.ABIs) != 2 {
		t.Errorf("expected 2 ABIs, got %d", len(result.Flutter.ABIs))
	}
	// IsObfuscated: has libapp.so but no snapshot data
	if !result.Flutter.IsObfuscated {
		t.Error("expected IsObfuscated since no snapshot data files")
	}
	if len(result.Flutter.Plugins) == 0 {
		t.Error("expected plugins from DEX classes")
	}
}

func TestScanAPK_Flutter_WithSnapshots(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libflutter.so":                 {0x7f},
		"lib/arm64-v8a/libapp.so":                     {0x7f},
		"assets/flutter_assets/vm_snapshot_data":      {0x00},
		"assets/flutter_assets/isolate_snapshot_data": {0x00},
		"assets/flutter_assets/kernel_blob.bin":       {0x00},
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Flutter" {
		t.Fatalf("expected Flutter, got %q", result.Framework)
	}
	if result.Flutter.IsObfuscated {
		t.Error("expected not obfuscated since snapshot data present")
	}
	if len(result.Flutter.SnapshotFiles) != 3 {
		t.Errorf("expected 3 snapshot files, got %d", len(result.Flutter.SnapshotFiles))
	}
}

func TestScanAPK_Flutter_DEXOnly(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"classes.dex": {0x00},
	})
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lio/flutter/app/FlutterApplication;"},
			},
		}},
	}

	result, err := ScanAPK(apk, dexResult)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Flutter" {
		t.Errorf("expected Flutter from DEX-only, got %q", result.Framework)
	}
}

func TestScanAPK_ReactNative_Hermes(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"lib/arm64-v8a/libhermes.so":         {0x7f},
		"assets/index.android.bundle":        {0xc6, 0x1f, 0xbc, 0x03, 0x00}, // Hermes magic
	})

	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lcom/facebook/react/ReactActivity;"},
				{ClassName: "Lcom/myapp/MyNativeModule;"},
			},
		}},
	}

	result, err := ScanAPK(apk, dexResult)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "React Native" {
		t.Errorf("expected React Native, got %q", result.Framework)
	}
	if result.ReactNative == nil {
		t.Fatal("expected ReactNativeInfo")
	}
	if result.ReactNative.JSEngine != "Hermes" {
		t.Errorf("expected Hermes engine, got %q", result.ReactNative.JSEngine)
	}
	if !result.ReactNative.HasJSBundle {
		t.Error("expected HasJSBundle")
	}
	if result.ReactNative.JSBundleSize == 0 {
		t.Error("expected non-zero JSBundleSize")
	}
}

func TestScanAPK_ReactNative_JSC(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libjsc.so":     {0x7f},
		"assets/index.android.bundle": []byte("var x = 1;"),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "React Native" {
		t.Errorf("expected React Native, got %q", result.Framework)
	}
	if result.ReactNative.JSEngine != "JSC" {
		t.Errorf("expected JSC, got %q", result.ReactNative.JSEngine)
	}
}

func TestScanAPK_ReactNative_V8(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libv8executor.so": {0x7f},
		"assets/index.android.bundle":    []byte("var x = 1;"),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReactNative.JSEngine != "V8" {
		t.Errorf("expected V8, got %q", result.ReactNative.JSEngine)
	}
}

func TestScanAPK_ReactNative_SourceMap(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"assets/index.android.bundle":        []byte("x"),
		"assets/index.android.bundle.map":    []byte("{}"),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ReactNative.HasSourceMap {
		t.Error("expected HasSourceMap")
	}
}

func TestScanAPK_ReactNative_SourceMapExtraction(t *testing.T) {
	sourceMap := `{"version":3,"sources":["src/App.tsx","src/screens/Home.tsx","src/utils/api.ts"],"sourcesContent":["import React...","export default...","fetch(...)"],"mappings":"AAAA"}`
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"assets/index.android.bundle":        []byte("x"),
		"assets/index.android.bundle.map":    []byte(sourceMap),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	rn := result.ReactNative
	if rn.SourceMap == nil {
		t.Fatal("expected SourceMap to be populated")
	}
	if rn.SourceMap.Version != 3 {
		t.Errorf("expected version 3, got %d", rn.SourceMap.Version)
	}
	if rn.SourceMap.SourceCount != 3 {
		t.Errorf("expected 3 sources, got %d", rn.SourceMap.SourceCount)
	}
	if !rn.SourceMap.HasSources {
		t.Error("expected HasSources true")
	}
	if len(rn.SourceMap.TopSources) != 3 {
		t.Errorf("expected 3 top sources, got %d", len(rn.SourceMap.TopSources))
	}
	if rn.SourceMap.TopSources[0] != "src/App.tsx" {
		t.Errorf("unexpected first source: %q", rn.SourceMap.TopSources[0])
	}
	if len(rn.SourceMap.Files) != 1 {
		t.Errorf("expected 1 map file, got %d", len(rn.SourceMap.Files))
	}
}

func TestScanAPK_ReactNative_SourceMapNoInlineSources(t *testing.T) {
	sourceMap := `{"version":3,"sources":["a.js","b.js"],"mappings":"AAAA"}`
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"assets/index.android.bundle":        []byte("x"),
		"assets/index.android.bundle.map":    []byte(sourceMap),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReactNative.SourceMap.HasSources {
		t.Error("expected HasSources false when no sourcesContent")
	}
}

func TestScanAPK_ReactNative_SourceMapTruncation(t *testing.T) {
	// Build source map with 30 sources
	sources := make([]string, 30)
	for i := range sources {
		sources[i] = fmt.Sprintf("src/file%d.ts", i)
	}
	sourcesJSON, _ := json.Marshal(sources)
	sourceMap := fmt.Sprintf(`{"version":3,"sources":%s,"mappings":"AAAA"}`, sourcesJSON)

	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"assets/index.android.bundle":        []byte("x"),
		"assets/index.android.bundle.map":    []byte(sourceMap),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	sm := result.ReactNative.SourceMap
	if sm.SourceCount != 30 {
		t.Errorf("expected 30 sources, got %d", sm.SourceCount)
	}
	if len(sm.TopSources) != 20 {
		t.Errorf("expected TopSources capped at 20, got %d", len(sm.TopSources))
	}
}

func TestScanAPK_ReactNative_DEXOnly(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"classes.dex": {0x00},
	})
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lcom/facebook/react/bridge/ReactBridge;"},
			},
		}},
	}

	result, err := ScanAPK(apk, dexResult)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "React Native" {
		t.Errorf("expected React Native from DEX-only, got %q", result.Framework)
	}
}

func TestScanAPK_ReactNative_HermesMagicDetection(t *testing.T) {
	// No hermes lib, but bundle has hermes magic bytes -> should detect Hermes
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"assets/index.android.bundle":        {0xc6, 0x1f, 0xbc, 0x03, 0x01, 0x02},
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReactNative.JSEngine != "Hermes" {
		t.Errorf("expected Hermes from magic bytes, got %q", result.ReactNative.JSEngine)
	}
}

func TestScanAPK_Xamarin(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libmonodroid.so":     {0x7f},
		"lib/arm64-v8a/libmonosgen-2.0.so":  {0x7f},
		"assemblies/Xamarin.Forms.Core.dll": {0x00},
		"assemblies/MyApp.dll":              {0x00},
		"assemblies/System.dll":             {0x00},
	})

	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lmono/android/Runtime;"},
			},
		}},
	}

	result, err := ScanAPK(apk, dexResult)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Xamarin" {
		t.Errorf("expected Xamarin, got %q", result.Framework)
	}
	if result.Xamarin == nil {
		t.Fatal("expected XamarinInfo")
	}
	if !result.Xamarin.IsXamarinForms {
		t.Error("expected IsXamarinForms")
	}
	if result.Xamarin.AssemblyCount != 3 {
		t.Errorf("expected 3 assemblies, got %d", result.Xamarin.AssemblyCount)
	}
	if len(result.Xamarin.NativeLibs) != 2 {
		t.Errorf("expected 2 native libs, got %d", len(result.Xamarin.NativeLibs))
	}
}

func TestScanAPK_Xamarin_MAUI(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libmonodroid.so":          {0x7f},
		"assemblies/Microsoft.Maui.dll":          {0x00},
		"assemblies/Microsoft.Maui.Controls.dll": {0x00},
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Xamarin" {
		t.Fatalf("expected Xamarin, got %q", result.Framework)
	}
	if !result.Xamarin.IsMAUI {
		t.Error("expected IsMAUI")
	}
}

func TestScanAPK_Xamarin_AOT(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libmonodroid.so": {0x7f},
		"assemblies/MyApp.dll":          {0x00},
		"assemblies/MyApp.dll.so":       {0x7f},
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Xamarin.HasAOT {
		t.Error("expected HasAOT")
	}
}

func TestScanAPK_Xamarin_DEXOnly(t *testing.T) {
	apk := createTestAPK(t, map[string][]byte{
		"classes.dex": {0x00},
	})
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{{
			Classes: []dex.ClassDef{
				{ClassName: "Lmd/mono/android/Runtime;"},
			},
		}},
	}

	result, err := ScanAPK(apk, dexResult)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Xamarin" {
		t.Errorf("expected Xamarin from DEX, got %q", result.Framework)
	}
}

func TestScanAPK_InvalidPath(t *testing.T) {
	_, err := ScanAPK("/nonexistent/path.apk", nil)
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestScanAPK_PriorityOrder(t *testing.T) {
	// APK has markers for both Flutter and RN — Flutter should win (checked first)
	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libflutter.so":        {0x7f},
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"assets/index.android.bundle":        []byte("x"),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Framework != "Flutter" {
		t.Errorf("expected Flutter to take priority, got %q", result.Framework)
	}
}

func TestDetectJSEngine(t *testing.T) {
	tests := []struct {
		hermes, jsc, v8 bool
		want            string
	}{
		{true, false, false, "Hermes"},
		{false, true, false, "JSC"},
		{false, false, true, "V8"},
		{false, false, false, "unknown"},
		{true, true, false, "Hermes"}, // Hermes takes priority
	}
	for _, tt := range tests {
		got := detectJSEngine(tt.hermes, tt.jsc, tt.v8)
		if got != tt.want {
			t.Errorf("detectJSEngine(%v,%v,%v) = %q, want %q", tt.hermes, tt.jsc, tt.v8, got, tt.want)
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"a", "b", "a", "c", "b"})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("uniqueStrings returned %v", got)
	}
}

func TestExtractABI(t *testing.T) {
	tests := []struct {
		name, want string
	}{
		{"lib/arm64-v8a/libfoo.so", "arm64-v8a"},
		{"lib/armeabi-v7a/libbar.so", "armeabi-v7a"},
		{"assets/foo.txt", ""},
		{"lib/x86/", "x86"},
	}
	for _, tt := range tests {
		got := extractABI(tt.name)
		if got != tt.want {
			t.Errorf("extractABI(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestScanAPK_Flutter_EngineVersion(t *testing.T) {
	// Build a synthetic libflutter.so with an embedded version near "Flutter"
	soData := make([]byte, 512)
	copy(soData[100:], []byte("Flutter Engine"))
	copy(soData[120:], []byte("3.22.0"))

	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libflutter.so":              soData,
		"assets/flutter_assets/AssetManifest.json": []byte(`{}`),
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Flutter == nil {
		t.Fatal("expected FlutterInfo")
	}
	if result.Flutter.EngineVersion != "3.22.0" {
		t.Errorf("expected engine version 3.22.0, got %q", result.Flutter.EngineVersion)
	}
}

func TestScanAPK_Flutter_DartVersion(t *testing.T) {
	// Build synthetic vm_snapshot_data with Dart magic + version
	snapData := make([]byte, 64)
	// 64-bit Dart snapshot magic: 0xf5f5dcdc LE
	snapData[0] = 0xdc
	snapData[1] = 0xdc
	snapData[2] = 0xf5
	snapData[3] = 0xf5
	// Embed version string after magic
	copy(snapData[8:], []byte("3.4.0"))

	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libflutter.so":            {0x7f},
		"assets/flutter_assets/vm_snapshot_data": snapData,
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Flutter == nil {
		t.Fatal("expected FlutterInfo")
	}
	if result.Flutter.DartVersion != "3.4.0" {
		t.Errorf("expected Dart version 3.4.0, got %q", result.Flutter.DartVersion)
	}
}

func TestScanAPK_ReactNative_HermesVersion(t *testing.T) {
	// Build HBC with magic + version 93
	bundle := make([]byte, 16)
	bundle[0] = 0xc6
	bundle[1] = 0x1f
	bundle[2] = 0xbc
	bundle[3] = 0x03
	// Version 93 as uint32 LE
	bundle[4] = 93
	bundle[5] = 0
	bundle[6] = 0
	bundle[7] = 0

	apk := createTestAPK(t, map[string][]byte{
		"lib/arm64-v8a/libreactnativejni.so": {0x7f},
		"lib/arm64-v8a/libhermes.so":         {0x7f},
		"assets/index.android.bundle":        bundle,
	})

	result, err := ScanAPK(apk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReactNative == nil {
		t.Fatal("expected ReactNativeInfo")
	}
	if result.ReactNative.HermesVersion != "93" {
		t.Errorf("expected Hermes version 93, got %q", result.ReactNative.HermesVersion)
	}
}

func TestDetectFlutterPlugins_NoPlugins(t *testing.T) {
	classes := []string{"Lio/flutter/embedding/engine/FlutterEngine;"}
	plugins := detectFlutterPlugins(classes)
	if len(plugins) != 0 {
		t.Errorf("expected no plugins, got %v", plugins)
	}
}

func TestDetectFlutterPlugins_WithPlugins(t *testing.T) {
	classes := []string{
		"Lio/flutter/plugins/camera/CameraPlugin;",
		"Lio/flutter/plugins/pathprovider/PathProviderPlugin;",
		"Lio/flutter/plugins/camera/CameraHandler;",
	}
	plugins := detectFlutterPlugins(classes)
	if len(plugins) != 2 {
		t.Errorf("expected 2 plugins, got %d: %v", len(plugins), plugins)
	}
}
