/*
Copyright (c) 2026 Security Research
*/

package kotlin

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

func TestScanDEX_Nil(t *testing.T) {
	result := ScanDEX(nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.HasKotlin {
		t.Error("expected HasKotlin to be false for nil input")
	}
	if result.Stats.TotalClasses != 0 {
		t.Errorf("expected 0 total classes, got %d", result.Stats.TotalClasses)
	}
}

func TestScanDEX_NoKotlin(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Strings: []string{"java.lang.String", "com.example.MainActivity"},
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/example/MainActivity;"},
					{ClassName: "Lcom/example/util/Helper;"},
				},
				Methods: []dex.MethodRef{
					{ClassName: "Lcom/example/MainActivity;", Name: "onCreate"},
					{ClassName: "Lcom/example/util/Helper;", Name: "process"},
				},
			},
		},
	}

	result := ScanDEX(dexResult)
	if result.HasKotlin {
		t.Error("expected HasKotlin to be false for Java-only DEX")
	}
	if result.Stats.TotalClasses != 2 {
		t.Errorf("expected 2 total classes, got %d", result.Stats.TotalClasses)
	}
	if result.Stats.KotlinClasses != 0 {
		t.Errorf("expected 0 Kotlin classes, got %d", result.Stats.KotlinClasses)
	}
}

func TestScanDEX_WithKotlin(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Strings: []string{
					"kotlin.jvm.internal",
					"kotlin-stdlib",
					"1.9.0",
					"kotlinx.coroutines",
					"Dispatchers.Main",
					"Dispatchers.IO",
				},
				Classes: []dex.ClassDef{
					{ClassName: "Lkotlin/jvm/internal/Intrinsics;"},
					{ClassName: "Lkotlinx/coroutines/Dispatchers;"},
					{ClassName: "Lkotlinx/coroutines/flow/Flow;"},
					{ClassName: "Lcom/example/data/User$Companion;"},
					{ClassName: "Lcom/example/data/User;"},
					{ClassName: "Landroidx/compose/runtime/Composable;"},
				},
				Methods: []dex.MethodRef{
					{ClassName: "Lcom/example/data/User;", Name: "component1"},
					{ClassName: "Lcom/example/data/User;", Name: "component2"},
					{ClassName: "Lcom/example/data/User;", Name: "copy"},
					{ClassName: "Lcom/example/data/User;", Name: "copy$default"},
					{ClassName: "Lcom/example/MainActivity;", Name: "fetchData$suspendImpl"},
				},
			},
		},
	}

	result := ScanDEX(dexResult)

	if !result.HasKotlin {
		t.Error("expected HasKotlin to be true")
	}

	if result.KotlinVersion != "1.9.0" {
		t.Errorf("expected version 1.9.0, got %s", result.KotlinVersion)
	}

	if result.Stats.TotalClasses != 6 {
		t.Errorf("expected 6 total classes, got %d", result.Stats.TotalClasses)
	}

	if result.Stats.KotlinClasses == 0 {
		t.Error("expected non-zero Kotlin classes")
	}

	if result.Stats.CompanionObjects != 1 {
		t.Errorf("expected 1 companion object, got %d", result.Stats.CompanionObjects)
	}

	if result.Coroutines == nil {
		t.Fatal("expected coroutines info")
	}
	if !result.Coroutines.HasCoroutines {
		t.Error("expected HasCoroutines to be true")
	}
	if !result.Coroutines.HasFlow {
		t.Error("expected HasFlow to be true")
	}
	if result.Coroutines.SuspendFuncs != 1 {
		t.Errorf("expected 1 suspend function, got %d", result.Coroutines.SuspendFuncs)
	}
	if len(result.Coroutines.Dispatchers) == 0 {
		t.Error("expected dispatchers to be detected")
	}

	if result.Compose == nil {
		t.Fatal("expected compose info")
	}
	if !result.Compose.HasCompose {
		t.Error("expected HasCompose to be true")
	}

	if len(result.DataClasses) == 0 {
		t.Error("expected data classes to be detected")
	}

	if len(result.Features) == 0 {
		t.Error("expected features list to be populated")
	}
}

func TestDetectDataClasses(t *testing.T) {
	classes := []string{
		"Lcom/example/User;",
		"Lcom/example/Product;",
	}

	methods := []dex.MethodRef{
		{ClassName: "Lcom/example/User;", Name: "component1"},
		{ClassName: "Lcom/example/User;", Name: "component2"},
		{ClassName: "Lcom/example/User;", Name: "component3"},
		{ClassName: "Lcom/example/User;", Name: "copy"},
		{ClassName: "Lcom/example/User;", Name: "copy$default"},
		{ClassName: "Lcom/example/Product;", Name: "component1"},
		{ClassName: "Lcom/example/Product;", Name: "copy"},
		{ClassName: "Lcom/example/Helper;", Name: "process"},
	}

	dataClasses := detectDataClasses(classes, methods)

	if len(dataClasses) != 2 {
		t.Errorf("expected 2 data classes, got %d", len(dataClasses))
	}

	var userClass *DataClassInfo
	for i := range dataClasses {
		if dataClasses[i].ClassName == "Lcom/example/User;" {
			userClass = &dataClasses[i]
			break
		}
	}

	if userClass == nil {
		t.Fatal("expected User data class to be detected")
	}

	if len(userClass.Properties) != 3 {
		t.Errorf("expected 3 properties for User, got %d", len(userClass.Properties))
	}
}

func TestDetectVersion_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		strings []string
		want    string
	}{
		{
			name:    "no version string",
			strings: []string{"kotlin.jvm.internal", "kotlin-stdlib"},
			want:    "",
		},
		{
			name:    "multiple versions picks first",
			strings: []string{"kotlin-stdlib", "1.8.22", "2.0.0"},
			want:    "1.8.22",
		},
		{
			name:    "no kotlin context ignores version",
			strings: []string{"java.lang.String", "1.9.0"},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectVersion(tt.strings)
			if got != tt.want {
				t.Errorf("detectVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCountInlineClasses(t *testing.T) {
	classes := []string{
		"Lcom/example/MyInline$KMappedMarker;",
		"Lcom/example/AnotherInline$KMappedMarker;",
		"Lcom/example/Regular;",
	}

	got := countInlineClasses(classes)
	if got != 2 {
		t.Errorf("countInlineClasses() = %d, want 2", got)
	}
}

func TestDetectSerialization_Formats(t *testing.T) {
	tests := []struct {
		name       string
		classes    []string
		wantFormat string
	}{
		{
			name:       "json format",
			classes:    []string{"Lkotlinx/serialization/json/Json;"},
			wantFormat: "json",
		},
		{
			name:       "protobuf format",
			classes:    []string{"Lkotlinx/serialization/protobuf/ProtoBuf;"},
			wantFormat: "protobuf",
		},
		{
			name:       "cbor format",
			classes:    []string{"Lkotlinx/serialization/cbor/Cbor;"},
			wantFormat: "cbor",
		},
		{
			name:       "generic serialization no format",
			classes:    []string{"Lkotlinx/serialization/KSerializer;"},
			wantFormat: "",
		},
		{
			name:       "no serialization returns nil",
			classes:    []string{"Lcom/example/Regular;"},
			wantFormat: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := detectSerialization(tt.classes)
			if tt.wantFormat == "" && tt.name == "no serialization returns nil" {
				if info != nil {
					t.Error("expected nil for no serialization classes")
				}
				return
			}
			if info == nil {
				t.Fatal("expected non-nil serialization info")
			}
			if info.Format != tt.wantFormat {
				t.Errorf("Format = %q, want %q", info.Format, tt.wantFormat)
			}
		})
	}
}

func TestDetectCoroutines_Channel(t *testing.T) {
	classes := []string{
		"Lkotlinx/coroutines/channels/Channel;",
		"Lkotlin/coroutines/Continuation;",
	}
	info := detectCoroutines(nil, classes, nil)
	if info == nil {
		t.Fatal("expected non-nil coroutine info")
	}
	if !info.HasChannel {
		t.Error("expected HasChannel to be true")
	}
	if !info.HasCoroutines {
		t.Error("expected HasCoroutines to be true")
	}
}

func TestDetectCoroutines_AllDispatchers(t *testing.T) {
	strs := []string{
		"Dispatchers.Main",
		"Dispatchers.IO",
		"Dispatchers.Default",
		"Dispatchers.Unconfined",
	}
	classes := []string{"Lkotlinx/coroutines/Dispatchers;"}

	info := detectCoroutines(strs, classes, nil)
	if info == nil {
		t.Fatal("expected non-nil coroutine info")
	}
	if len(info.Dispatchers) != 4 {
		t.Errorf("expected 4 dispatchers, got %d", len(info.Dispatchers))
	}
}

func TestDetectCoroutines_SuspendCounting(t *testing.T) {
	methods := []dex.MethodRef{
		{ClassName: "Lcom/example/A;", Name: "fetchData$suspendImpl"},
		{ClassName: "Lcom/example/B;", Name: "loadUser$suspendImpl"},
		{ClassName: "Lcom/example/C;", Name: "normalMethod"},
	}
	classes := []string{
		"Lkotlinx/coroutines/CoroutineScope;",
		"Lcom/example/D$ContinuationImpl;",
	}

	info := detectCoroutines(nil, classes, methods)
	if info == nil {
		t.Fatal("expected non-nil coroutine info")
	}
	// 2 from $suspendImpl methods + 1 from $ContinuationImpl class
	if info.SuspendFuncs != 3 {
		t.Errorf("SuspendFuncs = %d, want 3", info.SuspendFuncs)
	}
}

func TestDetectCoroutines_NoneReturnsNil(t *testing.T) {
	info := detectCoroutines(
		[]string{"java.lang.String"},
		[]string{"Lcom/example/Regular;"},
		nil,
	)
	if info != nil {
		t.Error("expected nil coroutine info when nothing detected")
	}
}

func TestBuildFeatures_Completeness(t *testing.T) {
	result := &ScanResult{
		HasKotlin: true,
		Coroutines: &CoroutineInfo{
			HasCoroutines: true,
			HasFlow:       true,
			Evidence:      []string{"kotlinx/coroutines/CoroutineScope"},
		},
		Compose: &ComposeInfo{
			HasCompose:  true,
			Composables: 5,
			Evidence:    []string{"androidx/compose/runtime/Composable"},
		},
		Serialization: &SerializationInfo{
			HasSerialization: true,
			Format:           "json",
			Evidence:         []string{"kotlinx/serialization/json/Json"},
		},
		DataClasses: []DataClassInfo{
			{ClassName: "Lcom/example/User;", Properties: []string{"property1"}},
		},
		Stats: KotlinStats{
			CompanionObjects: 2,
			InlineClasses:    1,
		},
	}

	features := buildFeatures(result)
	if len(features) != 7 {
		t.Errorf("expected 7 features, got %d", len(features))
	}

	expectedNames := map[string]bool{
		"Coroutines":            true,
		"Flow":                  true,
		"Jetpack Compose":       true,
		"Kotlinx Serialization": true,
		"Data Classes":          true,
		"Companion Objects":     true,
		"Inline Classes":        true,
	}

	for _, f := range features {
		if !expectedNames[f.Name] {
			t.Errorf("unexpected feature name %q", f.Name)
		}
		if !f.Detected {
			t.Errorf("feature %q expected detected=true", f.Name)
		}
	}
}

func TestKotlinPercent_ZeroClasses(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Strings: []string{"kotlin-stdlib"},
				Classes: []dex.ClassDef{},
			},
		},
	}

	result := ScanDEX(dexResult)
	// No classes means no kotlin detected (detectKotlin checks classes too
	// but strings match first), however 0 classes means KotlinPercent stays 0
	if result.Stats.KotlinPercent != 0 {
		t.Errorf("expected 0 percent for 0 total classes, got %f", result.Stats.KotlinPercent)
	}
}

func TestScanDEX_MultiDex(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Strings: []string{"kotlin-stdlib"},
				Classes: []dex.ClassDef{
					{ClassName: "Lkotlin/Unit;"},
					{ClassName: "Lcom/example/A;"},
				},
			},
			{
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/example/B;"},
					{ClassName: "Lcom/example/C$Companion;"},
				},
			},
		},
	}

	result := ScanDEX(dexResult)
	if !result.HasKotlin {
		t.Error("expected HasKotlin to be true")
	}
	if result.Stats.TotalClasses != 4 {
		t.Errorf("expected 4 total classes across 2 DEX files, got %d", result.Stats.TotalClasses)
	}
	if result.Stats.CompanionObjects != 1 {
		t.Errorf("expected 1 companion object, got %d", result.Stats.CompanionObjects)
	}
}
