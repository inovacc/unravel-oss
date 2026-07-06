/*
Copyright (c) 2026 Security Research
*/
package protobuf

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

func TestDetectProtobuf_Nil(t *testing.T) {
	result := DetectProtobuf(nil)

	if result == nil {
		t.Fatal("expected non-nil result for nil input")
	}

	if result.HasProtobuf {
		t.Error("expected HasProtobuf=false for nil input")
	}

	if result.HasGRPC {
		t.Error("expected HasGRPC=false for nil input")
	}
}

func TestDetectProtobuf_NoProtobuf(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Name: "classes.dex",
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/example/MyActivity;"},
					{ClassName: "Lcom/example/Utils;"},
				},
				Strings: []string{"hello", "world"},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if result.HasProtobuf {
		t.Error("expected HasProtobuf=false")
	}

	if result.HasGRPC {
		t.Error("expected HasGRPC=false")
	}
}

func TestDetectProtobuf_WithProtobuf(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Name: "classes.dex",
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/google/protobuf/MessageLite;"},
					{ClassName: "Lcom/example/MyActivity;"},
				},
				Strings: []string{"my_message.proto", "hello"},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if !result.HasProtobuf {
		t.Error("expected HasProtobuf=true")
	}

	if result.HasGRPC {
		t.Error("expected HasGRPC=false")
	}

	if len(result.ProtoFiles) != 1 {
		t.Errorf("expected 1 proto file ref, got %d", len(result.ProtoFiles))
	}
}

func TestDetectProtobuf_WithGRPC(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Name: "classes.dex",
				Classes: []dex.ClassDef{
					{ClassName: "Lio/grpc/Channel;"},
					{ClassName: "Lio/grpc/okhttp/OkHttpChannelBuilder;"},
				},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if !result.HasGRPC {
		t.Error("expected HasGRPC=true")
	}

	if result.GRPCFramework != "grpc-okhttp" {
		t.Errorf("expected framework grpc-okhttp, got %s", result.GRPCFramework)
	}
}

func TestStripLPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no L prefix no semicolon",
			input: "com/example/Foo",
			want:  "com/example/Foo",
		},
		{
			name:  "L prefix without semicolon",
			input: "Lcom/example/Foo",
			want:  "com/example/Foo",
		},
		{
			name:  "L prefix with semicolon",
			input: "Lcom/example/Foo;",
			want:  "com/example/Foo",
		},
		{
			name:  "no L prefix but has semicolon suffix",
			input: "com/example/Foo;",
			want:  "com/example/Foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripLPrefix(tt.input)
			if got != tt.want {
				t.Errorf("stripLPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractServiceName(t *testing.T) {
	tests := []struct {
		name      string
		className string
		want      string
	}{
		{
			name:      "no Grpc$ in string returns full name",
			className: "com/example/SomeClass",
			want:      "com/example/SomeClass",
		},
		{
			name:      "slash-separated class name",
			className: "com/example/api/UserServiceGrpc$UserServiceStub",
			want:      "UserService",
		},
		{
			// When dot-separated, the function splits on "/" first.
			// With no "/" present, the full prefix before "Grpc$" is returned as-is.
			name:      "dot-separated class name returns full prefix before Grpc$",
			className: "com.example.api.UserServiceGrpc$UserServiceStub",
			want:      "com.example.api.UserService",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractServiceName(tt.className)
			if got != tt.want {
				t.Errorf("extractServiceName(%q) = %q, want %q", tt.className, got, tt.want)
			}
		})
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		name      string
		className string
		want      string
	}{
		{
			name:      "slash-separated returns dot-converted package",
			className: "com/example/api/UserServiceGrpc$UserServiceStub",
			want:      "com.example.api",
		},
		{
			name:      "dot-separated returns package portion",
			className: "com.example.api.UserServiceGrpc",
			want:      "com.example.api",
		},
		{
			name:      "no separator returns empty string",
			className: "MyClass",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackageName(tt.className)
			if got != tt.want {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.className, got, tt.want)
			}
		})
	}
}

func TestDetectProtobuf_ServiceStub(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Name: "classes.dex",
				Classes: []dex.ClassDef{
					{ClassName: "Lio/grpc/Channel;"},
					{ClassName: "Lcom/example/api/UserServiceGrpc$UserServiceStub;"},
				},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if len(result.GRPCServices) != 1 {
		t.Fatalf("expected 1 gRPC service, got %d", len(result.GRPCServices))
	}

	svc := result.GRPCServices[0]

	if svc.ServiceName != "UserService" {
		t.Errorf("expected service name UserService, got %s", svc.ServiceName)
	}

	if !svc.IsStub {
		t.Error("expected IsStub=true")
	}
}

func TestDetectProtobuf_GRPCKotlinFramework(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "Lio/grpc/kotlin/ClientCalls;"},
				},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if !result.HasGRPC {
		t.Error("expected HasGRPC=true")
	}

	if result.GRPCFramework != "grpc-kotlin" {
		t.Errorf("expected framework grpc-kotlin, got %s", result.GRPCFramework)
	}
}

func TestDetectProtobuf_GRPCJavaDefaultFramework(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					// Plain io.grpc class — not okhttp or kotlin variant
					{ClassName: "Lio/grpc/ManagedChannel;"},
				},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if !result.HasGRPC {
		t.Error("expected HasGRPC=true")
	}

	if result.GRPCFramework != "grpc-java" {
		t.Errorf("expected default framework grpc-java, got %s", result.GRPCFramework)
	}
}

func TestDetectProtobuf_OuterClassMessageTypes(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/example/UserOuterClass;"},
					{ClassName: "Lcom/example/OrderOuterClass;"},
				},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if len(result.MessageTypes) != 2 {
		t.Fatalf("expected 2 message types, got %d", len(result.MessageTypes))
	}

	wantTypes := map[string]bool{"User": true, "Order": true}
	for _, mt := range result.MessageTypes {
		if !wantTypes[mt] {
			t.Errorf("unexpected message type %q", mt)
		}
	}
}

func TestDetectProtobuf_DotSeparatedProtobufClass(t *testing.T) {
	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "com.google.protobuf.GeneratedMessageV3"},
				},
			},
		},
	}

	result := DetectProtobuf(dexResult)

	if !result.HasProtobuf {
		t.Error("expected HasProtobuf=true for dot-separated com.google.protobuf class")
	}
}

// makeSyntheticAPK writes a ZIP file at apkPath containing the given entry names.
func makeSyntheticAPK(t *testing.T, apkPath string, entries []string) {
	t.Helper()

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	for _, entry := range entries {
		fw, err := w.Create(entry)
		if err != nil {
			t.Fatalf("zip create entry %q: %v", entry, err)
		}
		_, _ = fw.Write([]byte("synthetic"))
	}
}

func TestScanAPK_AssetFiles(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	makeSyntheticAPK(t, apkPath, []string{
		"assets/schema.proto",
		"assets/data.pb",
		"assets/README.txt",
	})

	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/example/MainActivity;"},
				},
			},
		},
	}

	result, err := ScanAPK(apkPath, dexResult)
	if err != nil {
		t.Fatalf("ScanAPK returned error: %v", err)
	}

	if !result.HasProtobuf {
		t.Error("expected HasProtobuf=true after finding .proto and .pb assets")
	}

	// Only the .proto file produces an asset_file ProtoFileRef entry
	var assetEntries []ProtoFileRef
	for _, pf := range result.ProtoFiles {
		if pf.Source == "asset_file" {
			assetEntries = append(assetEntries, pf)
		}
	}

	if len(assetEntries) != 1 {
		t.Errorf("expected 1 asset_file proto entry, got %d", len(assetEntries))
	}

	if assetEntries[0].Name != "assets/schema.proto" {
		t.Errorf("expected entry name assets/schema.proto, got %s", assetEntries[0].Name)
	}
}

func TestScanAPK_InvalidZipReturnsDEXResults(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "not_a_zip.apk")

	if err := os.WriteFile(badPath, []byte("not a valid zip"), 0o600); err != nil {
		t.Fatalf("write bad apk: %v", err)
	}

	dexResult := &dex.ParseResult{
		DexFiles: []dex.DexFile{
			{
				Classes: []dex.ClassDef{
					{ClassName: "Lcom/google/protobuf/MessageLite;"},
				},
				Strings: []string{"service.proto"},
			},
		},
	}

	result, err := ScanAPK(badPath, dexResult)
	if err != nil {
		t.Fatalf("ScanAPK should not return error on bad ZIP, got: %v", err)
	}

	// DEX-derived detection must still be present
	if !result.HasProtobuf {
		t.Error("expected HasProtobuf=true from DEX-only results despite bad ZIP")
	}

	if len(result.ProtoFiles) != 1 || result.ProtoFiles[0].Source != "dex_strings" {
		t.Errorf("expected 1 dex_strings proto ref, got %+v", result.ProtoFiles)
	}
}
