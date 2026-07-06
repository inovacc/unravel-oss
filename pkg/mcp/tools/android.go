/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"archive/zip"
	"bytes"
	"io"

	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/framework"
	"github.com/inovacc/unravel-oss/pkg/android/kotlin"
	"github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/android/resources"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/smali"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/android/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type androidExtractInput struct {
	APKPath   string `json:"apk_path" jsonschema:"Path to APK file"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory (default: <name>_extracted)"`
}

type androidInfoInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidVerifyInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidCertInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidDecompileInput struct {
	InputPath       string `json:"input_path" jsonschema:"Path to APK/AAB/XAPK/APKM file"`
	OutputDir       string `json:"output_dir,omitempty" jsonschema:"Output directory"`
	Deobfuscate     bool   `json:"deobfuscate,omitempty" jsonschema:"Enable jadx deobfuscation"`
	DecompileNative bool   `json:"decompile_native,omitempty" jsonschema:"Decompile native .so with retdec"`
	DecompileDotnet bool   `json:"decompile_dotnet,omitempty" jsonschema:"Decompile .NET DLLs (Xamarin)"`
}

type androidManifestInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidSecretsInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidDexInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidNativeInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidObfuscationInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidNetworkInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidResourcesInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidTelemetryInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidKotlinInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidProtobufInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidFrameworkInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK file"`
}

type androidToolsInput struct{}

func registerAndroidTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_extract",
		Description: "Extract an Android APK archive to a directory",
	}, handleAndroidExtract)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_info",
		Description: "Display APK metadata: format, DEX files, native libs, signatures, resources",
	}, handleAndroidInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_verify",
		Description: "Verify APK signature schemes (v1 JAR, v2, v3, v4)",
	}, handleAndroidVerify)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_cert",
		Description: "Extract signing certificates from an APK with fingerprints",
	}, handleAndroidCert)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_decompile",
		Description: "Full decompilation pipeline: apktool + jadx + retdec + ilspycmd for APK/AAB/XAPK/APKM files",
	}, handleAndroidDecompile)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_tools_status",
		Description: "Show installed Android reverse engineering tools (apktool, jadx, dex2jar, retdec, etc.)",
	}, handleAndroidToolsStatus)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_manifest",
		Description: "Parse and analyze AndroidManifest.xml from APK: package info, permissions with risk classification, component export analysis, deep links, security scoring",
	}, handleAndroidManifest)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_secrets",
		Description: "Scan APK for hardcoded API keys, tokens, secrets, and high-entropy strings",
	}, handleAndroidSecrets)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_dex",
		Description: "Parse DEX files in APK: class/method inventory, high-entropy strings, dangerous API detection",
	}, handleAndroidDex)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_native",
		Description: "Analyze native .so libraries: ABI inventory, JNI exports, anti-debug/root/emulator detection, packer signatures",
	}, handleAndroidNative)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_obfuscation",
		Description: "Detect ProGuard/R8/DexGuard obfuscation and packer protection in APK",
	}, handleAndroidObfuscation)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_network",
		Description: "Analyze network endpoints, domain classification, cert pinning, and network security config in APK",
	}, handleAndroidNetwork)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_resources",
		Description: "Analyze resources.arsc string pool, asset inventory, WebView detection, and embedded databases in APK",
	}, handleAndroidResources)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_telemetry",
		Description: "Detect analytics/ad/attribution SDKs, stealth features, and suspicious permissions in APK",
	}, handleAndroidTelemetry)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_kotlin",
		Description: "Detect Kotlin features: coroutines, data classes, serialization, Compose, and language statistics",
	}, handleAndroidKotlin)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_protobuf",
		Description: "Detect Protocol Buffers and gRPC usage, service stubs, proto files, and message types in APK",
	}, handleAndroidProtobuf)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_framework",
		Description: "Detect app framework (Flutter, React Native, Xamarin): JS engine, native libs, assemblies, obfuscation",
	}, handleAndroidFramework)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_android_static_smali",
		Description: "Disassemble DEX bytecode to Smali assembly (pure Go, no external tools). Returns method count and instruction summary.",
	}, handleAndroidSmali)
}

func handleAndroidExtract(_ context.Context, _ *mcp.CallToolRequest, input androidExtractInput) (*mcp.CallToolResult, any, error) {
	report, err := apk.Extract(input.APKPath, input.OutputDir, false)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(report), nil, nil
}

func handleAndroidInfo(_ context.Context, _ *mcp.CallToolRequest, input androidInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := apk.Info(input.APKPath, true)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidVerify(_ context.Context, _ *mcp.CallToolRequest, input androidVerifyInput) (*mcp.CallToolResult, any, error) {
	result, err := apk.Verify(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidCert(_ context.Context, _ *mcp.CallToolRequest, input androidCertInput) (*mcp.CallToolResult, any, error) {
	result, err := apk.ExtractCertificates(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidDecompile(ctx context.Context, _ *mcp.CallToolRequest, input androidDecompileInput) (*mcp.CallToolResult, any, error) {
	opts := tools.DecompileOptions{
		InputPath:       input.InputPath,
		OutputDir:       input.OutputDir,
		Deobfuscate:     input.Deobfuscate,
		DecompileNative: input.DecompileNative,
		DecompileDotnet: input.DecompileDotnet,
	}

	result, err := tools.Decompile(ctx, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidToolsStatus(_ context.Context, _ *mcp.CallToolRequest, _ androidToolsInput) (*mcp.CallToolResult, any, error) {
	reg := tools.NewRegistry()
	status := reg.DetectAll()

	return jsonResult(status), nil, nil
}

func handleAndroidManifest(_ context.Context, _ *mcp.CallToolRequest, input androidManifestInput) (*mcp.CallToolResult, any, error) {
	m, err := manifest.ParseAPK(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	analysis := manifest.Analyze(m)

	result := struct {
		*manifest.Manifest
		Analysis *manifest.Analysis `json:"analysis"`
	}{
		Manifest: m,
		Analysis: analysis,
	}

	return jsonResult(result), nil, nil
}

func handleAndroidSecrets(_ context.Context, _ *mcp.CallToolRequest, input androidSecretsInput) (*mcp.CallToolResult, any, error) {
	result, err := secret.Scan(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidDex(_ context.Context, _ *mcp.CallToolRequest, input androidDexInput) (*mcp.CallToolResult, any, error) {
	result, err := dex.ScanAPK(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidNative(_ context.Context, _ *mcp.CallToolRequest, input androidNativeInput) (*mcp.CallToolResult, any, error) {
	result, err := native.ScanAPK(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidObfuscation(_ context.Context, _ *mcp.CallToolRequest, input androidObfuscationInput) (*mcp.CallToolResult, any, error) {
	dexResult, _ := dex.ScanAPK(input.APKPath) // DEX is optional; obfuscation.Analyze handles nil

	result := obfuscation.Analyze(dexResult)
	result.HasMapping = obfuscation.DetectMapping(input.APKPath)
	result.Packer = obfuscation.DetectPacker(input.APKPath)

	if result.Packer != nil {
		result.Type = obfuscation.ObfPacker
	}

	if result.HasMapping && result.Type == obfuscation.ObfUnknown {
		result.Type = obfuscation.ObfProGuard
	}

	return jsonResult(result), nil, nil
}

func handleAndroidNetwork(_ context.Context, _ *mcp.CallToolRequest, input androidNetworkInput) (*mcp.CallToolResult, any, error) {
	dexResult, _ := dex.ScanAPK(input.APKPath)

	result, err := network.ScanAPK(input.APKPath, dexResult)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidResources(_ context.Context, _ *mcp.CallToolRequest, input androidResourcesInput) (*mcp.CallToolResult, any, error) {
	result, err := resources.ScanAPK(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleAndroidTelemetry(_ context.Context, _ *mcp.CallToolRequest, input androidTelemetryInput) (*mcp.CallToolResult, any, error) {
	dexResult, _ := dex.ScanAPK(input.APKPath) // DEX is optional; telemetry.ScanAPK handles nil
	m, _ := manifest.ParseAPK(input.APKPath)

	result := telemetry.ScanAPK(dexResult, m)

	return jsonResult(result), nil, nil
}

func handleAndroidKotlin(_ context.Context, _ *mcp.CallToolRequest, input androidKotlinInput) (*mcp.CallToolResult, any, error) {
	dexResult, _ := dex.ScanAPK(input.APKPath) // DEX is optional; kotlin.ScanDEX handles nil

	result := kotlin.ScanDEX(dexResult)

	return jsonResult(result), nil, nil
}

func handleAndroidFramework(_ context.Context, _ *mcp.CallToolRequest, input androidFrameworkInput) (*mcp.CallToolResult, any, error) {
	dexResult, _ := dex.ScanAPK(input.APKPath)

	result, err := framework.ScanAPK(input.APKPath, dexResult)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

type androidSmaliInput struct {
	APKPath string `json:"apk_path" jsonschema:"Path to APK or DEX file"`
}

func handleAndroidSmali(_ context.Context, _ *mcp.CallToolRequest, input androidSmaliInput) (*mcp.CallToolResult, any, error) {
	// Parse DEX files from APK
	parseResult, err := dex.ScanAPK(input.APKPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	type methodSummary struct {
		ClassName  string `json:"class_name"`
		MethodName string `json:"method_name"`
		Registers  int    `json:"registers"`
		InsnCount  int    `json:"instruction_count"`
	}
	type result struct {
		DexFiles     int             `json:"dex_files"`
		TotalMethods int             `json:"total_methods"`
		Methods      []methodSummary `json:"methods,omitempty"`
	}

	res := result{DexFiles: len(parseResult.DexFiles)}

	zr, zerr := zip.OpenReader(input.APKPath)
	if zerr != nil {
		return errorResult(zerr), nil, nil
	}
	defer func() { _ = zr.Close() }()

	for _, df := range parseResult.DexFiles {
		for _, f := range zr.File {
			if f.Name != df.Name {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				continue
			}
			reader := bytes.NewReader(data)
			reparsed, err := dex.Parse(reader, int64(len(data)))
			if err != nil {
				continue
			}
			reparsed.Name = df.Name

			disResult, err := smali.Disassemble(reader, int64(len(data)), reparsed)
			if err != nil {
				continue
			}

			for _, mc := range disResult.Methods {
				res.TotalMethods++
				if len(res.Methods) < 100 { // Cap output at 100 methods
					res.Methods = append(res.Methods, methodSummary{
						ClassName:  mc.ClassName,
						MethodName: mc.MethodName,
						Registers:  int(mc.Registers),
						InsnCount:  len(mc.Instructions),
					})
				}
			}
		}
	}

	return jsonResult(res), nil, nil
}

func handleAndroidProtobuf(_ context.Context, _ *mcp.CallToolRequest, input androidProtobufInput) (*mcp.CallToolResult, any, error) {
	dexResult, _ := dex.ScanAPK(input.APKPath) // DEX is optional; protobuf.DetectProtobuf handles nil

	result, err := protobuf.ScanAPK(input.APKPath, dexResult)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
