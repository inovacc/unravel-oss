/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/android/apk"
)

// maxExtractedFileBytes caps a single extracted entry, mirroring pkg/deb and pkg/msix, to bound decompression-bomb exposure.
const maxExtractedFileBytes = 512 << 20 // 512 MiB

// DecompileOptions controls the decompilation pipeline.
type DecompileOptions struct {
	InputPath       string `json:"input_path"`
	OutputDir       string `json:"output_dir"`
	Deobfuscate     bool   `json:"deobfuscate"`
	DecompileNative bool   `json:"decompile_native"`
	DecompileDotnet bool   `json:"decompile_dotnet"`
	ToolFilter      string `json:"tool_filter,omitempty"`
	Verbose         bool   `json:"verbose"`
}

// DecompileResult summarizes the full decompilation pipeline run.
type DecompileResult struct {
	InputPath     string          `json:"input_path"`
	InputFormat   apk.FormatType  `json:"input_format"`
	OutputDir     string          `json:"output_dir"`
	Steps         []DecompileStep `json:"steps"`
	TotalDuration time.Duration   `json:"total_duration"`
	ToolsUsed     []string        `json:"tools_used"`
	ToolsSkipped  []string        `json:"tools_skipped,omitempty"`
	ToolsMissing  []string        `json:"tools_missing,omitempty"`
	Errors        []string        `json:"errors,omitempty"`
}

// DecompileStep represents a single tool invocation in the pipeline.
type DecompileStep struct {
	Tool      string        `json:"tool"`
	Action    string        `json:"action"`
	Input     string        `json:"input"`
	OutputDir string        `json:"output_dir"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	Error     string        `json:"error,omitempty"`
}

// Decompile runs the full decompilation pipeline on an Android package file.
func Decompile(ctx context.Context, opts DecompileOptions) (*DecompileResult, error) {
	absPath, err := filepath.Abs(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	// W5: reject paths whose base name starts with "-". Tools like apktool and
	// jadx do not universally support "--" to terminate flag parsing, so a file
	// named "-v evil.apk" in the input dir would be interpreted as a flag by
	// the tool rather than as a filename.
	if strings.HasPrefix(filepath.Base(absPath), "-") {
		return nil, fmt.Errorf("input file base name must not start with '-': %s", absPath)
	}

	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("input file: %w", err)
	}

	format, err := apk.DetectFormat(absPath)
	if err != nil {
		return nil, fmt.Errorf("detect format: %w", err)
	}

	outDir := opts.OutputDir
	if outDir == "" {
		base := filepath.Base(absPath)
		outDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_decompiled"
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	result := &DecompileResult{
		InputPath:   absPath,
		InputFormat: format,
		OutputDir:   outDir,
	}

	start := time.Now()
	registry := NewRegistry()
	registry.DetectAll()

	// Determine which APK to work with
	apkPath := absPath

	apkPath, err = unwrapBundle(ctx, registry, format, absPath, outDir, result)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("unwrap: %v", err))
		result.TotalDuration = time.Since(start)

		return result, nil
	}

	// Run pipeline steps
	if opts.ToolFilter == "" || opts.ToolFilter == "apktool" {
		runApktool(ctx, registry, apkPath, outDir, result)
	}

	if opts.ToolFilter == "" || opts.ToolFilter == "jadx" {
		runJadx(ctx, registry, apkPath, outDir, opts.Deobfuscate, result)
	}

	// Fallback decompiler chain (only when jadx is not available and no filter)
	if opts.ToolFilter == "" && !registry.IsAvailable("jadx") {
		runFallbackDecompilers(ctx, registry, apkPath, outDir, result)
	}

	// Native decompilation
	if opts.DecompileNative && (opts.ToolFilter == "" || opts.ToolFilter == "retdec") {
		runRetdec(ctx, registry, apkPath, outDir, result)
	}

	// .NET decompilation
	if opts.DecompileDotnet && (opts.ToolFilter == "" || opts.ToolFilter == "ilspycmd") {
		runIlspy(ctx, registry, apkPath, outDir, result)
	}

	result.TotalDuration = time.Since(start)

	return result, nil
}

func unwrapBundle(ctx context.Context, reg *Registry, format apk.FormatType, inputPath, outDir string, result *DecompileResult) (string, error) {
	switch format {
	case apk.FormatAAB:
		return unwrapAAB(ctx, reg, inputPath, outDir, result)
	case apk.FormatAPKM, apk.FormatXAPK, apk.FormatAPKS:
		return unwrapZipBundle(inputPath, outDir, result)
	default:
		return inputPath, nil
	}
}

func unwrapAAB(ctx context.Context, reg *Registry, aabPath, outDir string, result *DecompileResult) (string, error) {
	if !reg.IsAvailable("bundletool") {
		result.ToolsMissing = append(result.ToolsMissing, "bundletool")
		return "", fmt.Errorf("bundletool required to convert AAB")
	}

	apksPath := filepath.Join(outDir, "bundle.apks")
	step := DecompileStep{
		Tool:   "bundletool",
		Action: "Convert AAB to universal APK",
		Input:  aabPath,
	}

	start := time.Now()
	res, err := reg.Run(ctx, "bundletool",
		"build-apks",
		"--bundle="+aabPath,
		"--output="+apksPath,
		"--mode=universal",
	)
	step.Duration = time.Since(start)

	if err != nil || (res != nil && res.ExitCode != 0) {
		errMsg := "bundletool failed"
		if err != nil {
			errMsg = err.Error()
		} else if res != nil && res.Error != "" {
			errMsg = res.Stderr
		}

		step.Error = errMsg
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, errMsg)

		return "", fmt.Errorf("%s", errMsg)
	}

	step.Success = true
	result.Steps = append(result.Steps, step)
	result.ToolsUsed = append(result.ToolsUsed, "bundletool")

	// Extract universal.apk from the generated .apks (which is a zip)
	extractedAPK := filepath.Join(outDir, "base.apk")
	if err := extractFileFromZip(apksPath, "universal.apk", extractedAPK); err != nil {
		return "", fmt.Errorf("extract universal.apk: %w", err)
	}

	return extractedAPK, nil
}

func unwrapZipBundle(inputPath, outDir string, result *DecompileResult) (string, error) {
	step := DecompileStep{
		Tool:   "builtin",
		Action: "Extract base.apk from bundle",
		Input:  inputPath,
	}

	start := time.Now()

	zr, err := zip.OpenReader(inputPath)
	if err != nil {
		step.Error = err.Error()
		step.Duration = time.Since(start)
		result.Steps = append(result.Steps, step)

		return "", err
	}

	defer func() { _ = zr.Close() }()

	// Look for base.apk or the first .apk
	targetName := ""

	for _, f := range zr.File {
		if f.Name == "base.apk" {
			targetName = "base.apk"
			break
		}
	}

	if targetName == "" {
		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, ".apk") {
				targetName = f.Name
				break
			}
		}
	}

	if targetName == "" {
		step.Error = "no APK found in bundle"
		step.Duration = time.Since(start)
		result.Steps = append(result.Steps, step)

		return "", fmt.Errorf("no APK found in bundle")
	}

	extractedAPK := filepath.Join(outDir, "base.apk")
	if err := extractFileFromZip(inputPath, targetName, extractedAPK); err != nil {
		step.Error = err.Error()
		step.Duration = time.Since(start)
		result.Steps = append(result.Steps, step)

		return "", err
	}

	step.OutputDir = extractedAPK
	step.Success = true
	step.Duration = time.Since(start)
	result.Steps = append(result.Steps, step)

	return extractedAPK, nil
}

func runApktool(ctx context.Context, reg *Registry, apkPath, outDir string, result *DecompileResult) {
	if !reg.IsAvailable("apktool") {
		result.ToolsMissing = append(result.ToolsMissing, "apktool")
		return
	}

	apktoolOut := filepath.Join(outDir, "apktool")
	step := DecompileStep{
		Tool:      "apktool",
		Action:    "Decode resources and smali",
		Input:     apkPath,
		OutputDir: apktoolOut,
	}

	start := time.Now()
	res, err := reg.Run(ctx, "apktool", "d", apkPath, "-o", apktoolOut, "-f")
	step.Duration = time.Since(start)

	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("apktool: %v", err))

		return
	}

	if res.ExitCode != 0 {
		step.Error = res.Stderr
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("apktool: %s", res.Stderr))

		return
	}

	step.Success = true
	result.Steps = append(result.Steps, step)
	result.ToolsUsed = append(result.ToolsUsed, "apktool")
}

func runJadx(ctx context.Context, reg *Registry, apkPath, outDir string, deobf bool, result *DecompileResult) {
	if !reg.IsAvailable("jadx") {
		result.ToolsMissing = append(result.ToolsMissing, "jadx")
		return
	}

	jadxOut := filepath.Join(outDir, "jadx")
	step := DecompileStep{
		Tool:      "jadx",
		Action:    "Decompile DEX to Java",
		Input:     apkPath,
		OutputDir: jadxOut,
	}

	args := []string{apkPath, "-d", jadxOut}
	if deobf {
		args = append(args, "--deobf")
		step.Action = "Decompile DEX to Java (with deobfuscation)"
	}

	start := time.Now()
	res, err := reg.Run(ctx, "jadx", args...)
	step.Duration = time.Since(start)

	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("jadx: %v", err))

		return
	}

	if res.ExitCode != 0 {
		step.Error = res.Stderr
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("jadx: %s", res.Stderr))

		return
	}

	step.Success = true
	result.Steps = append(result.Steps, step)
	result.ToolsUsed = append(result.ToolsUsed, "jadx")
}

func runFallbackDecompilers(ctx context.Context, reg *Registry, apkPath, outDir string, result *DecompileResult) {
	// Step 1: dex2jar
	if !reg.IsAvailable("dex2jar") {
		result.ToolsMissing = append(result.ToolsMissing, "dex2jar")
		return
	}

	jarPath := filepath.Join(outDir, "classes.jar")
	step := DecompileStep{
		Tool:      "dex2jar",
		Action:    "Convert DEX to JAR",
		Input:     apkPath,
		OutputDir: jarPath,
	}

	start := time.Now()
	res, err := reg.Run(ctx, "dex2jar", apkPath, "-o", jarPath, "--force")
	step.Duration = time.Since(start)

	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("dex2jar: %v", err))

		return
	}

	if res.ExitCode != 0 {
		step.Error = res.Stderr
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("dex2jar: %s", res.Stderr))

		return
	}

	step.Success = true
	result.Steps = append(result.Steps, step)
	result.ToolsUsed = append(result.ToolsUsed, "dex2jar")

	// Step 2: decompile JAR with procyon or jd-cli
	if reg.IsAvailable("procyon") {
		runProcyon(ctx, reg, jarPath, outDir, result)
	} else if reg.IsAvailable("jd-cli") {
		runJdCli(ctx, reg, jarPath, outDir, result)
	} else {
		result.ToolsMissing = append(result.ToolsMissing, "procyon")
		result.ToolsMissing = append(result.ToolsMissing, "jd-cli")
	}
}

func runProcyon(ctx context.Context, reg *Registry, jarPath, outDir string, result *DecompileResult) {
	procyonOut := filepath.Join(outDir, "procyon")
	step := DecompileStep{
		Tool:      "procyon",
		Action:    "Decompile JAR to Java",
		Input:     jarPath,
		OutputDir: procyonOut,
	}

	start := time.Now()
	res, err := reg.Run(ctx, "procyon", "-jar", jarPath, "-o", procyonOut)
	step.Duration = time.Since(start)

	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("procyon: %v", err))

		return
	}

	if res.ExitCode != 0 {
		step.Error = res.Stderr
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("procyon: %s", res.Stderr))

		return
	}

	step.Success = true
	result.Steps = append(result.Steps, step)
	result.ToolsUsed = append(result.ToolsUsed, "procyon")
}

func runJdCli(ctx context.Context, reg *Registry, jarPath, outDir string, result *DecompileResult) {
	jdOut := filepath.Join(outDir, "jd-cli")
	step := DecompileStep{
		Tool:      "jd-cli",
		Action:    "Decompile JAR to Java",
		Input:     jarPath,
		OutputDir: jdOut,
	}

	start := time.Now()
	res, err := reg.Run(ctx, "jd-cli", jarPath, "-od", jdOut)
	step.Duration = time.Since(start)

	if err != nil {
		step.Error = err.Error()
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("jd-cli: %v", err))

		return
	}

	if res.ExitCode != 0 {
		step.Error = res.Stderr
		result.Steps = append(result.Steps, step)
		result.Errors = append(result.Errors, fmt.Sprintf("jd-cli: %s", res.Stderr))

		return
	}

	step.Success = true
	result.Steps = append(result.Steps, step)
	result.ToolsUsed = append(result.ToolsUsed, "jd-cli")
}

func runRetdec(ctx context.Context, reg *Registry, apkPath, outDir string, result *DecompileResult) {
	if !reg.IsAvailable("retdec") {
		result.ToolsMissing = append(result.ToolsMissing, "retdec")
		return
	}

	// Extract .so files from the APK
	soFiles, err := extractNativeLibs(apkPath, outDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("extract native libs: %v", err))
		return
	}

	if len(soFiles) == 0 {
		result.ToolsSkipped = append(result.ToolsSkipped, "retdec (no native libs)")
		return
	}

	nativeOut := filepath.Join(outDir, "native")
	if err := os.MkdirAll(nativeOut, 0o700); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("create native dir: %v", err))
		return
	}

	for _, soFile := range soFiles {
		relPath, _ := filepath.Rel(outDir, soFile)

		soOutDir := filepath.Join(nativeOut, filepath.Dir(relPath))
		if err := os.MkdirAll(soOutDir, 0o700); err != nil {
			continue
		}

		step := DecompileStep{
			Tool:      "retdec",
			Action:    "Decompile native library",
			Input:     soFile,
			OutputDir: soOutDir,
		}

		start := time.Now()
		outFile := filepath.Join(soOutDir, filepath.Base(soFile)+".c")
		res, err := reg.Run(ctx, "retdec", soFile, "-o", outFile)
		step.Duration = time.Since(start)

		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			result.Errors = append(result.Errors, fmt.Sprintf("retdec %s: %v", filepath.Base(soFile), err))

			continue
		}

		if res.ExitCode != 0 {
			step.Error = res.Stderr
			result.Steps = append(result.Steps, step)

			continue
		}

		step.Success = true
		result.Steps = append(result.Steps, step)
	}

	result.ToolsUsed = append(result.ToolsUsed, "retdec")
}

func runIlspy(ctx context.Context, reg *Registry, apkPath, outDir string, result *DecompileResult) {
	if !reg.IsAvailable("ilspycmd") {
		result.ToolsMissing = append(result.ToolsMissing, "ilspycmd")
		return
	}

	// Extract .dll files from the APK
	dllFiles, err := extractDotnetAssemblies(apkPath, outDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("extract assemblies: %v", err))
		return
	}

	if len(dllFiles) == 0 {
		result.ToolsSkipped = append(result.ToolsSkipped, "ilspycmd (no .NET assemblies)")
		return
	}

	dotnetOut := filepath.Join(outDir, "dotnet")
	if err := os.MkdirAll(dotnetOut, 0o700); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("create dotnet dir: %v", err))
		return
	}

	for _, dllFile := range dllFiles {
		baseName := strings.TrimSuffix(filepath.Base(dllFile), ".dll")

		dllOutDir := filepath.Join(dotnetOut, baseName)
		if err := os.MkdirAll(dllOutDir, 0o700); err != nil {
			continue
		}

		step := DecompileStep{
			Tool:      "ilspycmd",
			Action:    "Decompile .NET assembly",
			Input:     dllFile,
			OutputDir: dllOutDir,
		}

		start := time.Now()
		res, err := reg.Run(ctx, "ilspycmd", dllFile, "-p", "-o", dllOutDir)
		step.Duration = time.Since(start)

		if err != nil {
			step.Error = err.Error()
			result.Steps = append(result.Steps, step)
			result.Errors = append(result.Errors, fmt.Sprintf("ilspycmd %s: %v", filepath.Base(dllFile), err))

			continue
		}

		if res.ExitCode != 0 {
			step.Error = res.Stderr
			result.Steps = append(result.Steps, step)

			continue
		}

		step.Success = true
		result.Steps = append(result.Steps, step)
	}

	result.ToolsUsed = append(result.ToolsUsed, "ilspycmd")
}

// extractNativeLibs extracts lib/**/*.so files from an APK to a temp directory.
func extractNativeLibs(apkPath, outDir string) ([]string, error) {
	return extractByPattern(apkPath, outDir, func(name string) bool {
		return strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so")
	})
}

// extractDotnetAssemblies extracts assemblies/**/*.dll files from an APK.
func extractDotnetAssemblies(apkPath, outDir string) ([]string, error) {
	return extractByPattern(apkPath, outDir, func(name string) bool {
		return strings.HasSuffix(name, ".dll") &&
			(strings.HasPrefix(name, "assemblies/") || strings.Contains(name, "assemblies/"))
	})
}

func extractByPattern(apkPath, outDir string, match func(string) bool) ([]string, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, err
	}

	defer func() { _ = zr.Close() }()

	var extracted []string

	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !match(f.Name) {
			continue
		}

		target := filepath.Join(outDir, f.Name)

		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(outDir)+string(os.PathSeparator)) {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		out, err := os.Create(target)
		if err != nil {
			_ = rc.Close()
			continue
		}

		_, err = io.Copy(out, io.LimitReader(rc, maxExtractedFileBytes))
		_ = rc.Close()
		_ = out.Close()

		if err == nil {
			extracted = append(extracted, target)
		}
	}

	return extracted, nil
}

func extractFileFromZip(zipPath, entryName, destPath string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}

	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if f.Name != entryName {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		defer func() { _ = rc.Close() }()

		out, err := os.Create(destPath)
		if err != nil {
			return err
		}

		defer func() { _ = out.Close() }()

		_, err = io.Copy(out, io.LimitReader(rc, maxExtractedFileBytes))

		return err
	}

	return fmt.Errorf("entry %q not found in %s", entryName, zipPath)
}
