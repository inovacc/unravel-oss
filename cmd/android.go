/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/internal/boundedzip"
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

	"bytes"

	out "github.com/inovacc/unravel-oss/cmd/output"

	"github.com/spf13/cobra"
)

var (
	androidJSONFormat  bool
	androidDeobfuscate bool
	androidNative      bool
	androidDotnet      bool
	androidDexFull     bool
)

var androidCmd = &cobra.Command{
	Use:   "android",
	Short: "Android APK analysis, decompilation, and reverse engineering",
	Long: `Parse, extract, analyze, and decompile Android packages.

Supported formats:
  APK   - Standard Android application package
  AAB   - Android App Bundle
  Split - Split APK modules
  XAPK  - Multi-APK container (APKPure)
  APKS  - APK Set (bundletool)
  APKM  - APK Mirror bundle (base.apk + splits + info.json)

Subcommands:
  info              - Display APK metadata and structure
  extract           - Extract APK contents to disk
  static verify     - Verify APK signature schemes (v1-v4)
  static cert       - Extract signing certificates
  tools status      - Show installed reverse engineering tools
  static decompile  - Full decompilation pipeline
  tools apktool     - Run apktool directly
  tools jadx        - Run jadx directly
  static dex2jar    - Run dex2jar directly
  tools retdec      - Run retdec on native library
  tools bundletool  - Convert AAB to APK
  tools adb         - Android Debug Bridge operations`,
}

// androidStaticCmd groups offline/static-analysis verbs (decompile, dex,
// dex2jar, dex2java, smali, kotlin, native, resources, manifest, protobuf,
// obfuscation, secrets, framework, telemetry, network, cert, verify) per
// docs/COMMAND-TAXONOMY.md §6.5.
var androidStaticCmd = &cobra.Command{
	Use:   "static",
	Short: "Static analysis of Android artifacts",
}

// androidToolsCmd groups external-tooling-wrapper verbs (adb, apktool,
// bundletool, jadx, retdec) per docs/COMMAND-TAXONOMY.md §6.5.
var androidToolsCmd = &cobra.Command{
	Use:   "tools",
	Short: "External Android tooling wrappers",
}

var androidInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display APK metadata and structure",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidInfo,
}

var androidExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract APK contents to disk",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidExtract,
}

var androidVerifyCmd = &cobra.Command{
	Use:   "verify <file>",
	Short: "Verify APK signature schemes (v1-v4)",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidVerify,
}

var androidCertCmd = &cobra.Command{
	Use:   "cert <file>",
	Short: "Extract signing certificates",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidCert,
}

// androidToolsStatusCmd is NOT in docs/COMMAND-TAXONOMY.md §6.5's android
// verb list (see needs-decision note in the PR2 report): it was the
// pre-existing flat `android tools` verb, whose name collided with the new
// `android tools` sub-noun group once that group was introduced. Nested here
// as `android tools status` (unchanged Run/flags) as the minimal,
// non-destructive placement pending an explicit taxonomy decision.
var androidToolsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show installed reverse engineering tool status",
	Run:   runAndroidTools,
}

var androidDecompileCmd = &cobra.Command{
	Use:   "decompile <file>",
	Short: "Full decompilation pipeline (apktool + jadx + retdec + ilspy)",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidDecompile,
}

var androidApktoolCmd = &cobra.Command{
	Use:   "apktool <file>",
	Short: "Run apktool to decode resources and smali",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidApktool,
}

var androidJadxCmd = &cobra.Command{
	Use:   "jadx <file>",
	Short: "Run jadx to decompile DEX to Java",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidJadx,
}

var androidDex2jarCmd = &cobra.Command{
	Use:   "dex2jar <file>",
	Short: "Run dex2jar to convert DEX to JAR",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidDex2jar,
}

var androidRetdecCmd = &cobra.Command{
	Use:   "retdec <file.so>",
	Short: "Run retdec to decompile native library",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidRetdec,
}

var androidBundletoolCmd = &cobra.Command{
	Use:   "bundletool <file.aab>",
	Short: "Convert AAB to universal APK",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidBundletool,
}

var androidManifestCmd = &cobra.Command{
	Use:   "manifest <file>",
	Short: "Parse and display AndroidManifest.xml from APK",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidManifest,
}

var androidSecretsCmd = &cobra.Command{
	Use:   "secrets <file>",
	Short: "Scan APK for hardcoded API keys, tokens, and secrets",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidSecrets,
}

var androidDexCmd = &cobra.Command{
	Use:   "dex <file>",
	Short: "Parse DEX files in APK and analyze for dangerous APIs",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidDex,
}

var androidNativeCmd = &cobra.Command{
	Use:   "native <file>",
	Short: "Analyze native .so libraries in APK",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidNative,
}

var androidObfuscationCmd = &cobra.Command{
	Use:   "obfuscation <file>",
	Short: "Detect ProGuard/R8/DexGuard obfuscation and packers",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidObfuscation,
}

var androidNetworkCmd = &cobra.Command{
	Use:   "network <file>",
	Short: "Analyze network endpoints, domains, cert pinning in APK",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidNetwork,
}

var androidResourcesCmd = &cobra.Command{
	Use:   "resources <file>",
	Short: "Analyze resources.arsc and assets in APK",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidResources,
}

var androidTelemetryCmd = &cobra.Command{
	Use:   "telemetry <file>",
	Short: "Detect analytics, ads, attribution SDKs and stealth features",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidTelemetry,
}

var androidKotlinCmd = &cobra.Command{
	Use:   "kotlin <file>",
	Short: "Detect Kotlin features and language statistics",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidKotlin,
}

var androidProtobufCmd = &cobra.Command{
	Use:   "protobuf <file>",
	Short: "Detect Protocol Buffers and gRPC usage in APK",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidProtobuf,
}

var androidFrameworkCmd = &cobra.Command{
	Use:   "framework <file>",
	Short: "Detect app framework (Flutter, React Native, Xamarin)",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidFramework,
}

var androidAdbCmd = &cobra.Command{
	Use:   "adb",
	Short: "Android Debug Bridge operations",
}

var androidAdbListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed packages on device",
	Run:   runAndroidAdbList,
}

var androidAdbPullCmd = &cobra.Command{
	Use:   "pull <package>",
	Short: "Pull APK from device",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidAdbPull,
}

var androidAdbInfoCmd = &cobra.Command{
	Use:   "info <package>",
	Short: "Show package info from device",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidAdbInfo,
}

var androidSmaliCmd = &cobra.Command{
	Use:   "smali <file.apk|file.dex>",
	Short: "Disassemble DEX bytecode to Smali (pure Go, no external tools)",
	Long:  "Disassemble Dalvik bytecode into Smali assembly text. Accepts APK or DEX files. Outputs .smali files per class to the output directory.",
	Args:  cobra.ExactArgs(1),
	Run:   runAndroidSmali,
}

func init() {
	rootCmd.AddCommand(androidCmd)

	// Deep-grouping per docs/COMMAND-TAXONOMY.md §6.5.
	androidCmd.AddCommand(androidStaticCmd, androidToolsCmd)

	// Flat on android.
	androidCmd.AddCommand(androidInfoCmd)
	androidCmd.AddCommand(androidExtractCmd)

	// android static.
	androidStaticCmd.AddCommand(androidVerifyCmd)
	androidStaticCmd.AddCommand(androidCertCmd)
	androidStaticCmd.AddCommand(androidDecompileCmd)
	androidStaticCmd.AddCommand(androidDex2jarCmd)
	androidStaticCmd.AddCommand(androidManifestCmd)
	androidStaticCmd.AddCommand(androidSecretsCmd)
	androidStaticCmd.AddCommand(androidDexCmd)
	androidStaticCmd.AddCommand(androidNativeCmd)
	androidStaticCmd.AddCommand(androidObfuscationCmd)
	androidStaticCmd.AddCommand(androidNetworkCmd)
	androidStaticCmd.AddCommand(androidResourcesCmd)
	androidStaticCmd.AddCommand(androidTelemetryCmd)
	androidStaticCmd.AddCommand(androidKotlinCmd)
	androidStaticCmd.AddCommand(androidProtobufCmd)
	androidStaticCmd.AddCommand(androidFrameworkCmd)
	androidStaticCmd.AddCommand(androidSmaliCmd)

	// android tools.
	androidToolsCmd.AddCommand(androidApktoolCmd)
	androidToolsCmd.AddCommand(androidJadxCmd)
	androidToolsCmd.AddCommand(androidRetdecCmd)
	androidToolsCmd.AddCommand(androidBundletoolCmd)
	androidToolsCmd.AddCommand(androidAdbCmd)
	androidAdbCmd.AddCommand(androidAdbListCmd)
	androidAdbCmd.AddCommand(androidAdbPullCmd)
	androidAdbCmd.AddCommand(androidAdbInfoCmd)
	// Needs-decision: androidToolsStatusCmd (`android tools status`) is not
	// in §6.5's verb list; nested here as the minimal non-destructive home
	// for the pre-existing flat `android tools` verb. See report.
	androidToolsCmd.AddCommand(androidToolsStatusCmd)

	androidCmd.PersistentFlags().BoolVar(&androidJSONFormat, "json", false, "Output as JSON")
	androidDexCmd.Flags().BoolVar(&androidDexFull, "full", false, "include the full per-DEX string/class/method/field tables in --json (very large on real apps; default: summary + findings only)")

	androidDecompileCmd.Flags().BoolVar(&androidDeobfuscate, "deobf", false, "Enable jadx deobfuscation")
	androidDecompileCmd.Flags().BoolVar(&androidNative, "native", false, "Decompile native .so with retdec")
	androidDecompileCmd.Flags().BoolVar(&androidDotnet, "dotnet", false, "Decompile .NET DLLs with ilspycmd")

	androidJadxCmd.Flags().BoolVar(&androidDeobfuscate, "deobf", false, "Enable deobfuscation")
}

// --- Existing run functions ---

func runAndroidInfo(_ *cobra.Command, args []string) {
	info, err := apk.Info(args[0], verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidInfo(info)
}

func runAndroidExtract(_ *cobra.Command, args []string) {
	report, err := apk.Extract(args[0], output, verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidExtract(report)
}

func runAndroidVerify(_ *cobra.Command, args []string) {
	result, err := apk.Verify(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidVerify(result)
}

func runAndroidCert(_ *cobra.Command, args []string) {
	result, err := apk.ExtractCertificates(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidCert(result)
}

func runAndroidManifest(_ *cobra.Command, args []string) {
	m, err := manifest.ParseAPK(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(m, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidManifest(m)
}

func runAndroidSecrets(_ *cobra.Command, args []string) {
	result, err := secret.Scan(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidSecrets(result)
}

// --- New run functions ---

func runAndroidTools(_ *cobra.Command, _ []string) {
	reg := tools.NewRegistry()
	status := reg.DetectAll()

	if androidJSONFormat {
		data, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidTools(status, verbose)
}

func runAndroidDecompile(_ *cobra.Command, args []string) {
	opts := tools.DecompileOptions{
		InputPath:       args[0],
		OutputDir:       output,
		Deobfuscate:     androidDeobfuscate,
		DecompileNative: androidNative,
		DecompileDotnet: androidDotnet,
		Verbose:         verbose,
	}

	result, err := tools.Decompile(context.Background(), opts)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidDecompile(result)
}

func runAndroidApktool(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("apktool")

	outDir := output
	if outDir == "" {
		outDir = "apktool_output"
	}

	res, err := reg.Run(context.Background(), "apktool", "d", args[0], "-o", outDir, "-f")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidRun(res, verbose)
}

func runAndroidJadx(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("jadx")

	outDir := output
	if outDir == "" {
		outDir = "jadx_output"
	}

	cmdArgs := []string{args[0], "-d", outDir}
	if androidDeobfuscate {
		cmdArgs = append(cmdArgs, "--deobf")
	}

	res, err := reg.Run(context.Background(), "jadx", cmdArgs...)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidRun(res, verbose)
}

func runAndroidDex2jar(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("dex2jar")

	outPath := output
	if outPath == "" {
		outPath = "classes.jar"
	}

	res, err := reg.Run(context.Background(), "dex2jar", args[0], "-o", outPath, "--force")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidRun(res, verbose)
}

func runAndroidRetdec(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("retdec")

	outPath := output
	if outPath == "" {
		outPath = args[0] + ".c"
	}

	res, err := reg.Run(context.Background(), "retdec", args[0], "-o", outPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidRun(res, verbose)
}

func runAndroidBundletool(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("bundletool")

	outPath := output
	if outPath == "" {
		outPath = "output.apks"
	}

	res, err := reg.Run(context.Background(), "bundletool",
		"build-apks",
		"--bundle="+args[0],
		"--output="+outPath,
		"--mode=universal",
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidRun(res, verbose)
}

func runAndroidAdbList(_ *cobra.Command, _ []string) {
	reg := tools.NewRegistry()
	reg.Detect("adb")

	res, err := reg.Run(context.Background(), "adb", "shell", "pm", "list", "packages")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	if res.ExitCode != 0 {
		fmt.Printf("Error: %s\n", res.Stderr)
		os.Exit(1)
	}

	// Parse "package:com.example.app" lines
	for line := range strings.SplitSeq(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "package:"); ok {
			fmt.Println(after)
		}
	}
}

func runAndroidAdbPull(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("adb")

	// Get APK path
	pathRes, err := reg.Run(context.Background(), "adb", "shell", "pm", "path", args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if pathRes.ExitCode != 0 {
		fmt.Printf("Error: package not found: %s\n", args[0])
		os.Exit(1)
	}

	// Parse path from output
	apkPath := ""

	for line := range strings.SplitSeq(pathRes.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "package:"); ok {
			apkPath = after
			break
		}
	}

	if apkPath == "" {
		fmt.Println("Error: could not determine APK path")
		os.Exit(1)
	}

	outPath := output
	if outPath == "" {
		outPath = args[0] + ".apk"
	}

	pullRes, err := reg.Run(context.Background(), "adb", "pull", apkPath, outPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(pullRes, "", "  ")
		fmt.Println(string(data))

		return
	}

	if pullRes.ExitCode != 0 {
		fmt.Printf("Error: %s\n", pullRes.Stderr)
		os.Exit(1)
	}

	fmt.Printf("Pulled %s to %s\n", args[0], outPath)

	if pullRes.Stdout != "" {
		fmt.Print(pullRes.Stdout)
	}
}

func runAndroidAdbInfo(_ *cobra.Command, args []string) {
	reg := tools.NewRegistry()
	reg.Detect("adb")

	res, err := reg.Run(context.Background(), "adb", "shell", "dumpsys", "package", args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))

		return
	}

	if res.ExitCode != 0 {
		fmt.Printf("Error: %s\n", res.Stderr)
		os.Exit(1)
	}

	fmt.Print(res.Stdout)
}

func runAndroidDex(_ *cobra.Command, args []string) {
	result, err := dex.ScanAPK(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		// The per-DEX string/class/method/field tables dominate the output on
		// real apps (e.g. ~184 MB / 85k classes on Picsart) and bury the
		// summary + risk findings the command exists to surface. Strip them by
		// default; --full opts back into the raw tables. Totals, high-entropy
		// strings, risk findings, and parse errors are top-level and preserved.
		if !androidDexFull {
			result.StripHeavyTables()
		}

		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidDex(result)
}

func runAndroidNative(_ *cobra.Command, args []string) {
	result, err := native.ScanAPK(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidNative(result)
}

func runAndroidNetwork(_ *cobra.Command, args []string) {
	dexResult, _ := dex.ScanAPK(args[0])

	result, err := network.ScanAPK(args[0], dexResult)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidNetwork(result)
}

func runAndroidResources(_ *cobra.Command, args []string) {
	result, err := resources.ScanAPK(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidResources(result)
}

func runAndroidTelemetry(_ *cobra.Command, args []string) {
	dexResult, _ := dex.ScanAPK(args[0]) // DEX is optional; telemetry.ScanAPK handles nil
	m, _ := manifest.ParseAPK(args[0])

	result := telemetry.ScanAPK(dexResult, m)

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidTelemetry(result)
}

func runAndroidKotlin(_ *cobra.Command, args []string) {
	dexResult, _ := dex.ScanAPK(args[0]) // DEX is optional; kotlin.ScanDEX handles nil

	result := kotlin.ScanDEX(dexResult)

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidKotlin(result)
}

func runAndroidProtobuf(_ *cobra.Command, args []string) {
	dexResult, _ := dex.ScanAPK(args[0]) // DEX is optional

	result, err := protobuf.ScanAPK(args[0], dexResult)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidProtobuf(result)
}

func runAndroidFramework(_ *cobra.Command, args []string) {
	dexResult, _ := dex.ScanAPK(args[0])

	result, err := framework.ScanAPK(args[0], dexResult)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintFrameworkAnalysis(result)
}

func runAndroidObfuscation(_ *cobra.Command, args []string) {
	dexResult, _ := dex.ScanAPK(args[0]) // DEX is optional; obfuscation.Analyze handles nil

	result := obfuscation.Analyze(dexResult)
	result.HasMapping = obfuscation.DetectMapping(args[0])
	result.Packer = obfuscation.DetectPacker(args[0])

	if result.Packer != nil {
		result.Type = obfuscation.ObfPacker
	}

	if result.HasMapping && result.Type == obfuscation.ObfUnknown {
		result.Type = obfuscation.ObfProGuard
	}

	if androidJSONFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintAndroidObfuscation(result)
}

func runAndroidSmali(_ *cobra.Command, args []string) {
	path := args[0]

	// First parse DEX metadata via ScanAPK
	parseResult, err := dex.ScanAPK(path)
	if err != nil {
		// Try as raw DEX file
		f, ferr := os.Open(path)
		if ferr != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fi, _ := f.Stat()
		df, perr := dex.Parse(f, fi.Size())
		_ = f.Close()
		if perr != nil {
			fmt.Printf("Error parsing DEX: %v\n", perr)
			os.Exit(1)
		}
		df.Name = fi.Name()

		// Re-open for disassembly
		f, _ = os.Open(path)
		result, derr := smali.Disassemble(f, fi.Size(), df)
		_ = f.Close()
		if derr != nil {
			fmt.Printf("Error disassembling: %v\n", derr)
			os.Exit(1)
		}

		printSmaliResult(df.Name, result)
		return
	}

	// APK: re-open and disassemble each DEX entry
	totalMethods := 0
	for i := range parseResult.DexFiles {
		df := &parseResult.DexFiles[i]

		// For APK, we need to extract the DEX entry and disassemble from the raw bytes
		// ScanAPK already parsed the DEX, but smali.Disassemble needs raw reader access
		// to read code_items which aren't stored in DexFile struct
		//
		// Re-parse the DEX from the APK ZIP entry
		result, derr := disassembleDexFromAPK(path, df)
		if derr != nil {
			if verbose {
				fmt.Printf("  [SMALI] %s: skipped (%v)\n", df.Name, derr)
			}
			continue
		}

		totalMethods += len(result.Methods)
		printSmaliResult(df.Name, result)
	}

	fmt.Printf("\nTotal: %d methods disassembled from %d DEX files\n", totalMethods, len(parseResult.DexFiles))
}

func disassembleDexFromAPK(apkPath string, df *dex.DexFile) (*smali.DisassembleResult, error) {
	zr, err := boundedzip.OpenReader(apkPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if f.Name != df.Name {
			continue
		}

		dexData, err := zr.ReadEntry(f)
		if err != nil {
			return nil, err
		}

		reader := bytes.NewReader(dexData)
		reparsed, err := dex.Parse(reader, int64(len(dexData)))
		if err != nil {
			return nil, err
		}
		reparsed.Name = df.Name

		return smali.Disassemble(reader, int64(len(dexData)), reparsed)
	}

	return nil, fmt.Errorf("DEX entry %q not found in APK", df.Name)
}

func printSmaliResult(name string, result *smali.DisassembleResult) {
	if output != "" {
		written, err := smali.WriteSmali(result, output)
		if err != nil {
			fmt.Printf("Error writing smali: %v\n", err)
			return
		}
		fmt.Printf("  [SMALI] %s: wrote %d classes to %s\n", name, written, output)
	} else {
		fmt.Printf("  [SMALI] %s: %d methods disassembled\n", name, len(result.Methods))
		if verbose {
			for _, mc := range result.Methods {
				fmt.Printf("    %s->%s: %d instructions, %d registers\n",
					mc.ClassName, mc.MethodName, len(mc.Instructions), mc.Registers)
			}
		}
	}
}
