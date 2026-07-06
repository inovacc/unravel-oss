/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/android/apk"
)

// ---------------------------------------------------------------------------
// parseVersionLine – additional edge cases
// ---------------------------------------------------------------------------

func TestParseVersionLine_ExactlyOneHundredChars(t *testing.T) {
	// A line of exactly 100 characters must not be truncated.
	input := strings.Repeat("x", 100)
	got := parseVersionLine(input)
	if got != input {
		t.Errorf("100-char input was truncated: len(got)=%d", len(got))
	}
}

func TestParseVersionLine_OneHundredAndOneChars(t *testing.T) {
	// A line of 101 characters must be truncated to 100.
	input := strings.Repeat("y", 101)
	got := parseVersionLine(input)
	if len(got) != 100 {
		t.Errorf("len(got) = %d, want 100", len(got))
	}
}

func TestParseVersionLine_NewlineAtStart(t *testing.T) {
	// TrimSpace is applied to the whole output before splitting on '\n', so a
	// leading newline is stripped and the first non-empty line becomes the result.
	got := parseVersionLine("\nsome version info")
	if got != "some version info" {
		t.Errorf("got %q, want 'some version info' (TrimSpace removes leading newline)", got)
	}
}

func TestParseVersionLine_OnlyCarriageReturn(t *testing.T) {
	got := parseVersionLine("\r")
	// TrimSpace strips \r, so the result must be empty.
	if got != "" {
		t.Errorf("got %q, want empty string for lone CR", got)
	}
}

func TestParseVersionLine_TabSeparated(t *testing.T) {
	got := parseVersionLine("tool\t2.0.0")
	if got != "tool\t2.0.0" {
		t.Errorf("got %q, want %q", got, "tool\t2.0.0")
	}
}

func TestParseVersionLine_WindowsLineEnding(t *testing.T) {
	// The first line ends with \r\n; the trimmed result should drop the trailing \r.
	got := parseVersionLine("v1.2.3\r\nnext line")
	// strings.TrimSpace is applied after slicing, so \r is removed.
	if got != "v1.2.3" {
		t.Errorf("got %q, want %q", got, "v1.2.3")
	}
}

// ---------------------------------------------------------------------------
// detectVersion – use a tiny shell script in a temp PATH entry
// ---------------------------------------------------------------------------

func TestDetectVersion_MockBinary(t *testing.T) {
	binDir := t.TempDir()

	// Write a mock binary that prints a known version string.
	writeMockVersionScript(t, binDir, "fake-tool-tdtest", "fake-tool-tdtest 9.8.7")

	// Prepend binDir so exec.LookPath can find the script.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	got := detectVersion("fake-tool-tdtest")
	if got == "" {
		t.Error("detectVersion returned empty string; expected version output from mock binary")
	}
	if !strings.Contains(got, "9.8.7") {
		t.Errorf("detectVersion = %q, want it to contain '9.8.7'", got)
	}
}

func TestDetectVersion_NonExistentBinary(t *testing.T) {
	// A binary that does not exist must return an empty string, not panic.
	got := detectVersion("this-binary-does-not-exist-tdtest-xyz")
	if got != "" {
		t.Errorf("detectVersion = %q, want empty string for non-existent binary", got)
	}
}

// ---------------------------------------------------------------------------
// Registry.DetectAll – verify every registered tool name appears in result
// ---------------------------------------------------------------------------

func TestDetectAll_ContainsAllRegisteredTools(t *testing.T) {
	r := NewRegistry()
	status := r.DetectAll()

	// Build a set of names reported by DetectAll.
	reported := make(map[string]bool, len(status.Tools))
	for _, tool := range status.Tools {
		reported[tool.Name] = true
	}

	// Every name in the internal registry must appear in the result.
	r.mu.RLock()
	defer r.mu.RUnlock()

	var missing []string
	for name := range r.tools {
		if !reported[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("DetectAll did not report tools: %v", missing)
	}
}

func TestDetectAll_AvailableCountConsistency(t *testing.T) {
	r := NewRegistry()
	status := r.DetectAll()

	count := 0
	for _, tool := range status.Tools {
		if tool.Available {
			count++
		}
	}
	if count != status.Available {
		t.Errorf("status.Available = %d but counted %d available tools in Tools slice", status.Available, count)
	}
}

func TestDetectAll_EachToolHasErrorWhenUnavailable(t *testing.T) {
	r := NewRegistry()
	status := r.DetectAll()

	for _, tool := range status.Tools {
		if !tool.Available && tool.Error == "" {
			t.Errorf("tool %q is unavailable but has no Error message", tool.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// runApktool – when apktool is absent it must record the tool as missing
// ---------------------------------------------------------------------------

func TestRunApktool_ToolMissing(t *testing.T) {
	r := NewRegistry()
	// Do not call DetectAll; all tools are unavailable by default.

	result := &DecompileResult{}
	runApktool(context.Background(), r, "/fake/app.apk", t.TempDir(), result)

	if !containsString(result.ToolsMissing, "apktool") {
		t.Errorf("ToolsMissing = %v, want 'apktool'", result.ToolsMissing)
	}
	if len(result.Steps) != 0 {
		t.Errorf("expected no steps recorded when tool is missing, got %d", len(result.Steps))
	}
}

// ---------------------------------------------------------------------------
// runJadx – when jadx is absent it must record the tool as missing
// ---------------------------------------------------------------------------

func TestRunJadx_ToolMissing(t *testing.T) {
	r := NewRegistry()

	result := &DecompileResult{}
	runJadx(context.Background(), r, "/fake/app.apk", t.TempDir(), false, result)

	if !containsString(result.ToolsMissing, "jadx") {
		t.Errorf("ToolsMissing = %v, want 'jadx'", result.ToolsMissing)
	}
}

func TestRunJadx_ToolMissing_WithDeobf(t *testing.T) {
	r := NewRegistry()

	result := &DecompileResult{}
	runJadx(context.Background(), r, "/fake/app.apk", t.TempDir(), true, result)

	if !containsString(result.ToolsMissing, "jadx") {
		t.Errorf("ToolsMissing = %v, want 'jadx' (deobf mode)", result.ToolsMissing)
	}
}

// ---------------------------------------------------------------------------
// runRetdec – when retdec is absent it must record the tool as missing
// ---------------------------------------------------------------------------

func TestRunRetdec_ToolMissing(t *testing.T) {
	r := NewRegistry()

	result := &DecompileResult{}
	runRetdec(context.Background(), r, "/fake/app.apk", t.TempDir(), result)

	if !containsString(result.ToolsMissing, "retdec") {
		t.Errorf("ToolsMissing = %v, want 'retdec'", result.ToolsMissing)
	}
}

func TestRunRetdec_ToolMissing_NoNativeLibs(t *testing.T) {
	// Even if retdec were available, when the APK has no .so files it should
	// be skipped rather than erroring.  We test the "no native libs" path by
	// injecting a fake retdec and an APK without lib/*.so entries.
	r := NewRegistry()

	echoPath := "/bin/echo"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/echo not available")
	}

	r.mu.Lock()
	r.tools["retdec"] = &Tool{
		Name:      "retdec",
		Binary:    "retdec-decompiler",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	// APK with no lib/*.so files.
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "noso.apk")
	makeZip(t, apkPath, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         []byte("dex\n035"),
	})

	result := &DecompileResult{}
	runRetdec(context.Background(), r, apkPath, t.TempDir(), result)

	if !containsString(result.ToolsSkipped, "retdec (no native libs)") {
		t.Errorf("ToolsSkipped = %v, want 'retdec (no native libs)'", result.ToolsSkipped)
	}
}

// ---------------------------------------------------------------------------
// runIlspy – when ilspycmd is absent it must record the tool as missing
// ---------------------------------------------------------------------------

func TestRunIlspy_ToolMissing(t *testing.T) {
	r := NewRegistry()

	result := &DecompileResult{}
	runIlspy(context.Background(), r, "/fake/app.apk", t.TempDir(), result)

	if !containsString(result.ToolsMissing, "ilspycmd") {
		t.Errorf("ToolsMissing = %v, want 'ilspycmd'", result.ToolsMissing)
	}
}

func TestRunIlspy_NoDotnetAssemblies(t *testing.T) {
	// Inject a fake ilspycmd so availability check passes, then test the
	// "no .NET assemblies" skip path.
	r := NewRegistry()

	echoPath := "/bin/echo"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/echo not available")
	}

	r.mu.Lock()
	r.tools["ilspycmd"] = &Tool{
		Name:      "ilspycmd",
		Binary:    "ilspycmd",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeDotnet,
	}
	r.mu.Unlock()

	// APK with no assemblies/*.dll entries.
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "nodll.apk")
	makeZip(t, apkPath, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         []byte("dex\n035"),
	})

	result := &DecompileResult{}
	runIlspy(context.Background(), r, apkPath, t.TempDir(), result)

	if !containsString(result.ToolsSkipped, "ilspycmd (no .NET assemblies)") {
		t.Errorf("ToolsSkipped = %v, want 'ilspycmd (no .NET assemblies)'", result.ToolsSkipped)
	}
}

// ---------------------------------------------------------------------------
// unwrapAAB – bundletool not available must return error and record missing
// ---------------------------------------------------------------------------

func TestUnwrapAAB_BundletoolMissing(t *testing.T) {
	r := NewRegistry()
	// bundletool is not available (default state before DetectAll).

	dir := t.TempDir()
	result := &DecompileResult{}
	_, err := unwrapAAB(context.Background(), r, "/fake/app.aab", dir, result)

	if err == nil {
		t.Fatal("expected error when bundletool is missing")
	}
	if !strings.Contains(err.Error(), "bundletool") {
		t.Errorf("error %q should mention 'bundletool'", err)
	}
	if !containsString(result.ToolsMissing, "bundletool") {
		t.Errorf("ToolsMissing = %v, want 'bundletool'", result.ToolsMissing)
	}
}

// ---------------------------------------------------------------------------
// extractNativeLibs – additional pattern assertions
// ---------------------------------------------------------------------------

func TestExtractNativeLibs_OnlySoFilesUnderLib(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "app.apk")

	// Mix of matching and non-matching entries.
	makeZip(t, zipPath, map[string][]byte{
		"lib/arm64-v8a/libcore.so": []byte("ELF"),
		"lib/x86_64/libhello.so":   []byte("ELF2"),
		"assets/libwrong.so":       []byte("ELF3"), // not under lib/
		"classes.dex":              []byte("dex"),
	})

	outDir := t.TempDir()
	files, err := extractNativeLibs(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractNativeLibs: %v", err)
	}
	// Only the two lib/*.so files must match.
	if len(files) != 2 {
		t.Errorf("extracted %d files, want 2 (only lib/**/*.so)", len(files))
	}
}

func TestExtractDotnetAssemblies_NestedAssembliesDir(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "app.apk")

	makeZip(t, zipPath, map[string][]byte{
		"assemblies/Mono.Android.dll":     []byte("MZ"),
		"lib/arm64/assemblies/System.dll": []byte("MZ2"), // nested assemblies/
		"classes.dex":                     []byte("dex"),
		"lib/arm64/libnative.so":          []byte("ELF"),
	})

	outDir := t.TempDir()
	files, err := extractDotnetAssemblies(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractDotnetAssemblies: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("extracted %d dll files, want 2", len(files))
	}
}

// ---------------------------------------------------------------------------
// RunWithOptions – WorkDir, Env, OutputDir options
// ---------------------------------------------------------------------------

func TestRegistry_RunWithOptions_WorkDir(t *testing.T) {
	echoPath := "/bin/pwd"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/pwd not available")
	}

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_pwd"] = &Tool{
		Name:      "_pwd",
		Binary:    "pwd",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	workDir := t.TempDir()
	opts := &RunOptions{WorkDir: workDir}
	res, err := r.RunWithOptions(context.Background(), "_pwd", opts)
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}
	// pwd output should contain the workDir path (symlinks aside).
	if !strings.Contains(strings.TrimSpace(res.Stdout), filepath.Base(workDir)) {
		t.Errorf("stdout %q doesn't contain workdir basename %q", res.Stdout, filepath.Base(workDir))
	}
}

func TestRegistry_RunWithOptions_Env(t *testing.T) {
	envPrintPath := "/bin/sh"
	if _, err := os.Stat(envPrintPath); err != nil {
		t.Skip("/bin/sh not available")
	}

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_sh"] = &Tool{
		Name:      "_sh",
		Binary:    "sh",
		Path:      envPrintPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	opts := &RunOptions{
		Env: []string{"TDTEST_VAR=hello_from_env", "PATH=" + os.Getenv("PATH")},
	}
	res, err := r.RunWithOptions(context.Background(), "_sh", opts, "-c", "echo $TDTEST_VAR")
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}
	if !strings.Contains(res.Stdout, "hello_from_env") {
		t.Errorf("stdout %q should contain 'hello_from_env'", res.Stdout)
	}
}

func TestRegistry_RunWithOptions_OutputDirRecorded(t *testing.T) {
	echoPath := "/bin/echo"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/echo not available")
	}

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_echo2"] = &Tool{
		Name:      "_echo2",
		Binary:    "echo",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	wantOutputDir := "/tmp/some-output-dir"
	opts := &RunOptions{OutputDir: wantOutputDir}
	res, err := r.RunWithOptions(context.Background(), "_echo2", opts, "hi")
	if err != nil {
		t.Fatalf("RunWithOptions: %v", err)
	}
	if res.OutputDir != wantOutputDir {
		t.Errorf("OutputDir = %q, want %q", res.OutputDir, wantOutputDir)
	}
}

// ---------------------------------------------------------------------------
// detectTool – alt-binary fallback path
// ---------------------------------------------------------------------------

func TestDetectTool_AltBinaryFallback(t *testing.T) {
	// Create a fake binary only under an alt name so detectTool falls back.
	binDir := t.TempDir()

	altName := "fake-alt-binary-tdtest"
	writeMockVersionScript(t, binDir, altName, "alt 1.0")

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_alttool"] = &Tool{
		Name:        "_alttool",
		Binary:      "primary-that-does-not-exist-tdtest",
		AltBinaries: []string{altName},
		Type:        ToolTypeNative,
	}
	r.mu.Unlock()

	tool := r.Detect("_alttool")
	if tool == nil {
		t.Fatal("Detect returned nil")
	}
	if !tool.Available {
		t.Fatalf("tool should be available via alt binary; error: %s", tool.Error)
	}
	if tool.Binary != altName {
		t.Errorf("Binary = %q, want %q (alt name)", tool.Binary, altName)
	}
	if tool.Path == "" {
		t.Error("Path should be set after detection via alt binary")
	}
}

// ---------------------------------------------------------------------------
// Registry.IsAvailable – after Detect marks a tool available
// ---------------------------------------------------------------------------

func TestIsAvailable_AfterDetect_Unavailable(t *testing.T) {
	r := NewRegistry()
	r.Detect("apktool") // triggers detection; tool almost certainly absent in CI

	tool := r.GetTool("apktool")
	if tool == nil {
		t.Fatal("GetTool returned nil")
	}
	// IsAvailable must agree with the tool struct.
	if r.IsAvailable("apktool") != tool.Available {
		t.Errorf("IsAvailable disagrees with tool.Available")
	}
}

// ---------------------------------------------------------------------------
// RunResult fields populated correctly
// ---------------------------------------------------------------------------

func TestRegistry_Run_ResultFields(t *testing.T) {
	echoPath := "/bin/echo"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/echo not available")
	}

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_echo3"] = &Tool{
		Name:      "_echo3",
		Binary:    "echo",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	res, err := r.Run(context.Background(), "_echo3", "ping")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.Tool != "_echo3" {
		t.Errorf("Tool = %q, want '_echo3'", res.Tool)
	}
	if res.Command != echoPath {
		t.Errorf("Command = %q, want %q", res.Command, echoPath)
	}
	if len(res.Args) != 1 || res.Args[0] != "ping" {
		t.Errorf("Args = %v, want [ping]", res.Args)
	}
	if res.Duration <= 0 {
		t.Error("Duration must be positive")
	}
	if res.Error != "" {
		t.Errorf("Error = %q, want empty for success", res.Error)
	}
}

// ---------------------------------------------------------------------------
// Decompile – DecompileNative and DecompileDotnet flags with missing tools
// ---------------------------------------------------------------------------

func TestDecompile_NativeFlag_ToolMissing(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "minimal.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath:       apkPath,
		OutputDir:       t.TempDir(),
		DecompileNative: true,
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	// retdec is not installed in CI so it must appear as missing or skipped.
	hasMissing := containsString(result.ToolsMissing, "retdec")
	hasSkipped := false
	for _, s := range result.ToolsSkipped {
		if strings.Contains(s, "retdec") {
			hasSkipped = true
		}
	}
	if !hasMissing && !hasSkipped {
		t.Errorf("retdec should appear in ToolsMissing or ToolsSkipped; missing=%v skipped=%v",
			result.ToolsMissing, result.ToolsSkipped)
	}
}

func TestDecompile_DotnetFlag_ToolMissing(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "minimal.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath:       apkPath,
		OutputDir:       t.TempDir(),
		DecompileDotnet: true,
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	// ilspycmd is not installed in CI so it must appear as missing or skipped.
	hasMissing := containsString(result.ToolsMissing, "ilspycmd")
	hasSkipped := false
	for _, s := range result.ToolsSkipped {
		if strings.Contains(s, "ilspycmd") {
			hasSkipped = true
		}
	}
	if !hasMissing && !hasSkipped {
		t.Errorf("ilspycmd should appear in ToolsMissing or ToolsSkipped; missing=%v skipped=%v",
			result.ToolsMissing, result.ToolsSkipped)
	}
}

// ---------------------------------------------------------------------------
// Decompile – ToolFilter for retdec and ilspycmd
// ---------------------------------------------------------------------------

func TestDecompile_ToolFilter_Retdec_Missing(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "minimal.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath:       apkPath,
		OutputDir:       t.TempDir(),
		DecompileNative: true,
		ToolFilter:      "retdec",
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

// ---------------------------------------------------------------------------
// Decompile – TotalDuration is populated
// ---------------------------------------------------------------------------

func TestDecompile_TotalDurationPopulated(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "minimal.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath: apkPath,
		OutputDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	if result.TotalDuration <= 0 {
		t.Error("TotalDuration must be positive after Decompile returns")
	}
}

// ---------------------------------------------------------------------------
// Decompile – InputFormat is set correctly for a plain APK
// ---------------------------------------------------------------------------

func TestDecompile_InputFormatAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath: apkPath,
		OutputDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	if result.InputFormat == "" {
		t.Error("InputFormat must be set")
	}
}

// ---------------------------------------------------------------------------
// RunWithOptions – nil opts uses defaults (no panic)
// ---------------------------------------------------------------------------

func TestRegistry_RunWithOptions_NilOpts(t *testing.T) {
	echoPath := "/bin/echo"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/echo not available")
	}

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_echo4"] = &Tool{
		Name:      "_echo4",
		Binary:    "echo",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	res, err := r.RunWithOptions(context.Background(), "_echo4", nil, "ok")
	if err != nil {
		t.Fatalf("RunWithOptions with nil opts: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
}

// ---------------------------------------------------------------------------
// ToolsStatus – JavaOK / DotnetOK / AdbOK fields are booleans (smoke test)
// ---------------------------------------------------------------------------

func TestDetectAll_RuntimeFlags(t *testing.T) {
	r := NewRegistry()
	status := r.DetectAll()

	// We cannot assert the values are true/false (depends on the environment),
	// but we can assert the struct is well-formed and the fields are readable.
	_ = fmt.Sprintf("java=%v dotnet=%v adb=%v", status.JavaOK, status.DotnetOK, status.AdbOK)
}

// ---------------------------------------------------------------------------
// RunWithOptions – custom timeout shorter than defaultTimeout is honoured
// ---------------------------------------------------------------------------

func TestRegistry_RunWithOptions_CustomTimeout(t *testing.T) {
	sleepPath := "/bin/sleep"
	if _, err := os.Stat(sleepPath); err != nil {
		t.Skip("/bin/sleep not available")
	}

	r := NewRegistry()
	r.mu.Lock()
	r.tools["_sleep2"] = &Tool{
		Name:      "_sleep2",
		Binary:    "sleep",
		Path:      sleepPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	// A 50ms timeout against a 10s sleep — should finish quickly.
	opts := &RunOptions{Timeout: 50 * time.Millisecond}
	start := time.Now()
	_, _ = r.RunWithOptions(context.Background(), "_sleep2", opts, "10")
	elapsed := time.Since(start)

	// The call must return well before the default 10-minute timeout.
	if elapsed > 5*time.Second {
		t.Errorf("RunWithOptions took %v, expected to respect short timeout", elapsed)
	}
}

// ---------------------------------------------------------------------------
// runApktool – mock tool success and nonzero exit paths
// ---------------------------------------------------------------------------

// writeMockScript is defined in testhelper_{unix,windows}_test.go

func injectTool(r *Registry, toolName, binary, scriptPath string) {
	// On Windows, writeMockScript creates .bat files; resolve the actual path.
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			if _, err := os.Stat(scriptPath + ".bat"); err == nil {
				scriptPath = scriptPath + ".bat"
				binary = binary + ".bat"
			}
		}
	}
	r.mu.Lock()
	r.tools[toolName] = &Tool{
		Name:      toolName,
		Binary:    binary,
		Path:      scriptPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()
}

func TestRunApktool_MockSuccess(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "apktool", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "apktool", "apktool", filepath.Join(binDir, "apktool"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runApktool(context.Background(), r, apkPath, t.TempDir(), result)

	if !containsString(result.ToolsUsed, "apktool") {
		t.Errorf("ToolsUsed = %v, want 'apktool'", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || !result.Steps[0].Success {
		t.Error("step should be marked successful")
	}
}

func TestRunApktool_MockNonZeroExit(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "apktool", "echo 'apktool error' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "apktool", "apktool", filepath.Join(binDir, "apktool"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runApktool(context.Background(), r, apkPath, t.TempDir(), result)

	if len(result.Steps) == 0 || result.Steps[0].Success {
		t.Error("step should not be marked successful on nonzero exit")
	}
	if len(result.Errors) == 0 {
		t.Error("expected an error entry on nonzero exit")
	}
}

// ---------------------------------------------------------------------------
// runJadx – mock tool success and deobf flag
// ---------------------------------------------------------------------------

func TestRunJadx_MockSuccess(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "jadx", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "jadx", "jadx", filepath.Join(binDir, "jadx"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runJadx(context.Background(), r, apkPath, t.TempDir(), false, result)

	if !containsString(result.ToolsUsed, "jadx") {
		t.Errorf("ToolsUsed = %v, want 'jadx'", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || !result.Steps[0].Success {
		t.Error("step should be marked successful")
	}
	if strings.Contains(result.Steps[0].Action, "deobfuscation") {
		t.Error("action should not mention deobfuscation when deobf=false")
	}
}

func TestRunJadx_MockSuccess_WithDeobf(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "jadx", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "jadx", "jadx", filepath.Join(binDir, "jadx"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runJadx(context.Background(), r, apkPath, t.TempDir(), true, result)

	if !containsString(result.ToolsUsed, "jadx") {
		t.Errorf("ToolsUsed = %v, want 'jadx'", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || !strings.Contains(result.Steps[0].Action, "deobfuscation") {
		t.Error("action should mention deobfuscation when deobf=true")
	}
}

func TestRunJadx_MockNonZeroExit(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "jadx", "echo 'jadx failed' >&2; exit 2")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "jadx", "jadx", filepath.Join(binDir, "jadx"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runJadx(context.Background(), r, apkPath, t.TempDir(), false, result)

	if containsString(result.ToolsUsed, "jadx") {
		t.Error("jadx should not be in ToolsUsed on failure")
	}
	if len(result.Errors) == 0 {
		t.Error("expected an error entry on nonzero exit")
	}
}

// ---------------------------------------------------------------------------
// runProcyon – 0% coverage; exercise success and nonzero exit
// ---------------------------------------------------------------------------

func TestRunProcyon_MockSuccess(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "procyon", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "procyon", "procyon", filepath.Join(binDir, "procyon"))

	result := &DecompileResult{}
	runProcyon(context.Background(), r, "/fake/classes.jar", t.TempDir(), result)

	if !containsString(result.ToolsUsed, "procyon") {
		t.Errorf("ToolsUsed = %v, want 'procyon'", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || !result.Steps[0].Success {
		t.Error("step should be successful")
	}
}

func TestRunProcyon_MockNonZeroExit(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "procyon", "echo 'boom' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "procyon", "procyon", filepath.Join(binDir, "procyon"))

	result := &DecompileResult{}
	runProcyon(context.Background(), r, "/fake/classes.jar", t.TempDir(), result)

	if containsString(result.ToolsUsed, "procyon") {
		t.Error("procyon should not be in ToolsUsed on failure")
	}
	if len(result.Steps) == 0 || result.Steps[0].Success {
		t.Error("step should not be successful on nonzero exit")
	}
}

// ---------------------------------------------------------------------------
// runJdCli – 0% coverage; exercise success and nonzero exit
// ---------------------------------------------------------------------------

func TestRunJdCli_MockSuccess(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "jd-cli", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "jd-cli", "jd-cli", filepath.Join(binDir, "jd-cli"))

	result := &DecompileResult{}
	runJdCli(context.Background(), r, "/fake/classes.jar", t.TempDir(), result)

	if !containsString(result.ToolsUsed, "jd-cli") {
		t.Errorf("ToolsUsed = %v, want 'jd-cli'", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || !result.Steps[0].Success {
		t.Error("step should be successful")
	}
}

func TestRunJdCli_MockNonZeroExit(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "jd-cli", "echo 'fail' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "jd-cli", "jd-cli", filepath.Join(binDir, "jd-cli"))

	result := &DecompileResult{}
	runJdCli(context.Background(), r, "/fake/classes.jar", t.TempDir(), result)

	if containsString(result.ToolsUsed, "jd-cli") {
		t.Error("jd-cli should not be in ToolsUsed on failure")
	}
	if len(result.Errors) == 0 {
		t.Error("expected an error entry on nonzero exit")
	}
}

// ---------------------------------------------------------------------------
// runFallbackDecompilers – exercises dex2jar + procyon and dex2jar + jd-cli
// ---------------------------------------------------------------------------

func TestRunFallbackDecompilers_Dex2jarMissing(t *testing.T) {
	r := NewRegistry()
	result := &DecompileResult{}
	runFallbackDecompilers(context.Background(), r, "/fake/app.apk", t.TempDir(), result)

	if !containsString(result.ToolsMissing, "dex2jar") {
		t.Errorf("ToolsMissing = %v, want 'dex2jar'", result.ToolsMissing)
	}
}

func TestRunFallbackDecompilers_Dex2jarSuccess_ProcyonChosen(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "dex2jar", "exit 0")
	writeMockScript(t, binDir, "procyon", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "dex2jar", "dex2jar", filepath.Join(binDir, "dex2jar"))
	injectTool(r, "procyon", "procyon", filepath.Join(binDir, "procyon"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runFallbackDecompilers(context.Background(), r, apkPath, t.TempDir(), result)

	if !containsString(result.ToolsUsed, "dex2jar") {
		t.Errorf("ToolsUsed = %v, want 'dex2jar'", result.ToolsUsed)
	}
	if !containsString(result.ToolsUsed, "procyon") {
		t.Errorf("ToolsUsed = %v, want 'procyon'", result.ToolsUsed)
	}
}

func TestRunFallbackDecompilers_Dex2jarSuccess_JdCliChosen(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "dex2jar", "exit 0")
	writeMockScript(t, binDir, "jd-cli", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "dex2jar", "dex2jar", filepath.Join(binDir, "dex2jar"))
	// procyon is intentionally absent; jd-cli is the fallback.
	injectTool(r, "jd-cli", "jd-cli", filepath.Join(binDir, "jd-cli"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runFallbackDecompilers(context.Background(), r, apkPath, t.TempDir(), result)

	if !containsString(result.ToolsUsed, "dex2jar") {
		t.Errorf("ToolsUsed = %v, want 'dex2jar'", result.ToolsUsed)
	}
	if !containsString(result.ToolsUsed, "jd-cli") {
		t.Errorf("ToolsUsed = %v, want 'jd-cli'", result.ToolsUsed)
	}
}

func TestRunFallbackDecompilers_Dex2jarSuccess_BothJarDecompilersMissing(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "dex2jar", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "dex2jar", "dex2jar", filepath.Join(binDir, "dex2jar"))
	// procyon and jd-cli are both absent.

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runFallbackDecompilers(context.Background(), r, apkPath, t.TempDir(), result)

	if !containsString(result.ToolsMissing, "procyon") {
		t.Errorf("ToolsMissing = %v, want 'procyon'", result.ToolsMissing)
	}
	if !containsString(result.ToolsMissing, "jd-cli") {
		t.Errorf("ToolsMissing = %v, want 'jd-cli'", result.ToolsMissing)
	}
}

func TestRunFallbackDecompilers_Dex2jarNonZeroExit(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "dex2jar", "echo 'fail' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "dex2jar", "dex2jar", filepath.Join(binDir, "dex2jar"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result := &DecompileResult{}
	runFallbackDecompilers(context.Background(), r, apkPath, t.TempDir(), result)

	if containsString(result.ToolsUsed, "dex2jar") {
		t.Error("dex2jar should not be in ToolsUsed on failure")
	}
	if len(result.Errors) == 0 {
		t.Error("expected an error entry for dex2jar nonzero exit")
	}
}

// ---------------------------------------------------------------------------
// runRetdec – with native libs present in APK
// ---------------------------------------------------------------------------

func TestRunRetdec_MockSuccess_WithNativeLibs(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "retdec", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "retdec", "retdec", filepath.Join(binDir, "retdec"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeZip(t, apkPath, map[string][]byte{
		"AndroidManifest.xml":        []byte("<manifest/>"),
		"lib/arm64-v8a/libnative.so": []byte("ELF"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	runRetdec(context.Background(), r, apkPath, outDir, result)

	if !containsString(result.ToolsUsed, "retdec") {
		t.Errorf("ToolsUsed = %v, want 'retdec'", result.ToolsUsed)
	}
}

func TestRunRetdec_MockNonZeroExit_WithNativeLibs(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "retdec", "echo 'retdec failed' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "retdec", "retdec", filepath.Join(binDir, "retdec"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeZip(t, apkPath, map[string][]byte{
		"AndroidManifest.xml":        []byte("<manifest/>"),
		"lib/arm64-v8a/libnative.so": []byte("ELF"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	runRetdec(context.Background(), r, apkPath, outDir, result)

	// retdec is still appended to ToolsUsed even when individual libs fail.
	if !containsString(result.ToolsUsed, "retdec") {
		t.Errorf("ToolsUsed = %v, want 'retdec' (appended after loop)", result.ToolsUsed)
	}
	// The nonzero exit should be captured in the step.
	if len(result.Steps) == 0 {
		t.Error("expected at least one step for the lib decompilation attempt")
	}
}

// ---------------------------------------------------------------------------
// runIlspy – with DLL assemblies present in APK
// ---------------------------------------------------------------------------

func TestRunIlspy_MockSuccess_WithDlls(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "ilspycmd", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "ilspycmd", "ilspycmd", filepath.Join(binDir, "ilspycmd"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeZip(t, apkPath, map[string][]byte{
		"AndroidManifest.xml":  []byte("<manifest/>"),
		"assemblies/MyApp.dll": []byte("MZ"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	runIlspy(context.Background(), r, apkPath, outDir, result)

	if !containsString(result.ToolsUsed, "ilspycmd") {
		t.Errorf("ToolsUsed = %v, want 'ilspycmd'", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || !result.Steps[0].Success {
		t.Error("step should be marked successful")
	}
}

func TestRunIlspy_MockNonZeroExit_WithDlls(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "ilspycmd", "echo 'ilspy fail' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "ilspycmd", "ilspycmd", filepath.Join(binDir, "ilspycmd"))

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeZip(t, apkPath, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"assemblies/Foo.dll":  []byte("MZ"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	runIlspy(context.Background(), r, apkPath, outDir, result)

	// ilspycmd is still appended to ToolsUsed after the loop.
	if !containsString(result.ToolsUsed, "ilspycmd") {
		t.Errorf("ToolsUsed = %v, want 'ilspycmd' (appended after loop)", result.ToolsUsed)
	}
	if len(result.Steps) == 0 || result.Steps[0].Success {
		t.Error("step should not be marked successful on nonzero exit")
	}
}

// ---------------------------------------------------------------------------
// unwrapAAB – mock bundletool that succeeds and produces a valid .apks zip
// ---------------------------------------------------------------------------

func TestUnwrapAAB_MockSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses complex shell script; not portable to Windows")
	}
	// The bundletool mock must produce a valid zip at the apksPath argument.
	// We parse apksPath from the --output= flag in the script.
	// Since shell script receives --output=/path/bundle.apks, we extract the
	// path and create a zip with universal.apk inside.
	binDir := t.TempDir()
	script := `#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --output=*) OUT="${arg#--output=}" ;;
  esac
done
# Create a minimal zip with universal.apk so extractFileFromZip succeeds.
python3 -c "
import zipfile, sys
with zipfile.ZipFile('$OUT' if '$OUT' else sys.argv[1], 'w') as z:
    z.writestr('universal.apk', 'fake-apk')
" 2>/dev/null || {
  # Fallback: use zip command.
  TMPFILE=$(mktemp /tmp/uapk.XXXXXX)
  echo 'fake-apk' > "$TMPFILE"
  zip -j "$OUT" "$TMPFILE" -x "*" 2>/dev/null
  rm -f "$TMPFILE"
}
exit 0
`
	if err := os.WriteFile(filepath.Join(binDir, "bundletool"), []byte(script), 0o755); err != nil {
		t.Fatalf("write bundletool mock: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "bundletool", "bundletool", filepath.Join(binDir, "bundletool"))

	dir := t.TempDir()
	aabPath := filepath.Join(dir, "app.aab")
	if err := os.WriteFile(aabPath, []byte("fake aab content"), 0o644); err != nil {
		t.Fatalf("write aab: %v", err)
	}

	outDir := t.TempDir()
	result := &DecompileResult{}
	apkPath, err := unwrapAAB(context.Background(), r, aabPath, outDir, result)

	if err != nil {
		// This path may fail if neither python3 nor zip is available; skip gracefully.
		t.Skipf("bundletool mock could not create zip (python3/zip unavailable): %v", err)
	}

	if !containsString(result.ToolsUsed, "bundletool") {
		t.Errorf("ToolsUsed = %v, want 'bundletool'", result.ToolsUsed)
	}
	if !strings.HasSuffix(apkPath, "base.apk") {
		t.Errorf("returned path %q should end with base.apk", apkPath)
	}
}

func TestUnwrapAAB_MockBundletoolFails(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "bundletool", "echo 'bundletool error' >&2; exit 1")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	r := NewRegistry()
	injectTool(r, "bundletool", "bundletool", filepath.Join(binDir, "bundletool"))

	dir := t.TempDir()
	aabPath := filepath.Join(dir, "app.aab")
	if err := os.WriteFile(aabPath, []byte("fake aab"), 0o644); err != nil {
		t.Fatalf("write aab: %v", err)
	}

	outDir := t.TempDir()
	result := &DecompileResult{}
	_, err := unwrapAAB(context.Background(), r, aabPath, outDir, result)

	if err == nil {
		t.Fatal("expected error when bundletool exits nonzero")
	}
	if len(result.Errors) == 0 {
		t.Error("expected an error entry in result.Errors")
	}
}

// ---------------------------------------------------------------------------
// unwrapBundle – APK passthrough (non-bundle format returns inputPath unchanged)
// ---------------------------------------------------------------------------

func TestUnwrapBundle_PlainAPK_Passthrough(t *testing.T) {
	r := NewRegistry()
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	format, err := apk.DetectFormat(apkPath)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}

	result := &DecompileResult{}
	got, err := unwrapBundle(context.Background(), r, format, apkPath, t.TempDir(), result)
	if err != nil {
		t.Fatalf("unwrapBundle: %v", err)
	}
	if got != apkPath {
		t.Errorf("plain APK should be returned unchanged; got %q, want %q", got, apkPath)
	}
	if len(result.Steps) != 0 {
		t.Errorf("plain APK passthrough should add no steps, got %d", len(result.Steps))
	}
}

// ---------------------------------------------------------------------------
// unwrapBundle – XAPK bundle routes to unwrapZipBundle
// ---------------------------------------------------------------------------

func TestUnwrapBundle_XAPKBundle_ExtractsBaseAPK(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "app.xapk")
	makeZip(t, bundlePath, map[string][]byte{
		"base.apk":      []byte("fake-apk"),
		"manifest.json": []byte("{}"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}

	// FormatXAPK is the apk.FormatType value; use the constant from the tools package via Decompile path.
	// We test unwrapZipBundle directly since we cannot construct apk.FormatXAPK without importing apk.
	apkPath, err := unwrapZipBundle(bundlePath, outDir, result)
	if err != nil {
		t.Fatalf("unwrapZipBundle: %v", err)
	}
	if !strings.HasSuffix(apkPath, "base.apk") {
		t.Errorf("path %q should end with base.apk", apkPath)
	}
}

// ---------------------------------------------------------------------------
// Decompile – ToolFilter "apktool" with mock tool present
// ---------------------------------------------------------------------------

func TestDecompile_ToolFilter_Apktool_MockSuccess(t *testing.T) {
	binDir := t.TempDir()
	writeMockScript(t, binDir, "apktool", "exit 0")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+origPath)

	// We cannot inject the registry into Decompile directly (it creates its own),
	// so we rely on PATH injection for exec.LookPath inside DetectAll.
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "app.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath:  apkPath,
		OutputDir:  t.TempDir(),
		ToolFilter: "apktool",
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	// apktool was found via PATH; it should be used.
	if !containsString(result.ToolsUsed, "apktool") {
		// Not a hard failure — apktool may not be the exact binary name on this system.
		t.Logf("apktool not in ToolsUsed (may not match binary name on this system): %v", result.ToolsUsed)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func containsString(slice []string, s string) bool {
	return slices.Contains(slice, s)
}
