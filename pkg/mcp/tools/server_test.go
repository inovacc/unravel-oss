/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect creates an in-memory client session connected to the given server.
func connect(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)

	ct, st := mcp.NewInMemoryTransports()

	serverSession, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}

	t.Cleanup(func() { _ = serverSession.Wait() })

	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestNewServerRegistersExpectedTools(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	ctx := context.Background()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	expectedTools := []string{
		// garble
		"unravel_garble_detect",
		"unravel_garble_info",
		"unravel_garble_strings",
		"unravel_garble_symbols",
		"unravel_garble_scan",
		// cert
		"unravel_cert_info",
		"unravel_cert_verify",
		"unravel_cert_compare",
		"unravel_cert_scan",
		// extension
		"unravel_extension_scan",
		"unravel_extension_analyze",
		"unravel_extension_search",
		"unravel_extension_list",
		"unravel_extension_gather",
		// asar
		"unravel_asar_extract",
		"unravel_asar_dump",
		"unravel_asar_search",
		// analyze
		"unravel_app_scan",
		// leveldb
		"unravel_leveldb_parse",
		// cache
		"unravel_cache_parse",
		// ipc
		"unravel_ipc_discover",
		"unravel_ipc_fuzz",
		// license
		"unravel_license_test",
		// jsdeob
		"unravel_jsdeob_analyze",
		"unravel_jsdeob_deobfuscate",
		// android
		"unravel_android_extract",
		"unravel_android_info",
		"unravel_android_static_verify",
		"unravel_android_static_cert",
		"unravel_android_static_decompile",
		"unravel_android_tools_status",
		"unravel_android_static_manifest",
		"unravel_android_static_secrets",
		"unravel_android_static_dex",
		"unravel_android_static_native",
		"unravel_android_static_obfuscation",
		"unravel_android_static_network",
		"unravel_android_static_resources",
		"unravel_android_static_telemetry",
		"unravel_android_static_kotlin",
		"unravel_android_static_protobuf",
		"unravel_android_static_framework",
		// deb
		"unravel_deb_extract",
		"unravel_deb_info",
		"unravel_deb_verify",
		// rpm
		"unravel_rpm_extract",
		"unravel_rpm_info",
		"unravel_rpm_verify",
		// detect
		"unravel_app_detect",
		// disasm
		"unravel_app_disasm",
		// msi
		"unravel_msi_extract",
		"unravel_msi_info",
		"unravel_msi_verify",
		// dissect
		"unravel_app_dissect",
		// capture
		"unravel_capture_diff",
		"unravel_capture_list",
		// schema
		"unravel_app_schema",
		// knowledge
		"unravel_knowledge",
	}

	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("expected tool %q not registered", name)
		}
	}

	if len(result.Tools) < len(expectedTools) {
		t.Errorf("got %d tools, want at least %d", len(result.Tools), len(expectedTools))
	}
}

func TestToolsHaveDescriptions(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	ctx := context.Background()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
	}
}

// callTool is a helper that calls a tool by name with the given arguments.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	ctx := context.Background()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}

	return result
}

// assertIsError checks that the result is an error result containing the given substring.
func assertIsError(t *testing.T, result *mcp.CallToolResult, substr string) {
	t.Helper()

	if !result.IsError {
		t.Fatalf("expected error result, got success")
	}

	if len(result.Content) == 0 {
		t.Fatal("error result has no content")
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if substr != "" && !strings.Contains(text, substr) {
		t.Errorf("error text %q does not contain %q", text, substr)
	}
}

// TestErrorPaths_MissingFile tests that handlers return error results for nonexistent files.
func TestErrorPaths_MissingFile(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	tests := []struct {
		tool string
		args map[string]any
	}{
		{"unravel_garble_detect", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_garble_info", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_garble_strings", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_garble_symbols", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_cert_info", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_cert_verify", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_cert_compare", map[string]any{"binary_paths": []string{"/nonexistent/a", "/nonexistent/b"}}},
		{"unravel_asar_extract", map[string]any{"file_path": "/nonexistent/app.asar"}},
		{"unravel_asar_dump", map[string]any{"file_path": "/nonexistent/app.asar"}},
		{"unravel_asar_search", map[string]any{"file_path": "/nonexistent/app.asar", "pattern": "test"}},
		{"unravel_leveldb_parse", map[string]any{"path": "/nonexistent/leveldb"}},
		{"unravel_cache_parse", map[string]any{"path": "/nonexistent/cache"}},
		{"unravel_ipc_discover", map[string]any{"binary_path": "/nonexistent/binary"}},
		{"unravel_app_detect", map[string]any{"path": "/nonexistent/file"}},
		{"unravel_app_disasm", map[string]any{"path": "/nonexistent/binary"}},
		{"unravel_app_dissect", map[string]any{"path": "/nonexistent/file"}},
		{"unravel_deb_extract", map[string]any{"deb_path": "/nonexistent/pkg.deb"}},
		{"unravel_deb_info", map[string]any{"deb_path": "/nonexistent/pkg.deb"}},
		{"unravel_deb_verify", map[string]any{"deb_path": "/nonexistent/pkg.deb"}},
		{"unravel_rpm_extract", map[string]any{"rpm_path": "/nonexistent/pkg.rpm"}},
		{"unravel_rpm_info", map[string]any{"rpm_path": "/nonexistent/pkg.rpm"}},
		{"unravel_rpm_verify", map[string]any{"rpm_path": "/nonexistent/pkg.rpm"}},
		{"unravel_msi_extract", map[string]any{"msi_path": "/nonexistent/pkg.msi"}},
		{"unravel_msi_info", map[string]any{"msi_path": "/nonexistent/pkg.msi"}},
		{"unravel_msi_verify", map[string]any{"msi_path": "/nonexistent/pkg.msi"}},
		{"unravel_android_extract", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_info", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_verify", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_cert", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_manifest", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_secrets", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_dex", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_native", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_network", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_resources", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_android_static_framework", map[string]any{"apk_path": "/nonexistent/app.apk"}},
		{"unravel_jsdeob_analyze", map[string]any{"file_path": "/nonexistent/script.js"}},
		{"unravel_jsdeob_deobfuscate", map[string]any{"file_path": "/nonexistent/script.js"}},
		{"unravel_android_static_decompile", map[string]any{"input_path": "/nonexistent/app.apk"}},
		{"unravel_capture_diff", map[string]any{"before_file": "/nonexistent/a.json", "after_file": "/nonexistent/b.json"}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			result := callTool(t, session, tt.tool, tt.args)
			assertIsError(t, result, "")
		})
	}
}

// TestJsonResult verifies the jsonResult helper produces valid JSON text content.
func TestJsonResult(t *testing.T) {
	data := map[string]string{"key": "value"}
	result := jsonResult(data)

	if result.IsError {
		t.Fatal("jsonResult returned error")
	}

	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content, got %d", len(result.Content))
	}

	text := result.Content[0].(*mcp.TextContent).Text

	var parsed map[string]string
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("jsonResult output is not valid JSON: %v", err)
	}

	if parsed["key"] != "value" {
		t.Errorf("unexpected value: %v", parsed)
	}
}

// TestJsonResult_UnmarshalableValue verifies jsonResult handles marshal errors.
func TestJsonResult_UnmarshalableValue(t *testing.T) {
	result := jsonResult(make(chan int))

	if !result.IsError {
		t.Fatal("expected error for unmarshalable value")
	}
}

// TestErrorResult verifies the errorResult helper.
func TestErrorResult(t *testing.T) {
	result := errorResult(fmt.Errorf("test error"))

	if !result.IsError {
		t.Fatal("expected IsError=true")
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "test error") {
		t.Errorf("error text %q missing expected message", text)
	}
}

// TestAndroidToolsStatus calls the tools status handler which requires no file input.
func TestAndroidToolsStatus(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_android_tools_status", map[string]any{})
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !json.Valid([]byte(text)) {
		t.Error("android_tools result is not valid JSON")
	}
}

// TestAndroidObfuscation_NonexistentAPK exercises the obfuscation handler which
// tolerates DEX scan failure and still produces a result.
func TestAndroidObfuscation_NonexistentAPK(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_android_static_obfuscation", map[string]any{
		"apk_path": "/nonexistent/app.apk",
	})

	// Obfuscation handler doesn't fail on missing APK - it proceeds with nil DEX.
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAndroidTelemetry_NonexistentAPK exercises the telemetry handler which
// tolerates both DEX and manifest failures.
func TestAndroidTelemetry_NonexistentAPK(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_android_static_telemetry", map[string]any{
		"apk_path": "/nonexistent/app.apk",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAndroidKotlin_NonexistentAPK exercises the kotlin handler with nil DEX.
func TestAndroidKotlin_NonexistentAPK(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_android_static_kotlin", map[string]any{
		"apk_path": "/nonexistent/app.apk",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestJsdeobAnalyze_ValidFile tests jsdeob analyze with a real JS file.
func TestJsdeobAnalyze_ValidFile(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "test.js")
	_ = os.WriteFile(jsFile, []byte(`
		var x = "https://api.example.com/data";
		function fetchData() { return fetch(x); }
	`), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_jsdeob_analyze", map[string]any{
		"file_path": jsFile,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "api.example.com") {
		t.Error("expected URL extraction in result")
	}
}

// TestJsdeobDeobfuscate_ValidFile tests deobfuscation with a real JS file.
func TestJsdeobDeobfuscate_ValidFile(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "obfuscated.js")
	_ = os.WriteFile(jsFile, []byte(`var a=1+2+3;var b="hello"+"world";`), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_jsdeob_deobfuscate", map[string]any{
		"file_path": jsFile,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestDetect_ValidFile tests the detect tool with a real file.
func TestDetect_ValidFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	_ = os.WriteFile(testFile, []byte("hello world"), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_detect", map[string]any{
		"path": testFile,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestDetect_Directory tests the detect tool with a directory (scan mode).
func TestDetect_Directory(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_detect", map[string]any{
		"path": dir,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestGarbleStrings_DefaultMinLen verifies the default min_len logic.
func TestGarbleStrings_DefaultMinLen(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	// This will fail because the binary doesn't exist, but it exercises the
	// default min_len code path before calling garble.ExtractStrings.
	result := callTool(t, session, "unravel_garble_strings", map[string]any{
		"binary_path": "/nonexistent/binary",
		"min_len":     0,
	})

	assertIsError(t, result, "")
}

// TestIPCFuzz_DefaultValues verifies the IPC fuzz handler defaults.
func TestIPCFuzz_DefaultValues(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	// Fuzz with an invalid URL will still exercise the default value logic.
	result := callTool(t, session, "unravel_ipc_fuzz", map[string]any{
		"url": "http://127.0.0.1:1/invalid",
	})

	// FuzzCommands runs with nil commands, so it should return a (possibly empty) report.
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestLicenseTest exercises the license test handler with an unreachable URL.
func TestLicenseTest(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_license_test", map[string]any{
		"url":     "http://127.0.0.1:1/nonexistent",
		"timeout": 1,
	})

	// RunTests produces a report even on failure.
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAnalyze_GatherMode exercises the gather code path.
func TestAnalyze_GatherMode(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_scan", map[string]any{
		"gather": true,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAnalyze_InvalidAppPath exercises the error path with a missing app.
func TestAnalyze_InvalidAppPath(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_scan", map[string]any{
		"app_path": "/nonexistent/app",
	})

	assertIsError(t, result, "")
}

// TestAnalyze_InvalidManifest exercises the custom manifest error path.
func TestAnalyze_InvalidManifest(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_scan", map[string]any{
		"app_path":      "/nonexistent/app",
		"manifest_path": "/nonexistent/manifest.yaml",
	})

	assertIsError(t, result, "")
}

// TestExtensionList exercises the extension list handler.
func TestExtensionList(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_extension_list", map[string]any{})

	// Should return an array (possibly empty) of browser profiles.
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestExtensionSearch exercises the extension search handler.
func TestExtensionSearch(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_extension_search", map[string]any{
		"pattern": "nonexistent_pattern_xyz",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestLoadManifest verifies the loadManifest helper returns a non-nil manifest.
func TestLoadManifest(t *testing.T) {
	m := loadManifest()
	if m == nil {
		t.Fatal("loadManifest returned nil")
	}
}

// TestDissect_ValidFile tests dissect with a real file and output dir.
func TestDissect_ValidFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.js")
	_ = os.WriteFile(testFile, []byte(`var x = 1; console.log(x);`), 0644)

	outDir := filepath.Join(dir, "output")

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_dissect", map[string]any{
		"path":       testFile,
		"output_dir": outDir,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestDissect_ValidFileNoOutput tests dissect without output dir.
func TestDissect_ValidFileNoOutput(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "hello.txt")
	_ = os.WriteFile(testFile, []byte("hello world"), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_dissect", map[string]any{
		"path": testFile,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestExtensionScan exercises the extension scan handler.
func TestExtensionScan(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_extension_scan", map[string]any{
		"browser": "nonexistent_browser",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestExtensionAnalyze_InvalidTarget exercises the extension analyze error path.
func TestExtensionAnalyze_InvalidTarget(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_extension_analyze", map[string]any{
		"target":  "/nonexistent/extension",
		"browser": "nonexistent",
	})

	// May return error or empty result depending on implementation.
	_ = result
}

// TestExtensionGather exercises the extension gather handler.
func TestExtensionGather(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_extension_gather", map[string]any{
		"browser": "nonexistent_browser",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestGarbleScan_NonexistentDir returns empty results (not error) for missing dir.
func TestGarbleScan_NonexistentDir(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_garble_scan", map[string]any{
		"directory_path": "/nonexistent/dir",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestCertScan_NonexistentDir returns empty results for missing dir.
func TestCertScan_NonexistentDir(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_cert_scan", map[string]any{
		"directory_path": "/nonexistent/dir",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAndroidProtobuf_NonexistentAPK tolerates missing APK.
func TestAndroidProtobuf_NonexistentAPK(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_android_static_protobuf", map[string]any{
		"apk_path": "/nonexistent/app.apk",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// makeMinimalASAR writes a minimal valid ASAR archive to path with a single file entry.
func makeMinimalASAR(t *testing.T, path string) {
	t.Helper()

	// Build header JSON with one small file entry.
	headerJSON := `{"files":{"hello.txt":{"offset":"0","size":5}}}`
	fileData := []byte("hello")

	headerBytes := []byte(headerJSON)
	headerSize := uint32(len(headerBytes))

	// ASAR header layout: 4-byte magic-like padding, 4-byte total-header-size,
	// 4-byte padding, 4-byte header-string-size, then headerJSON, then file data.
	totalHeaderSize := 8 + headerSize // matches the 8-byte inner block

	buf := make([]byte, 0, 16+len(headerBytes)+len(fileData))

	b4 := make([]byte, 4)
	// bytes 0-3: inner block size (4 + headerSize)
	binary.LittleEndian.PutUint32(b4, 4+headerSize)
	buf = append(buf, b4...)
	// bytes 4-7: totalHeaderSize
	binary.LittleEndian.PutUint32(b4, totalHeaderSize)
	buf = append(buf, b4...)
	// bytes 8-11: padding (conventionally matches totalHeaderSize)
	binary.LittleEndian.PutUint32(b4, totalHeaderSize)
	buf = append(buf, b4...)
	// bytes 12-15: header string size
	binary.LittleEndian.PutUint32(b4, headerSize)
	buf = append(buf, b4...)
	buf = append(buf, headerBytes...)
	buf = append(buf, fileData...)

	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatalf("write asar: %v", err)
	}
}

// TestAsarExtract_ValidFile exercises the extract success path.
func TestAsarExtract_ValidFile(t *testing.T) {
	dir := t.TempDir()
	asarPath := filepath.Join(dir, "app.asar")
	makeMinimalASAR(t, asarPath)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_asar_extract", map[string]any{
		"file_path":  asarPath,
		"output_dir": filepath.Join(dir, "out"),
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAsarExtract_DefaultOutputDir exercises the default output dir path.
func TestAsarExtract_DefaultOutputDir(t *testing.T) {
	dir := t.TempDir()
	asarPath := filepath.Join(dir, "app.asar")
	makeMinimalASAR(t, asarPath)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_asar_extract", map[string]any{
		"file_path": asarPath,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestAsarDump_ValidFile exercises the dump success path.
func TestAsarDump_ValidFile(t *testing.T) {
	dir := t.TempDir()
	asarPath := filepath.Join(dir, "app.asar")
	makeMinimalASAR(t, asarPath)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_asar_dump", map[string]any{
		"file_path": asarPath,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "hello.txt") {
		t.Error("dump output should contain file entry name")
	}
}

// TestAsarSearch_ValidFile exercises the search success path.
func TestAsarSearch_ValidFile(t *testing.T) {
	dir := t.TempDir()
	asarPath := filepath.Join(dir, "app.asar")
	makeMinimalASAR(t, asarPath)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_asar_search", map[string]any{
		"file_path": asarPath,
		"pattern":   "hello",
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestFridaGenerate_MissingAPK exercises the frida generate error path.
func TestFridaGenerate_MissingAPK(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_generate", map[string]any{
		"apk_path": "/nonexistent/app.apk",
	})

	assertIsError(t, result, "")
}

// TestFridaRun_EmptyPackageName exercises the package_name empty-string check.
func TestFridaRun_EmptyPackageName(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_run", map[string]any{
		"package_name": "",
	})

	assertIsError(t, result, "package_name is required")
}

// TestFridaRun_NoDevice exercises the device check failure path.
func TestFridaRun_NoDevice(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_run", map[string]any{
		"package_name": "com.example.app",
		"ssl":          true,
	})

	// Should fail at device check since no frida-server is running.
	assertIsError(t, result, "")
}

// TestFridaRun_NoScripts exercises the "no scripts to run" path by filtering all scripts out.
func TestFridaRun_NoScripts(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_run", map[string]any{
		"package_name": "com.example.app",
		"scripts":      []any{"nonexistent_script_xyz"},
	})

	assertIsError(t, result, "no scripts to run")
}

// TestDissect_AIAnalysisMCP exercises the MCP AI mode path.
func TestDissect_AIAnalysisMCP(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "test.js")
	_ = os.WriteFile(jsFile, []byte(`var x = "https://api.example.com"; eval(x);`), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_app_dissect", map[string]any{
		"path":            jsFile,
		"ai_analysis_mcp": true,
	})

	// The ai_analysis_mcp branch is taken when result.AIPrompt != ""; result may or
	// may not have a prompt depending on dissect analysis, but the call must not crash.
	_ = result
}

// TestFridaGenerate_ValidFile exercises frida generate with a real JS file so
// dissect.Run succeeds and the generate logic runs.
func TestFridaGenerate_ValidFile(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "app.js")
	_ = os.WriteFile(jsFile, []byte(`var x = "https://api.example.com"; eval(x);`), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_generate", map[string]any{
		"apk_path": jsFile,
	})

	// dissect.Run should succeed on a JS file; frida generate should return JSON.
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestFridaGenerate_ManualFlags exercises the manual flags path (hasManual = true).
func TestFridaGenerate_ManualFlags(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "app.js")
	_ = os.WriteFile(jsFile, []byte(`console.log("hello");`), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_generate", map[string]any{
		"apk_path": jsFile,
		"ssl":      true,
		"root":     true,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestFridaGenerate_AllFlag exercises the all=true code path with output dir.
func TestFridaGenerate_AllFlag(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "app.js")
	_ = os.WriteFile(jsFile, []byte(`console.log("hello");`), 0644)

	server := NewServer()
	session := connect(t, server)

	result := callTool(t, session, "unravel_frida_generate", map[string]any{
		"apk_path":   jsFile,
		"all":        true,
		"capture":    true,
		"output_dir": filepath.Join(dir, "scripts"),
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestDissect_WithOutputDirAndAIMCP exercises the output dir + AI MCP paths.
func TestDissect_WithOutputDirAndAIMCP(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "bundle.js")
	_ = os.WriteFile(jsFile, []byte(`
		var _0x1a = ["hello", "world"];
		eval("https://api.example.com/v1/data");
	`), 0644)

	outDir := filepath.Join(dir, "out")

	server := NewServer()
	session := connect(t, server)

	// With output dir: exercises markdown report + AI prompt writing paths.
	result := callTool(t, session, "unravel_app_dissect", map[string]any{
		"path":            jsFile,
		"output_dir":      outDir,
		"ai_analysis_mcp": true,
	})

	_ = result
}

// TestNewServerRegistersExpectedFridaTools verifies frida tools are registered.
func TestNewServerRegistersExpectedFridaTools(t *testing.T) {
	server := NewServer()
	session := connect(t, server)

	ctx := context.Background()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	toolNames := make(map[string]bool)
	for _, tool := range res.Tools {
		toolNames[tool.Name] = true
	}

	for _, name := range []string{"unravel_frida_generate", "unravel_frida_run"} {
		if !toolNames[name] {
			t.Errorf("expected tool %q not registered", name)
		}
	}
}

// TestCaptureDiff_ValidFiles exercises the capture diff success path.
func TestCaptureDiff_ValidFiles(t *testing.T) {
	dir := t.TempDir()

	session := `{"version":"1.0","app":{"name":"TestApp","path":"/tmp","framework":"electron","pid":1},"capture":{"started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:01:00Z","duration_ms":60000,"host":"test","tool_version":"1.0"},"events":[]}`

	beforeFile := filepath.Join(dir, "before.json")
	afterFile := filepath.Join(dir, "after.json")
	_ = os.WriteFile(beforeFile, []byte(session), 0644)
	_ = os.WriteFile(afterFile, []byte(session), 0644)

	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_capture_diff", map[string]any{
		"before_file": beforeFile,
		"after_file":  afterFile,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !json.Valid([]byte(text)) {
		t.Error("capture diff result is not valid JSON")
	}
}

// TestCaptureList_ValidDir exercises the capture list success path.
func TestCaptureList_ValidDir(t *testing.T) {
	dir := t.TempDir()

	session := `{"version":"1.0","app":{"name":"MyApp","path":"/tmp","framework":"tauri","pid":2},"capture":{"started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:02:00Z","duration_ms":120000,"host":"test","tool_version":"1.0"},"events":[{"seq":1,"ts":"2026-01-01T00:00:01Z","type":"console_log","source":"cdp","data":{}}]}`

	_ = os.WriteFile(filepath.Join(dir, "capture1.json"), []byte(session), 0644)
	_ = os.WriteFile(filepath.Join(dir, "not-json.txt"), []byte("ignored"), 0644)

	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_capture_list", map[string]any{
		"directory": dir,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "MyApp") {
		t.Error("capture list should contain app name")
	}
	if !strings.Contains(text, "tauri") {
		t.Error("capture list should contain framework")
	}
}

// TestCaptureList_EmptyDir exercises the capture list with no JSON files.
func TestCaptureList_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_capture_list", map[string]any{
		"directory": dir,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestCaptureList_InvalidJSON exercises the skip-on-parse-error path.
func TestCaptureList_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not valid json"), 0644)

	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_capture_list", map[string]any{
		"directory": dir,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}
}

// TestSchema_ValidFile exercises the schema extraction MCP tool.
func TestSchema_ValidFile(t *testing.T) {
	dir := t.TempDir()
	jsFile := filepath.Join(dir, "app.js")
	_ = os.WriteFile(jsFile, []byte(`var x = "https://api.example.com"; eval(x);`), 0644)

	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_app_schema", map[string]any{
		"path": jsFile,
	})

	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].(*mcp.TextContent).Text)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !json.Valid([]byte(text)) {
		t.Error("schema result is not valid JSON")
	}
}

// TestSchema_MissingFile exercises the schema error path.
func TestSchema_MissingFile(t *testing.T) {
	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_app_schema", map[string]any{
		"path": "/nonexistent/file",
	})

	assertIsError(t, result, "")
}

// TestCaptureDiff_AfterFileMissing exercises the after-file error path.
func TestCaptureDiff_AfterFileMissing(t *testing.T) {
	dir := t.TempDir()
	session := `{"version":"1.0","app":{"name":"A","path":"/","framework":"e","pid":1},"capture":{"started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:00:01Z","duration_ms":1000,"host":"h","tool_version":"1"},"events":[]}`
	beforeFile := filepath.Join(dir, "before.json")
	_ = os.WriteFile(beforeFile, []byte(session), 0644)

	server := NewServer()
	cs := connect(t, server)

	result := callTool(t, cs, "unravel_capture_diff", map[string]any{
		"before_file": beforeFile,
		"after_file":  filepath.Join(dir, "nonexistent.json"),
	})

	assertIsError(t, result, "after file")
}
