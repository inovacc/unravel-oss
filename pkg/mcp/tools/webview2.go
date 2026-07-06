/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type webView2DetectInput struct {
	Path string `json:"path" jsonschema:"Path to executable or app directory to inspect"`
}

type webView2AnalyzeInput struct {
	Path           string `json:"path" jsonschema:"Path to executable or app directory to inspect"`
	UDFOverride    string `json:"udf_override,omitempty" jsonschema:"Optional UDF path override (sanitized against path traversal)"`
	ExtractCache   bool   `json:"extract_cache,omitempty" jsonschema:"Extract HTTP cache via pkg/cache (default true)"`
	ExtractLevelDB bool   `json:"extract_leveldb,omitempty" jsonschema:"Extract LevelDB via pkg/leveldb (default true)"`
	ExtractCookies bool   `json:"extract_cookies,omitempty" jsonschema:"Record Cookies SQLite path for pkg/chromium (default true)"`
	MaxProfiles    int    `json:"max_profiles,omitempty" jsonschema:"Max profiles to scan (default 8)"`
}

func registerWebView2Tools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_webview2_detect",
		Description: "Fast WebView2 detection: PE-import signals, file patterns, runtime mode (evergreen/fixed/unknown)",
	}, handleWebView2Detect)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_webview2_analyze",
		Description: "Full WebView2 analysis: UDF discovery, profile enumeration, per-profile cache/LevelDB extraction, Preferences DPAPI flagging",
	}, handleWebView2Analyze)
}

func handleWebView2Detect(_ context.Context, _ *mcp.CallToolRequest, input webView2DetectInput) (*mcp.CallToolResult, any, error) {
	res, err := webview2.Analyze(input.Path, analyze.Options{})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(res), nil, nil
}

func handleWebView2Analyze(_ context.Context, _ *mcp.CallToolRequest, input webView2AnalyzeInput) (*mcp.CallToolResult, any, error) {
	if _, err := sanitizeMCPUDFPath(input.UDFOverride); err != nil {
		return errorResult(err), nil, nil
	}

	opts := analyze.DefaultOptions()
	// Only override defaults when the caller explicitly set a field. We treat
	// the zero-value booleans as "use default" by checking whether at least
	// one extract flag is non-default OR MaxProfiles is set.
	if input.ExtractCache || input.ExtractLevelDB || input.ExtractCookies || input.MaxProfiles > 0 {
		opts = analyze.Options{
			ExtractCache:      input.ExtractCache,
			ExtractLevelDB:    input.ExtractLevelDB,
			ExtractCookies:    input.ExtractCookies,
			RejectSymlinks:    true,
			MaxProfilesToScan: input.MaxProfiles,
		}
	}
	// Thread udf_override end-to-end (BUG-02 / D-02). The override is
	// always honored, regardless of whether other extract flags are set.
	opts.UDFOverride = input.UDFOverride

	res, err := webview2.Analyze(input.Path, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(res), nil, nil
}

// sanitizeMCPUDFPath mitigates T-03-14 path-traversal through the MCP handler.
func sanitizeMCPUDFPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("udf_override contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve udf_override: %w", err)
	}
	// Per D-02: surface the override even when the path does not exist or is
	// not yet a directory. Existence is decided by the resolver (Exists flag).
	// We only reject path traversal here.
	if st, err := os.Stat(abs); err == nil && !st.IsDir() {
		return "", fmt.Errorf("udf_override is not a directory: %s", abs)
	}
	return abs, nil
}
