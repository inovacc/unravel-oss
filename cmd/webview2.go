/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"

	"github.com/spf13/cobra"
)

var (
	webview2JSON        bool
	webview2UDFOverride string
)

var webview2Cmd = &cobra.Command{
	Use:   "webview2",
	Short: "WebView2 host application analysis",
	Long: `Analyze WebView2-based desktop applications: detection signals
(PE imports, file patterns, registry), User Data Folder (UDF) discovery,
per-profile data extraction (HTTP cache, LevelDB, Preferences with DPAPI
flagging), and runtime (evergreen/fixed) detection.

Subcommands:
  detect   - Fast signal check + runtime info only
  analyze  - Full analysis: detect + UDF + profiles + data extraction
  udf      - List candidate User Data Folders + profiles`,
}

var webview2DetectCmd = &cobra.Command{
	Use:   "detect <path>",
	Short: "Fast WebView2 detection (signals + runtime info)",
	Args:  cobra.ExactArgs(1),
	Run:   runWebView2Detect,
}

var webview2AnalyzeCmd = &cobra.Command{
	Use:   "analyze <path>",
	Short: "Full WebView2 analysis (UDF discovery + profiles + extraction)",
	Args:  cobra.ExactArgs(1),
	Run:   runWebView2Analyze,
}

var webview2UDFCmd = &cobra.Command{
	Use:   "udf <path>",
	Short: "List candidate WebView2 User Data Folders",
	Args:  cobra.ExactArgs(1),
	Run:   runWebView2UDF,
}

func init() {
	rootCmd.AddCommand(webview2Cmd)
	webview2Cmd.AddCommand(webview2DetectCmd)
	webview2Cmd.AddCommand(webview2AnalyzeCmd)
	webview2Cmd.AddCommand(webview2UDFCmd)

	webview2Cmd.PersistentFlags().BoolVar(&webview2JSON, "json", false, "Output as JSON")
	webview2AnalyzeCmd.Flags().StringVar(&webview2UDFOverride, "udf", "", "Override UDF path (sanitized against path traversal)")
}

// sanitizeUDFPath cleans + rejects path-traversal segments (T-03-13, V5 ASVS).
// Returns ("", error) when the input contains dotdot segments.
func sanitizeUDFPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	cleaned := filepath.Clean(p)
	parts := strings.Split(filepath.ToSlash(cleaned), "/")
	for _, seg := range parts {
		if seg == ".." {
			return "", fmt.Errorf("udf override path contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve udf override: %w", err)
	}
	// D-02: surface override even when missing; only reject path-traversal
	// and explicit non-directory existing paths.
	if st, err := os.Stat(abs); err == nil && !st.IsDir() {
		return "", fmt.Errorf("udf override is not a directory: %s", abs)
	}
	return abs, nil
}

func runWebView2Detect(_ *cobra.Command, args []string) {
	res, err := webview2.Analyze(args[0], analyze.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if webview2JSON {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}
	out.DisplayDetectResult(res)
}

func runWebView2Analyze(_ *cobra.Command, args []string) {
	clean, err := sanitizeUDFPath(webview2UDFOverride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	opts := analyze.DefaultOptions()
	opts.UDFOverride = clean
	res, err := webview2.Analyze(args[0], opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if webview2JSON {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}
	out.DisplayAnalyzeResult(res)
}

func runWebView2UDF(_ *cobra.Command, args []string) {
	res, err := webview2.Analyze(args[0], analyze.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if webview2JSON {
		payload := struct {
			UDFs     any `json:"udfs"`
			Profiles any `json:"profiles"`
		}{res.UDFs, res.Profiles}
		data, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(data))
		return
	}
	out.DisplayUDFs(res)
}
