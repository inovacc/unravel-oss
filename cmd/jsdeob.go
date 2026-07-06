/*
Copyright © 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/jsdeob"

	"github.com/spf13/cobra"
)

var (
	jsdeobOutputFile     string
	jsdeobBeautify       bool
	jsdeobDecodeStrings  bool
	jsdeobUnpackPacked   bool
	jsdeobSimplifyMath   bool
	jsdeobRenameVars     bool
	jsdeobExtractStrings bool
	jsdeobAllTransforms  bool
	jsdeobExtractURLs    bool
	jsdeobExtractFuncs   bool
	jsdeobExtractAPI     bool
	jsdeobExtractHeaders bool
	jsdeobMinLength      int
	jsdeobBeautifyAI     bool
)

var jsdeobCmd = &cobra.Command{
	Use:   "jsdeob",
	Short: "JavaScript deobfuscator and unpacker",
	Long: `A security research tool for deobfuscating and unpacking JavaScript code.

Supported features:
  - Beautify/format minified code
  - Decode string encodings (hex, unicode, base64, char codes)
  - Unpack eval-based packers
  - Simplify constant expressions
  - Rename obfuscated variables
  - Extract strings and URLs`,
}

var jsdeobDeobfuscateCmd = &cobra.Command{
	Use:   "deobfuscate <file>",
	Short: "Deobfuscate JavaScript code",
	Long: `Deobfuscate and unpack JavaScript code.

Transformations:
  --beautify       Format minified code with proper indentation
  --decode         Decode hex, unicode, base64, and charcode strings
  --unpack         Unpack packed/encoded sections
  --simplify       Simplify constant math expressions
  --rename         Rename _0x... variables to readable names
  --extract        Extract strings and URLs

Examples:
  unravel jsdeob deobfuscate app.js -o clean.js --all
  unravel jsdeob deobfuscate app.js --decode --beautify
  unravel jsdeob deobfuscate app.js --extract --json`,
	Args: cobra.ExactArgs(1),
	RunE: runJsdeobDeobfuscate,
}

var jsdeobBeautifyCmd = &cobra.Command{
	Use:   "beautify <file>",
	Short: "Beautify/format minified JavaScript",
	Long: `Format minified JavaScript code with proper indentation.

Examples:
  unravel jsdeob beautify app.min.js -o app.js
  unravel jsdeob beautify app.min.js`,
	Args: cobra.ExactArgs(1),
	RunE: runJsdeobBeautify,
}

var jsdeobDecodeCmd = &cobra.Command{
	Use:   "decode <file>",
	Short: "Decode encoded strings in JavaScript",
	Long: `Decode various string encodings:

  - Hex strings: \x48\x65\x6c\x6c\x6f -> Hello
  - Unicode: \u0048\u0065\u006c\u006c\u006f -> Hello
  - Base64: atob("SGVsbG8=") -> "Hello"
  - CharCodes: String.fromCharCode(72,101,108,108,111) -> "Hello"

Examples:
  unravel jsdeob decode obfuscated.js -o decoded.js
  unravel jsdeob decode obfuscated.js --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runJsdeobDecode,
}

var jsdeobExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract strings, URLs, and other data from JavaScript",
	Long: `Extract various data from JavaScript code:

  --urls       Extract URLs
  --functions  Extract function names
  --api        Extract API calls (fetch, axios, XHR, method+path, API paths)
  --headers    Extract HTTP request headers (x-*, Authorization, etc.)
  --strings    Extract all strings (default)

Examples:
  unravel jsdeob extract app.js --urls
  unravel jsdeob extract app.js --api --json
  unravel jsdeob extract app.js --api --headers --json
  unravel jsdeob extract app.js --functions`,
	Args: cobra.ExactArgs(1),
	RunE: runJsdeobExtract,
}

var jsdeobAnalyzeCmd = &cobra.Command{
	Use:   "analyze <file>",
	Short: "Analyze JavaScript for security-relevant patterns",
	Long: `Analyze JavaScript code for security-relevant patterns:

  - Dangerous functions
  - Obfuscation indicators
  - Network operations
  - Encoded payloads

Examples:
  unravel jsdeob analyze suspicious.js
  unravel jsdeob analyze app.js --json`,
	Args: cobra.ExactArgs(1),
	RunE: runJsdeobAnalyze,
}

func init() {
	rootCmd.AddCommand(jsdeobCmd)
	jsdeobCmd.AddCommand(jsdeobDeobfuscateCmd)
	jsdeobCmd.AddCommand(jsdeobBeautifyCmd)
	jsdeobCmd.AddCommand(jsdeobDecodeCmd)
	jsdeobCmd.AddCommand(jsdeobExtractCmd)
	jsdeobCmd.AddCommand(jsdeobAnalyzeCmd)

	// deobfuscate flags
	jsdeobDeobfuscateCmd.Flags().StringVarP(&jsdeobOutputFile, "output", "o", "", "Output file (default: stdout)")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobBeautify, "beautify", "b", false, "Beautify/format code")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobDecodeStrings, "decode", "d", false, "Decode encoded strings")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobUnpackPacked, "unpack", "u", false, "Unpack packed code")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobSimplifyMath, "simplify", "s", false, "Simplify math expressions")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobRenameVars, "rename", "r", false, "Rename obfuscated variables")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobExtractStrings, "extract", "e", false, "Extract strings and URLs")
	jsdeobDeobfuscateCmd.Flags().BoolVarP(&jsdeobAllTransforms, "all", "a", false, "Apply all transformations")
	jsdeobDeobfuscateCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")

	// beautify flags
	jsdeobBeautifyCmd.Flags().StringVarP(&jsdeobOutputFile, "output", "o", "", "Output file (default: stdout)")
	jsdeobBeautifyCmd.Flags().BoolVar(&jsdeobBeautifyAI, "ai", false, "Use AI-driven beautification with framework detection (D-15)")

	// decode flags
	jsdeobDecodeCmd.Flags().StringVarP(&jsdeobOutputFile, "output", "o", "", "Output file (default: stdout)")

	// extract flags
	jsdeobExtractCmd.Flags().BoolVar(&jsdeobExtractURLs, "urls", false, "Extract URLs only")
	jsdeobExtractCmd.Flags().BoolVar(&jsdeobExtractFuncs, "functions", false, "Extract function names")
	jsdeobExtractCmd.Flags().BoolVar(&jsdeobExtractAPI, "api", false, "Extract API calls")
	jsdeobExtractCmd.Flags().BoolVar(&jsdeobExtractHeaders, "headers", false, "Extract HTTP request headers")
	jsdeobExtractCmd.Flags().IntVar(&jsdeobMinLength, "min-length", 3, "Minimum string length")
	jsdeobExtractCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")

	// analyze flags
	jsdeobAnalyzeCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}

func runJsdeobDeobfuscate(_ *cobra.Command, args []string) error {
	inputFile := args[0]

	code, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	opts := jsdeob.Options{
		Beautify:       jsdeobBeautify || jsdeobAllTransforms,
		DecodeStrings:  jsdeobDecodeStrings || jsdeobAllTransforms,
		UnpackPacked:   jsdeobUnpackPacked || jsdeobAllTransforms,
		SimplifyMath:   jsdeobSimplifyMath || jsdeobAllTransforms,
		RenameVars:     jsdeobRenameVars || jsdeobAllTransforms,
		ExtractStrings: jsdeobExtractStrings || jsdeobAllTransforms,
		Verbose:        verbose,
	}

	if !jsdeobBeautify && !jsdeobDecodeStrings && !jsdeobUnpackPacked && !jsdeobSimplifyMath && !jsdeobRenameVars && !jsdeobExtractStrings && !jsdeobAllTransforms {
		opts.Beautify = true
	}

	result, err := jsdeob.Deobfuscate(string(code), opts)
	if err != nil {
		return fmt.Errorf("deobfuscation failed: %w", err)
	}

	if jsonFormat {
		output := map[string]any{
			"file":            filepath.Base(inputFile),
			"transformations": result.Transformations,
			"urls":            result.ExtractedURLs,
			"strings_count":   len(result.ExtractedStrs),
			"code_length":     len(result.Code),
		}
		if jsdeobExtractStrings || jsdeobAllTransforms {
			output["strings"] = result.ExtractedStrs
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(output)
	}

	if verbose && len(result.Transformations) > 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Transformations applied:")
		for _, t := range result.Transformations {
			_, _ = fmt.Fprintf(os.Stderr, "  - %s\n", t)
		}

		_, _ = fmt.Fprintln(os.Stderr)
	}

	if (jsdeobExtractStrings || jsdeobAllTransforms) && !jsonFormat {
		if len(result.ExtractedURLs) > 0 {
			_, _ = fmt.Fprintln(os.Stderr, "Extracted URLs:")
			for _, url := range result.ExtractedURLs {
				_, _ = fmt.Fprintf(os.Stderr, "  %s\n", url)
			}

			_, _ = fmt.Fprintln(os.Stderr)
		}
	}

	if jsdeobOutputFile != "" {
		if err := os.WriteFile(jsdeobOutputFile, []byte(result.Code), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}

		_, _ = fmt.Fprintf(os.Stderr, "Output written to: %s\n", jsdeobOutputFile)
	} else {
		fmt.Print(result.Code)
	}

	return nil
}

// sanitizeJsdeobPath rejects path-traversal segments at the Cobra
// boundary (T-06-01 / D-19). Mirrors sanitizeDotnetPath in dotnet.go.
func sanitizeJsdeobPath(p string, mustExist bool) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if mustExist {
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("stat path: %w", err)
		}
	}
	return abs, nil
}

// jsdeobAIBeautifier adapts an *ai.Client to jsdeob.Beautifier.
type jsdeobAIBeautifier struct {
	c *ai.Client
}

func (a *jsdeobAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

func runJsdeobBeautify(cmd *cobra.Command, args []string) error {
	inAbs, err := sanitizeJsdeobPath(args[0], true)
	if err != nil {
		return fmt.Errorf("input path: %w", err)
	}
	inputFile := inAbs

	code, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// 06-04 Task 1 / D-15: --ai dispatches to jsdeob.BeautifyAI with
	// framework detection.
	if jsdeobBeautifyAI {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		client, cerr := ai.NewClient()
		if cerr != nil {
			return fmt.Errorf("ai client: %w", cerr)
		}
		opts := jsdeob.BeautifyAIOptions{AIEnabled: true, InputPath: inAbs}
		if jsdeobOutputFile != "" {
			outAbs, oerr := sanitizeJsdeobPath(jsdeobOutputFile, false)
			if oerr != nil {
				return fmt.Errorf("output path: %w", oerr)
			}
			opts.OutputDir = filepath.Dir(outAbs)
			jsdeobOutputFile = outAbs
		}
		bytes_, report, berr := jsdeob.BeautifyAI(ctx, &jsdeobAIBeautifier{c: client}, code, opts)
		if berr != nil {
			return fmt.Errorf("beautify-ai: %w", berr)
		}
		out.PrintBeautifyAIReport(report, os.Stderr)
		if jsdeobOutputFile != "" {
			if dir := filepath.Dir(jsdeobOutputFile); dir != "" {
				_ = os.MkdirAll(dir, 0o755)
			}
			// Reject symlink at output target (T-06-06).
			if info, lerr := os.Lstat(jsdeobOutputFile); lerr == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("refusing to write through symlink: %q", jsdeobOutputFile)
				}
			}
			if werr := os.WriteFile(jsdeobOutputFile, bytes_, 0o644); werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
		} else {
			fmt.Print(string(bytes_))
		}
		return nil
	}

	result := jsdeob.Beautify(string(code))

	if jsdeobOutputFile != "" {
		outPath := jsdeobOutputFile

		// If -o points to a directory (or ends with a separator), generate
		// the output filename from the input basename.
		if strings.HasSuffix(outPath, "/") || strings.HasSuffix(outPath, "\\") {
			outPath = filepath.Join(outPath, filepath.Base(inputFile))
		} else if info, statErr := os.Stat(outPath); statErr == nil && info.IsDir() {
			outPath = filepath.Join(outPath, filepath.Base(inputFile))
		}

		// Ensure parent directory exists
		if dir := filepath.Dir(outPath); dir != "" {
			if mkErr := os.MkdirAll(dir, 0755); mkErr != nil {
				return fmt.Errorf("failed to create output directory: %w", mkErr)
			}
		}

		if err := os.WriteFile(outPath, []byte(result), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}

		_, _ = fmt.Fprintf(os.Stderr, "Output written to: %s\n", outPath)
	} else {
		fmt.Print(result)
	}

	return nil
}

func runJsdeobDecode(_ *cobra.Command, args []string) error {
	inputFile := args[0]

	code, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	codeStr := string(code)
	totalDecoded := 0

	unpacked, count := jsdeob.UnpackPacked(codeStr)
	codeStr = unpacked
	totalDecoded += count

	decoded, count := jsdeob.DecodeStrings(codeStr)
	codeStr = decoded
	totalDecoded += count

	if verbose {
		_, _ = fmt.Fprintf(os.Stderr, "Decoded %d encoded strings/sections\n", totalDecoded)
	}

	if jsdeobOutputFile != "" {
		if err := os.WriteFile(jsdeobOutputFile, []byte(codeStr), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}

		_, _ = fmt.Fprintf(os.Stderr, "Output written to: %s\n", jsdeobOutputFile)
	} else {
		fmt.Print(codeStr)
	}

	return nil
}

func runJsdeobExtract(_ *cobra.Command, args []string) error {
	inputFile := args[0]

	code, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	codeStr := string(code)
	output := make(map[string]any)

	extractAll := !jsdeobExtractURLs && !jsdeobExtractFuncs && !jsdeobExtractAPI && !jsdeobExtractHeaders

	if jsdeobExtractURLs || extractAll {
		urls := jsdeob.ExtractURLs(codeStr)
		output["urls"] = urls

		if !jsonFormat {
			fmt.Println("URLs:")

			for _, url := range urls {
				fmt.Printf("  %s\n", url)
			}

			fmt.Println()
		}
	}

	if jsdeobExtractFuncs || extractAll {
		funcs := jsdeob.ExtractFunctions(codeStr)
		output["functions"] = funcs

		if !jsonFormat {
			fmt.Println("Functions:")

			for _, f := range funcs {
				fmt.Printf("  %s\n", f)
			}

			fmt.Println()
		}
	}

	if jsdeobExtractAPI || extractAll {
		calls := jsdeob.ExtractAPICalls(codeStr)
		output["api_calls"] = calls

		if !jsonFormat {
			fmt.Println("API Calls:")

			for _, c := range calls {
				fmt.Printf("  %s\n", c)
			}

			fmt.Println()
		}
	}

	if jsdeobExtractHeaders || extractAll {
		headers := jsdeob.ExtractHeaders(codeStr)
		output["headers"] = headers

		if !jsonFormat {
			fmt.Println("HTTP Headers:")

			for _, h := range headers {
				fmt.Printf("  %s\n", h)
			}

			fmt.Println()
		}
	}

	if extractAll {
		strs := jsdeob.ExtractStrings(codeStr)

		var filtered []string

		for _, s := range strs {
			if len(s) >= jsdeobMinLength {
				filtered = append(filtered, s)
			}
		}

		output["strings"] = filtered

		output["strings_count"] = len(filtered)
		if !jsonFormat {
			fmt.Printf("Strings (%d total, showing first 50):\n", len(filtered))

			limit := min(len(filtered), 50)

			for i := 0; i < limit; i++ {
				s := filtered[i]
				if len(s) > 80 {
					s = s[:77] + "..."
				}

				fmt.Printf("  %s\n", s)
			}
		}
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(output)
	}

	return nil
}

type jsdeobAnalysisResult struct {
	File             string   `json:"file"`
	Size             int      `json:"size_bytes"`
	ObfuscationScore int      `json:"obfuscation_score"`
	Indicators       []string `json:"indicators"`
	DangerousCalls   []string `json:"dangerous_calls"`
	NetworkCalls     []string `json:"network_calls"`
	EncodedData      []string `json:"encoded_data"`
	URLs             []string `json:"urls"`
	Strings          int      `json:"strings_count"`
	Functions        int      `json:"functions_count"`
}

func runJsdeobAnalyze(_ *cobra.Command, args []string) error {
	inputFile := args[0]

	code, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	codeStr := string(code)
	result := jsdeobAnalysisResult{
		File:           inputFile,
		Size:           len(code),
		Indicators:     []string{},
		DangerousCalls: []string{},
		NetworkCalls:   []string{},
		EncodedData:    []string{},
	}

	// Check for dangerous function calls
	dangerousPatterns := map[string]*regexp.Regexp{
		"dynamic code execution":  regexp.MustCompile(`\beval\s*\(`),
		"Function constructor":    regexp.MustCompile(`\bFunction\s*\(`),
		"setTimeout with string":  regexp.MustCompile(`setTimeout\s*\(\s*["']`),
		"setInterval with string": regexp.MustCompile(`setInterval\s*\(\s*["']`),
		"DOM write operations":    regexp.MustCompile(`document\.(write|writeln)\s*\(`),
		"innerHTML modification":  regexp.MustCompile(`\.innerHTML\s*=`),
	}

	for name, pattern := range dangerousPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			result.DangerousCalls = append(result.DangerousCalls,
				fmt.Sprintf("%s (%d occurrences)", name, len(matches)))
		}
	}

	// Check for network operations
	networkPatterns := map[string]*regexp.Regexp{
		"fetch()":        regexp.MustCompile(`\bfetch\s*\(`),
		"XMLHttpRequest": regexp.MustCompile(`XMLHttpRequest`),
		"axios":          regexp.MustCompile(`\baxios\b`),
		"WebSocket":      regexp.MustCompile(`\bWebSocket\s*\(`),
		"sendBeacon":     regexp.MustCompile(`navigator\.sendBeacon`),
	}

	for name, pattern := range networkPatterns {
		if pattern.MatchString(codeStr) {
			result.NetworkCalls = append(result.NetworkCalls, name)
		}
	}

	// Check for encoded data
	base64Pattern := regexp.MustCompile(`atob\s*\(\s*["']([A-Za-z0-9+/=]{20,})["']\s*\)`)
	for _, match := range base64Pattern.FindAllStringSubmatch(codeStr, 5) {
		if len(match) > 1 {
			preview := match[1]
			if len(preview) > 30 {
				preview = preview[:30] + "..."
			}

			result.EncodedData = append(result.EncodedData, "base64: "+preview)
		}
	}

	hexPattern := regexp.MustCompile(`"((?:\\x[0-9a-fA-F]{2}){10,})"`)
	if hexPattern.MatchString(codeStr) {
		result.EncodedData = append(result.EncodedData, "hex-encoded strings detected")
	}

	charCodePattern := regexp.MustCompile(`String\.fromCharCode\s*\([\d,\s]{20,}\)`)
	if charCodePattern.MatchString(codeStr) {
		result.EncodedData = append(result.EncodedData, "charcode-encoded strings detected")
	}

	// Calculate obfuscation score
	score := 0

	obfVarPattern := regexp.MustCompile(`_0x[a-f0-9]{4,}`)

	obfVars := len(obfVarPattern.FindAllString(codeStr, -1))
	if obfVars > 10 {
		score += 30

		result.Indicators = append(result.Indicators, fmt.Sprintf("%d obfuscated variable names", obfVars))
	}

	if len(result.EncodedData) > 0 {
		score += 20
	}

	if len(result.DangerousCalls) > 0 {
		score += 15 * len(result.DangerousCalls)
	}

	lines := strings.Split(codeStr, "\n")
	longLines := 0

	for _, line := range lines {
		if len(line) > 500 {
			longLines++
		}
	}

	if longLines > 0 {
		score += 10

		result.Indicators = append(result.Indicators, fmt.Sprintf("%d very long lines (>500 chars)", longLines))
	}

	if len(code) > 1000 && len(lines) < len(code)/500 {
		score += 10

		result.Indicators = append(result.Indicators, "Highly minified/packed code")
	}

	result.ObfuscationScore = score
	result.URLs = jsdeob.ExtractURLs(codeStr)
	result.Strings = len(jsdeob.ExtractStrings(codeStr))
	result.Functions = len(jsdeob.ExtractFunctions(codeStr))

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(result)
	}

	fmt.Printf("File: %s (%d bytes)\n\n", result.File, result.Size)
	fmt.Printf("Obfuscation Score: %d", result.ObfuscationScore)

	if result.ObfuscationScore < 20 {
		fmt.Println(" (LOW)")
	} else if result.ObfuscationScore < 50 {
		fmt.Println(" (MEDIUM)")
	} else {
		fmt.Println(" (HIGH)")
	}

	fmt.Println()

	if len(result.Indicators) > 0 {
		fmt.Println("Obfuscation Indicators:")

		for _, ind := range result.Indicators {
			fmt.Printf("  - %s\n", ind)
		}

		fmt.Println()
	}

	if len(result.DangerousCalls) > 0 {
		fmt.Println("Dangerous Function Calls:")

		for _, call := range result.DangerousCalls {
			fmt.Printf("  - %s\n", call)
		}

		fmt.Println()
	}

	if len(result.NetworkCalls) > 0 {
		fmt.Println("Network Operations:")

		for _, call := range result.NetworkCalls {
			fmt.Printf("  - %s\n", call)
		}

		fmt.Println()
	}

	if len(result.EncodedData) > 0 {
		fmt.Println("Encoded Data:")

		for _, data := range result.EncodedData {
			fmt.Printf("  - %s\n", data)
		}

		fmt.Println()
	}

	if len(result.URLs) > 0 {
		fmt.Println("URLs Found:")

		for _, url := range result.URLs {
			fmt.Printf("  - %s\n", url)
		}

		fmt.Println()
	}

	fmt.Printf("Statistics: %d strings, %d functions\n", result.Strings, result.Functions)

	return nil
}
