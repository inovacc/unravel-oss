/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/frida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fridaGenerateInput struct {
	APKPath   string `json:"apk_path" jsonschema:"Path to APK file for auto-detection"`
	OutputDir string `json:"output_dir,omitempty" jsonschema:"Output directory for .js files"`
	SSL       bool   `json:"ssl,omitempty" jsonschema:"Include SSL pinning bypass"`
	Root      bool   `json:"root,omitempty" jsonschema:"Include root detection bypass"`
	Debug     bool   `json:"debug,omitempty" jsonschema:"Include anti-debug bypass"`
	Network   bool   `json:"network,omitempty" jsonschema:"Include network traffic capture"`
	Crypto    bool   `json:"crypto,omitempty" jsonschema:"Include crypto API hooking"`
	IPC       bool   `json:"ipc,omitempty" jsonschema:"Include IPC monitoring"`
	All       bool   `json:"all,omitempty" jsonschema:"Enable all hook categories"`
	Capture   bool   `json:"capture,omitempty" jsonschema:"Include traffic capture templates (mitmproxy, pcapdroid, burp, charles)"`
}

type fridaRunInput struct {
	PackageName string   `json:"package_name" jsonschema:"Target app package name (required)"`
	Host        string   `json:"host,omitempty" jsonschema:"Frida-server host:port (default 127.0.0.1:27042)"`
	DeviceID    string   `json:"device_id,omitempty" jsonschema:"Target device ID for direct USB"`
	Scripts     []string `json:"scripts,omitempty" jsonschema:"Script names to run (empty = generate all)"`
	Timeout     int      `json:"timeout,omitempty" jsonschema:"Per-script timeout in seconds (default 30)"`
	Spawn       bool     `json:"spawn,omitempty" jsonschema:"Spawn app instead of attaching"`
	SSL         bool     `json:"ssl,omitempty" jsonschema:"Include SSL pinning bypass"`
	Root        bool     `json:"root,omitempty" jsonschema:"Include root detection bypass"`
	Debug       bool     `json:"debug,omitempty" jsonschema:"Include anti-debug bypass"`
	Network     bool     `json:"network,omitempty" jsonschema:"Include network capture"`
	Crypto      bool     `json:"crypto,omitempty" jsonschema:"Include crypto hooking"`
	IPC         bool     `json:"ipc,omitempty" jsonschema:"Include IPC monitoring"`
	All         bool     `json:"all,omitempty" jsonschema:"Enable all hook categories"`
}

func registerFridaTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_frida_generate",
		Description: "Generate Frida instrumentation scripts for an Android APK. Auto-detects cert pinning, root detection, anti-debug, and crypto usage to generate targeted hook scripts.",
	}, handleFridaGenerate)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_frida_run",
		Description: "Run Frida instrumentation scripts against a target Android app. Connects to frida-server, generates scripts if needed, and executes them to collect runtime data.",
	}, handleFridaRun)
}

func handleFridaGenerate(_ context.Context, _ *mcp.CallToolRequest, input fridaGenerateInput) (*mcp.CallToolResult, any, error) {
	// Run dissect to auto-detect
	dr, err := dissect.Run(input.APKPath, dissect.Options{
		Debug: debug.NopRecorder(),
	})
	if err != nil {
		return errorResult(err), nil, nil
	}

	// Use the dissect result's auto-generated Frida scripts if available
	var result *frida.GenerateResult

	hasManual := input.SSL || input.Root || input.Debug || input.Network ||
		input.Crypto || input.IPC || input.All

	if hasManual {
		config := frida.ScriptConfig{
			IncludeSSL:     input.SSL || input.All,
			IncludeRoot:    input.Root || input.All,
			IncludeDebug:   input.Debug || input.All,
			IncludeNetwork: input.Network || input.All,
			IncludeStorage: input.All,
			IncludeCrypto:  input.Crypto || input.All,
			IncludeIPC:     input.IPC || input.All,
		}

		if dr.ManifestInfo != nil {
			config.PackageName = dr.ManifestInfo.Package
		}

		result = frida.Generate(config)

		// Carry over auto-detected info from dissect
		if dr.FridaScripts != nil {
			result.AutoDetected = dr.FridaScripts.AutoDetected
		}
	} else if dr.FridaScripts != nil {
		result = dr.FridaScripts
	} else {
		result = frida.Generate(frida.ScriptConfig{IncludeNetwork: true})
	}

	// Generate capture templates if requested
	if input.Capture || input.All {
		if result.CaptureTemplates == nil {
			pkg := ""
			if dr.ManifestInfo != nil {
				pkg = dr.ManifestInfo.Package
			}

			result.CaptureTemplates = frida.GenerateCapture(pkg, nil)
		}
	}

	// Write to output directory if specified
	if input.OutputDir != "" {
		if err := os.MkdirAll(input.OutputDir, 0755); err != nil {
			return errorResult(fmt.Errorf("create output dir: %w", err)), nil, nil
		}

		for _, s := range result.Scripts {
			path := filepath.Join(input.OutputDir, s.Name+".js")
			if err := os.WriteFile(path, []byte(s.Content), 0644); err != nil {
				return errorResult(fmt.Errorf("write %s: %w", path, err)), nil, nil
			}
		}

		if result.CaptureTemplates != nil {
			for _, tmpl := range result.CaptureTemplates.Templates {
				path := filepath.Join(input.OutputDir, tmpl.Name+"."+tmpl.Format)
				if err := os.WriteFile(path, []byte(tmpl.Content), 0644); err != nil {
					return errorResult(fmt.Errorf("write %s: %w", path, err)), nil, nil
				}
			}
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}

func handleFridaRun(ctx context.Context, _ *mcp.CallToolRequest, input fridaRunInput) (*mcp.CallToolResult, any, error) {
	if input.PackageName == "" {
		return errorResult(fmt.Errorf("package_name is required")), nil, nil
	}

	// Generate scripts based on flags
	hasManual := input.SSL || input.Root || input.Debug || input.Network ||
		input.Crypto || input.IPC || input.All

	config := frida.ScriptConfig{
		PackageName: input.PackageName,
	}

	if hasManual {
		config.IncludeSSL = input.SSL || input.All
		config.IncludeRoot = input.Root || input.All
		config.IncludeDebug = input.Debug || input.All
		config.IncludeNetwork = input.Network || input.All
		config.IncludeStorage = input.All
		config.IncludeCrypto = input.Crypto || input.All
		config.IncludeIPC = input.IPC || input.All
	} else {
		config.IncludeNetwork = true
	}

	generated := frida.Generate(config)

	// Filter scripts if specific names requested
	scripts := generated.Scripts
	if len(input.Scripts) > 0 {
		nameSet := make(map[string]bool, len(input.Scripts))
		for _, n := range input.Scripts {
			nameSet[n] = true
		}

		filtered := make([]frida.GeneratedScript, 0, len(input.Scripts))
		for _, s := range scripts {
			if nameSet[s.Name] {
				filtered = append(filtered, s)
			}
		}

		scripts = filtered
	}

	if len(scripts) == 0 {
		return errorResult(fmt.Errorf("no scripts to run")), nil, nil
	}

	// Build runner
	var opts []frida.RunnerOption
	if input.Host != "" {
		opts = append(opts, frida.WithHost(input.Host))
	}
	if input.DeviceID != "" {
		opts = append(opts, frida.WithDevice(input.DeviceID))
	}

	runner := frida.NewRunner(input.PackageName, opts...)

	// Check device
	if err := runner.CheckDevice(ctx); err != nil {
		return errorResult(fmt.Errorf("device check: %w", err)), nil, nil
	}

	// Determine timeout
	timeout := 30 * time.Second
	if input.Timeout > 0 {
		timeout = time.Duration(input.Timeout) * time.Second
	}

	// Run scripts
	session, err := runner.RunAll(ctx, scripts, timeout)
	if err != nil {
		return errorResult(fmt.Errorf("run scripts: %w", err)), nil, nil
	}

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return errorResult(err), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(data)},
		},
	}, nil, nil
}
