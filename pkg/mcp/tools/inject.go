/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"errors"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/pkg/inject"
	"github.com/inovacc/unravel-oss/pkg/inject/builtins"
	_ "github.com/inovacc/unravel-oss/pkg/inject/registry" // blank-import: fire scanner init() registrations
)

type injectScanInput struct {
	Path      string `json:"path" jsonschema:"Path to app dir or extracted ASAR"`
	ExtractTo string `json:"extract_to,omitempty" jsonschema:"Optional extraction dir for archive inputs"`
}

// injectActiveInput drives the active `unravel_app_inject` MCP tool. The `confirm`
// flag is mandatory and must be `true` — the tool refuses to execute otherwise
// (defensive analysis only; mirrors the CLI consent gate).
type injectActiveInput struct {
	Target     string `json:"target" jsonschema:"Path to running Electron/WebView2 app or ASAR"`
	Builtin    string `json:"builtin,omitempty" jsonschema:"Built-in script name (devtools|ipc-logger|network); mutually exclusive with script"`
	Script     string `json:"script,omitempty" jsonschema:"Inline JS script body; mutually exclusive with builtin"`
	ScriptName string `json:"script_name,omitempty" jsonschema:"Optional logical name for the script (defaults to 'inline.js' or '<builtin>.js')"`
	Method     string `json:"method,omitempty" jsonschema:"cdp | asar | auto (default auto)"`
	World      string `json:"world,omitempty" jsonschema:"main | isolated (default isolated; CDP only)"`
	Persistent bool   `json:"persistent,omitempty" jsonschema:"CDP only: addScriptToEvaluateOnNewDocument vs Runtime.evaluate"`
	CDPPort    int    `json:"cdp_port,omitempty" jsonschema:"CDP only: remote-debugging-port the target was launched with"`
	ASARPath   string `json:"asar_path,omitempty" jsonschema:"ASAR only: explicit path to app.asar"`
	Confirm    bool   `json:"confirm" jsonschema:"REQUIRED: must be true; defensive analysis only — server refuses unless explicitly confirmed"`
}

func registerInjectTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_inject_scan",
		Description: "Enumerate code-injection seams in Electron / Tauri / WebView2 apps (scan-only, never executes target)",
	}, handleInjectScan)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_app_inject",
		Description: "Active code injection into running Electron/WebView2 apps via CDP attach or ASAR repatch (defensive analysis only; requires confirm:true; appends to the unravel injection log)",
	}, handleInjectActive)
}

func handleInjectScan(ctx context.Context, _ *mcp.CallToolRequest, input injectScanInput) (*mcp.CallToolResult, any, error) {
	if input.Path == "" {
		return errorResult(errInjectMissingPath), nil, nil
	}
	// extract_to is reserved for future archive-input support; current scanners
	// expect an already-extracted application directory.
	_ = input.ExtractTo

	result, err := inject.Scan(ctx, input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(result), nil, nil
}

func handleInjectActive(ctx context.Context, _ *mcp.CallToolRequest, input injectActiveInput) (*mcp.CallToolResult, any, error) {
	if input.Target == "" {
		return errorResult(errInjectMissingTarget), nil, nil
	}
	if !input.Confirm {
		return errorResult(errInjectConfirmRequired), nil, nil
	}
	if input.Builtin == "" && input.Script == "" {
		return errorResult(errInjectScriptRequired), nil, nil
	}
	if input.Builtin != "" && input.Script != "" {
		return errorResult(errInjectScriptExclusive), nil, nil
	}

	var script []byte
	scriptName := input.ScriptName
	if input.Builtin != "" {
		b, err := builtins.Get(input.Builtin)
		if err != nil {
			return errorResult(err), nil, nil
		}
		script = b
		if scriptName == "" {
			scriptName = input.Builtin + ".js"
		}
	} else {
		script = []byte(input.Script)
		if scriptName == "" {
			scriptName = "inline.js"
		}
	}

	method := inject.InjectMethod(input.Method)
	if method == "" || method == "auto" {
		// Auto: prefer ASAR if asarPath supplied, else CDP.
		if input.ASARPath != "" {
			method = inject.MethodASAR
		} else {
			method = inject.MethodCDP
		}
	}
	world := input.World
	if world == "" {
		world = "isolated"
	}

	opts := inject.InjectOpts{
		Method:     method,
		Script:     script,
		ScriptName: scriptName,
		World:      world,
		Persistent: input.Persistent,
		CDPPort:    input.CDPPort,
		ASARPath:   input.ASARPath,
		Confirmed:  true,
	}
	res, err := inject.Inject(ctx, input.Target, opts)
	if err != nil {
		if errors.Is(err, inject.ErrConsentRequired) {
			return errorResult(err), nil, nil
		}
		return errorResult(err), nil, nil
	}
	out := map[string]any{
		"target":      res.TargetPath,
		"method":      string(res.Method),
		"script_hash": "sha256:" + res.ScriptHash,
		"script_name": scriptName,
		"started_at":  res.StartedAt,
		"finished_at": res.FinishedAt,
		"persistent":  res.Persistent,
		"output_path": res.OutputPath,
		"audit_log":   inject.LogPath(),
	}
	_ = os.Getenv // keep tree clean if unused; reserved for future env hooks
	return jsonResult(out), nil, nil
}

// errInjectMissingPath is returned when the MCP caller omits the required path.
var errInjectMissingPath = injectErr("inject: path is required")
var errInjectMissingTarget = injectErr("inject: target is required")
var errInjectConfirmRequired = injectErr("inject: confirm must be true (defensive analysis only — explicit consent required)")
var errInjectScriptRequired = injectErr("inject: one of builtin or script is required")
var errInjectScriptExclusive = injectErr("inject: builtin and script are mutually exclusive")

type injectErr string

func (e injectErr) Error() string { return string(e) }
