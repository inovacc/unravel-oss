/*
Copyright (c) 2026 Security Research
*/

// Package mcpprobe provides MCP tool enumeration for npm-distributed MCP servers.
// It reads package.json to find the server entry point, spawns it via stdio,
// and probes its capabilities using the MCP protocol (JSON-RPC 2.0).
package mcpprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	mcpclient "github.com/inovacc/unravel-oss/pkg/mcp/client"
	"github.com/inovacc/unravel-oss/pkg/npm"
)

// DefaultTimeout is the default probe timeout.
const DefaultTimeout = 10 * time.Second

// ProbeResult holds the MCP capabilities discovered from an npm package.
type ProbeResult struct {
	PackageName    string           `json:"package_name"`
	PackageVersion string           `json:"package_version"`
	ServerName     string           `json:"server_name,omitempty"`
	ServerVersion  string           `json:"server_version,omitempty"`
	ProtocolVer    string           `json:"protocol_version,omitempty"`
	Transport      string           `json:"transport"`
	EntryPoint     string           `json:"entry_point"`
	TotalTools     int              `json:"total_tools"`
	Tools          []ToolDetail     `json:"tools,omitempty"`
	Resources      []ResourceDetail `json:"resources,omitempty"`
	Prompts        []PromptDetail   `json:"prompts,omitempty"`
	Duration       time.Duration    `json:"duration"`
	Error          string           `json:"error,omitempty"`
}

// ToolDetail describes a single MCP tool with its input schema.
type ToolDetail struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// ResourceDetail describes a single MCP resource.
type ResourceDetail struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// PromptDetail describes a single MCP prompt.
type PromptDetail struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Probe discovers MCP capabilities from an npm package directory.
// It reads package.json to find the entry point, determines the right
// command to spawn (node, npx, etc.), and uses the MCP protocol to
// enumerate tools, resources, and prompts.
func Probe(ctx context.Context, dir string, timeout time.Duration) (*ProbeResult, error) {
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	// Read package.json to find entry point and metadata.
	pkgPath := filepath.Join(dir, "package.json")
	pkg, err := npm.ParsePackageJSON(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: %w", err)
	}

	// Find the MCP server entry point.
	entryPoint, err := findEntryPoint(dir, pkg)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: %w", err)
	}

	// Determine command and args.
	command, args := buildCommand(dir, entryPoint)

	// Probe using mcpclient.
	raw, err := mcpclient.Probe(ctx, command, args...)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: %w", err)
	}

	// Convert to our enriched result.
	result := &ProbeResult{
		PackageName:    pkg.Name,
		PackageVersion: pkg.Version,
		ServerName:     raw.ServerName,
		ServerVersion:  raw.ServerVersion,
		ProtocolVer:    raw.ProtocolVer,
		Transport:      "stdio",
		EntryPoint:     entryPoint,
		TotalTools:     len(raw.Tools),
		Duration:       time.Since(start),
		Error:          raw.Error,
	}

	for _, t := range raw.Tools {
		result.Tools = append(result.Tools, ToolDetail{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}

	for _, r := range raw.Resources {
		result.Resources = append(result.Resources, ResourceDetail{
			URI:         r.URI,
			Name:        r.Name,
			Description: r.Description,
		})
	}

	for _, p := range raw.Prompts {
		result.Prompts = append(result.Prompts, PromptDetail{
			Name:        p.Name,
			Description: p.Description,
		})
	}

	return result, nil
}

// findEntryPoint determines the MCP server entry point from package.json.
// It checks (in order):
//  1. bin field entries
//  2. scripts with "start" or "serve" key
//  3. main field
//  4. common entry files (index.js, index.mjs, server.js, dist/index.js)
func findEntryPoint(dir string, pkg *npm.PackageJSON) (string, error) {
	// 1. Check bin entries — most MCP servers declare a bin.
	bins := pkg.BinEntries()
	if len(bins) > 0 {
		// Prefer a bin entry that contains "mcp" or "server" in its name.
		for name, path := range bins {
			lower := strings.ToLower(name)
			if strings.Contains(lower, "mcp") || strings.Contains(lower, "server") {
				return path, nil
			}
		}
		// Fall back to first bin entry.
		for _, path := range bins {
			return path, nil
		}
	}

	// 2. Check scripts for a "start" or "serve" command that references a file.
	for _, key := range []string{"start", "serve", "mcp"} {
		if script, ok := pkg.Scripts[key]; ok {
			// Extract the file argument from "node server.js" or similar.
			if entry := extractFileFromScript(script); entry != "" {
				return entry, nil
			}
		}
	}

	// 3. Check main field.
	if pkg.Main != "" {
		absMain := filepath.Join(dir, pkg.Main)
		if _, err := os.Stat(absMain); err == nil {
			return pkg.Main, nil
		}
	}

	// 4. Check common entry files.
	candidates := []string{
		"index.js", "index.mjs", "server.js", "server.mjs",
		"dist/index.js", "dist/index.mjs",
		"build/index.js", "build/index.mjs",
		"src/index.js", "src/index.ts",
	}

	for _, c := range candidates {
		absPath := filepath.Join(dir, c)
		if _, err := os.Stat(absPath); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("no MCP server entry point found in %s", dir)
}

// extractFileFromScript tries to extract a .js/.mjs/.ts file path from a script string.
// E.g., "node src/index.js --stdio" -> "src/index.js"
func extractFileFromScript(script string) string {
	parts := strings.FieldsSeq(script)
	for p := range parts {
		lower := strings.ToLower(p)
		if strings.HasSuffix(lower, ".js") ||
			strings.HasSuffix(lower, ".mjs") ||
			strings.HasSuffix(lower, ".cjs") ||
			strings.HasSuffix(lower, ".ts") {
			return p
		}
	}

	return ""
}

// buildCommand determines the command and arguments to spawn the MCP server.
func buildCommand(dir string, entryPoint string) (string, []string) {
	absEntry := filepath.Join(dir, entryPoint)

	// Check if the entry point has a shebang or is a .js/.mjs file.
	ext := strings.ToLower(filepath.Ext(entryPoint))

	switch ext {
	case ".js", ".cjs":
		return nodeCommand(), []string{absEntry}
	case ".mjs":
		return nodeCommand(), []string{absEntry}
	case ".ts":
		// Try npx tsx for TypeScript.
		return "npx", []string{"tsx", absEntry}
	default:
		// Assume it's a node script.
		return nodeCommand(), []string{absEntry}
	}
}

// nodeCommand returns the node executable name (node.exe on Windows).
func nodeCommand() string {
	if runtime.GOOS == "windows" {
		return "node.exe"
	}

	return "node"
}

// FormatToolList returns a formatted string listing all tools.
func FormatToolList(result *ProbeResult) string {
	if result == nil || len(result.Tools) == 0 {
		return "No tools discovered."
	}

	var sb strings.Builder

	_, _ = fmt.Fprintf(&sb, "Server:        %s", result.ServerName)
	if result.ServerVersion != "" {
		_, _ = fmt.Fprintf(&sb, " v%s", result.ServerVersion)
	}

	sb.WriteString("\n")

	if result.ProtocolVer != "" {
		_, _ = fmt.Fprintf(&sb, "Protocol:      %s\n", result.ProtocolVer)
	}

	_, _ = fmt.Fprintf(&sb, "Package:       %s@%s\n", result.PackageName, result.PackageVersion)
	_, _ = fmt.Fprintf(&sb, "Entry Point:   %s\n", result.EntryPoint)
	_, _ = fmt.Fprintf(&sb, "Transport:     %s\n", result.Transport)
	_, _ = fmt.Fprintf(&sb, "Total Tools:   %d\n", result.TotalTools)
	_, _ = fmt.Fprintf(&sb, "Duration:      %s\n", result.Duration.Round(time.Millisecond))

	_, _ = fmt.Fprintf(&sb, "\nTools (%d):\n", len(result.Tools))
	for _, t := range result.Tools {
		if t.Description != "" {
			_, _ = fmt.Fprintf(&sb, "  %-40s %s\n", t.Name, t.Description)
		} else {
			_, _ = fmt.Fprintf(&sb, "  %s\n", t.Name)
		}
	}

	if len(result.Resources) > 0 {
		_, _ = fmt.Fprintf(&sb, "\nResources (%d):\n", len(result.Resources))
		for _, r := range result.Resources {
			if r.Description != "" {
				_, _ = fmt.Fprintf(&sb, "  %-40s %s\n", r.URI, r.Description)
			} else {
				_, _ = fmt.Fprintf(&sb, "  %s\n", r.URI)
			}
		}
	}

	if len(result.Prompts) > 0 {
		_, _ = fmt.Fprintf(&sb, "\nPrompts (%d):\n", len(result.Prompts))
		for _, p := range result.Prompts {
			if p.Description != "" {
				_, _ = fmt.Fprintf(&sb, "  %-40s %s\n", p.Name, p.Description)
			} else {
				_, _ = fmt.Fprintf(&sb, "  %s\n", p.Name)
			}
		}
	}

	return sb.String()
}
