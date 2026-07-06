/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ToolType identifies the runtime requirement for a tool.
type ToolType string

const (
	ToolTypeNative ToolType = "native"
	ToolTypeJava   ToolType = "java"
	ToolTypeDotnet ToolType = "dotnet"
)

// Tool represents an external reverse engineering tool.
type Tool struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Binary      string   `json:"binary"`
	AltBinaries []string `json:"-"`
	Type        ToolType `json:"type"`
	Version     string   `json:"version"`
	Path        string   `json:"path"`
	Available   bool     `json:"available"`
	Error       string   `json:"error,omitempty"`
}

// ToolsStatus is the result of detecting all registered tools.
type ToolsStatus struct {
	Tools     []*Tool `json:"tools"`
	Available int     `json:"available"`
	Total     int     `json:"total"`
	JavaOK    bool    `json:"java_available"`
	DotnetOK  bool    `json:"dotnet_available"`
	AdbOK     bool    `json:"adb_available"`
}

// Registry manages the set of known external tools.
type Registry struct {
	tools map[string]*Tool
	mu    sync.RWMutex
}

// NewRegistry creates a registry with all supported tool definitions.
func NewRegistry() *Registry {
	r := &Registry{
		tools: make(map[string]*Tool),
	}

	defs := []Tool{
		{
			Name:        "apktool",
			Description: "APK resource decoding and smali disassembly",
			Binary:      "apktool",
			Type:        ToolTypeJava,
		},
		{
			Name:        "jadx",
			Description: "DEX to Java decompiler",
			Binary:      "jadx",
			Type:        ToolTypeJava,
		},
		{
			Name:        "dex2jar",
			Description: "DEX to JAR converter",
			Binary:      "d2j-dex2jar",
			AltBinaries: []string{"d2j-dex2jar.sh", "d2j-dex2jar.bat"},
			Type:        ToolTypeJava,
		},
		{
			Name:        "procyon",
			Description: "Java decompiler (jadx fallback)",
			Binary:      "procyon",
			AltBinaries: []string{"procyon-decompiler"},
			Type:        ToolTypeJava,
		},
		{
			Name:        "jd-cli",
			Description: "Java decompiler CLI",
			Binary:      "jd-cli",
			Type:        ToolTypeJava,
		},
		{
			Name:        "retdec",
			Description: "Native binary decompiler",
			Binary:      "retdec-decompiler",
			AltBinaries: []string{"retdec"},
			Type:        ToolTypeNative,
		},
		{
			Name:        "ilspycmd",
			Description: ".NET/Xamarin assembly decompiler",
			Binary:      "ilspycmd",
			Type:        ToolTypeDotnet,
		},
		{
			Name:        "bundletool",
			Description: "Android App Bundle tool",
			Binary:      "bundletool",
			Type:        ToolTypeJava,
		},
		{
			Name:        "adb",
			Description: "Android Debug Bridge",
			Binary:      "adb",
			Type:        ToolTypeNative,
		},
	}

	for i := range defs {
		t := defs[i]
		r.tools[t.Name] = &t
	}

	return r
}

// Detect checks availability of a single tool by name.
func (r *Registry) Detect(name string) *Tool {
	r.mu.RLock()
	t, ok := r.tools[name]
	r.mu.RUnlock()

	if !ok {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.detectTool(t)

	return t
}

// DetectAll checks availability of all registered tools and runtimes.
func (r *Registry) DetectAll() *ToolsStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	status := &ToolsStatus{}

	for _, t := range r.tools {
		r.detectTool(t)

		status.Tools = append(status.Tools, t)
		if t.Available {
			status.Available++
		}
	}

	status.Total = len(r.tools)

	// Check runtimes
	if _, err := exec.LookPath("java"); err == nil {
		status.JavaOK = true
	}

	if _, err := exec.LookPath("dotnet"); err == nil {
		status.DotnetOK = true
	}

	if t, ok := r.tools["adb"]; ok {
		status.AdbOK = t.Available
	}

	return status
}

// IsAvailable returns whether a tool is detected on the system.
func (r *Registry) IsAvailable(name string) bool {
	r.mu.RLock()
	t, ok := r.tools[name]
	r.mu.RUnlock()

	if !ok {
		return false
	}

	return t.Available
}

// GetTool returns the tool definition by name.
func (r *Registry) GetTool(name string) *Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.tools[name]
}

func (r *Registry) detectTool(t *Tool) {
	// Try primary binary
	if path, err := exec.LookPath(t.Binary); err == nil {
		t.Path = path
		t.Available = true
		t.Version = detectVersion(t.Binary)

		return
	}

	// Try alternatives
	for _, alt := range t.AltBinaries {
		if path, err := exec.LookPath(alt); err == nil {
			t.Path = path
			t.Binary = alt
			t.Available = true
			t.Version = detectVersion(alt)

			return
		}
	}

	t.Available = false
	t.Error = "not found in PATH"
}

func detectVersion(binary string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try common version flags
	for _, flag := range []string{"--version", "-version", "version"} {
		cmd := exec.CommandContext(ctx, binary, flag)

		out, err := cmd.CombinedOutput()
		if err == nil && len(out) > 0 {
			return parseVersionLine(string(out))
		}
	}

	return ""
}

func parseVersionLine(output string) string {
	line := strings.TrimSpace(output)
	// Take first line only
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	// Limit length
	if len(line) > 100 {
		line = line[:100]
	}

	return strings.TrimSpace(line)
}
