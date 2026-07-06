package dotnet

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// RuntimeConfig represents the parsed .runtimeconfig.json file structure.
type RuntimeConfig struct {
	RuntimeOptions RuntimeOptions `json:"runtimeOptions"`
}

// RuntimeOptions holds the runtime configuration options.
type RuntimeOptions struct {
	TFM              string         `json:"tfm"`
	Framework        *FrameworkRef  `json:"framework,omitempty"`
	Frameworks       []FrameworkRef `json:"frameworks,omitempty"`
	ConfigProperties map[string]any `json:"configProperties,omitempty"`
}

// FrameworkRef identifies a shared framework by name and version.
type FrameworkRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RuntimeConfigResult is the high-level analysis result from parsing a .runtimeconfig.json file.
type RuntimeConfigResult struct {
	TFM        string         `json:"tfm"`
	Frameworks []FrameworkRef `json:"frameworks"`
	Properties map[string]any `json:"properties,omitempty"`
	IsASPNET   bool           `json:"is_aspnet"`
	IsDesktop  bool           `json:"is_desktop"`
}

// ParseRuntimeConfig reads a .runtimeconfig.json file and returns a structured result.
func ParseRuntimeConfig(path string) (*RuntimeConfigResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runtimeconfig.json: %w", err)
	}

	var cfg RuntimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse runtimeconfig.json: %w", err)
	}

	result := &RuntimeConfigResult{
		TFM:        cfg.RuntimeOptions.TFM,
		Properties: cfg.RuntimeOptions.ConfigProperties,
	}

	// Collect frameworks from both singular and plural fields.
	if cfg.RuntimeOptions.Frameworks != nil {
		result.Frameworks = append(result.Frameworks, cfg.RuntimeOptions.Frameworks...)
	} else if cfg.RuntimeOptions.Framework != nil {
		result.Frameworks = append(result.Frameworks, *cfg.RuntimeOptions.Framework)
	}

	// Detect ASP.NET and Desktop frameworks.
	for _, fw := range result.Frameworks {
		lower := strings.ToLower(fw.Name)
		if strings.Contains(lower, "aspnetcore") {
			result.IsASPNET = true
		}
		if strings.Contains(lower, "windowsdesktop") {
			result.IsDesktop = true
		}
	}

	return result, nil
}
