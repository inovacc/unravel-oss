/*
Copyright (c) 2026 Security Research

Package manifests loads YAML rubric/configuration files used by the analysis
pipeline. The capability-scoring rubric (capabilities.yaml) is loaded here so
pkg/uwp/risk does not need its own YAML wiring.
*/
package manifests

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CapabilitiesConfig is the parsed shape of capabilities.yaml. Unknown keys
// are tolerated by yaml.v3 so the file is forward-compatible.
type CapabilitiesConfig struct {
	Version                  int                `yaml:"version"`
	Weights                  map[string]int     `yaml:"weights"`
	AutoCriticalNamespaces   []string           `yaml:"auto_critical_namespaces"`
	AutoCriticalNames        []string           `yaml:"auto_critical_names"`
	UnknownCapability        UnknownCap         `yaml:"unknown_capability"`
	SignatureMultipliers     map[string]float64 `yaml:"signature_multipliers"`
	TrustedMicrosoftMaxLevel string             `yaml:"trusted_microsoft_max_bucket"`
	Buckets                  []Bucket           `yaml:"buckets"`
}

// UnknownCap holds the unknown-capability handling rule (D-12).
type UnknownCap struct {
	Bucket string `yaml:"bucket"`
	Weight int    `yaml:"weight"`
}

// Bucket is one entry of the categorical bucket ladder.
type Bucket struct {
	Name string `yaml:"name"`
	Max  int    `yaml:"max"`
}

// LoadCapabilities reads and parses the YAML capability rubric at path. It
// applies a path-traversal guard (T-04-06) before opening the file: paths
// containing ".." segments are rejected, and the resolved path must point at
// a regular file.
//
// Returns (nil, fs.ErrNotExist) when the file is absent so callers can fall
// back to Go-baked defaults explicitly.
func LoadCapabilities(path string) (*CapabilitiesConfig, error) {
	if path == "" {
		return nil, fs.ErrNotExist
	}

	clean := filepath.Clean(path)
	// Reject any traversal-looking segments. We compare against the raw path
	// because filepath.Clean may already collapse ../ on absolute roots; the
	// presence of ".." in the original input is the suspicious signal.
	if strings.Contains(filepath.ToSlash(path), "../") || strings.HasSuffix(filepath.ToSlash(path), "/..") {
		return nil, fmt.Errorf("manifests: refusing to load path with traversal segments: %q", path)
	}

	abs, err := filepath.Abs(clean)
	if err != nil {
		return nil, fmt.Errorf("manifests: resolve path: %w", err)
	}

	stat, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("manifests: stat %q: %w", abs, err)
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("manifests: not a regular file: %q", abs)
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("manifests: read %q: %w", abs, err)
	}

	cfg := &CapabilitiesConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("manifests: parse yaml %q: %w", abs, err)
	}
	return cfg, nil
}
