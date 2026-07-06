package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed config.example.yaml
var exampleConfig []byte

// ExampleConfig returns the embedded annotated config template.
func ExampleConfig() []byte {
	return exampleConfig
}

// Scaffold writes the embedded example config to path when no file exists
// there yet, creating parent directories as needed.
func Scaffold(path string) (created bool, resolved string, err error) {
	if path == "" {
		path = Path()
	}

	switch _, statErr := os.Stat(path); {
	case statErr == nil:
		return false, path, nil
	case !os.IsNotExist(statErr):
		return false, path, fmt.Errorf("stat config %s: %w", path, statErr)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, path, fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, exampleConfig, 0o600); err != nil {
		return false, path, fmt.Errorf("write config %s: %w", path, err)
	}
	return true, path, nil
}
