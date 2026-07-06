package npm

import (
	"encoding/json"
	"fmt"
	"os"
)

// PackageJSON represents a parsed package.json file.
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	Main            string            `json:"main"`
	Type            string            `json:"type"` // "module" or "commonjs"
	Bin             any               `json:"bin"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	License         any               `json:"license"`
	Homepage        string            `json:"homepage"`
	Repository      any               `json:"repository"`
	Private         bool              `json:"private"`
}

// ParsePackageJSON reads and parses a package.json file.
func ParsePackageJSON(path string) (*PackageJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	return &pkg, nil
}

// BinEntries returns the bin entries as a map.
// Handles both string format ("bin": "./cli.js") and map format ("bin": {"cmd": "./cli.js"}).
func (p *PackageJSON) BinEntries() map[string]string {
	if p.Bin == nil {
		return nil
	}

	switch v := p.Bin.(type) {
	case string:
		// Single binary: use package name as key
		return map[string]string{p.Name: v}
	case map[string]any:
		result := make(map[string]string, len(v))
		for k, val := range v {
			if s, ok := val.(string); ok {
				result[k] = s
			}
		}
		return result
	default:
		return nil
	}
}
