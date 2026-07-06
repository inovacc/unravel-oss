/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// tauriConfig represents the relevant parts of tauri.conf.json.
type tauriConfig struct {
	Build struct {
		FrontendDist string `json:"frontendDist"`
		DevURL       string `json:"devUrl"`
	} `json:"build"`
}

// extractFromTauri discovers CSS files from a Tauri application directory.
// It reads tauri.conf.json to locate the frontend dist path, with fallbacks.
func extractFromTauri(appDir string, opts Options) ([]Stylesheet, []string, error) {
	// Try to find tauri.conf.json
	confPaths := []string{
		filepath.Join(appDir, "src-tauri", "tauri.conf.json"),
		filepath.Join(appDir, "tauri.conf.json"),
	}

	for _, confPath := range confPaths {
		data, err := os.ReadFile(confPath)
		if err != nil {
			continue
		}
		var conf tauriConfig
		if err := json.Unmarshal(data, &conf); err != nil {
			continue
		}
		if conf.Build.FrontendDist != "" {
			distPath := conf.Build.FrontendDist
			// Resolve relative path against config directory
			if !filepath.IsAbs(distPath) {
				distPath = filepath.Join(filepath.Dir(confPath), distPath)
			}
			distPath = filepath.Clean(distPath)
			if info, err := os.Stat(distPath); err == nil && info.IsDir() {
				return extractFromDir(distPath, opts)
			}
		}
	}

	// Fallback: check common dist directories
	fallbacks := []string{
		filepath.Join(appDir, "dist"),
		filepath.Join(appDir, "build"),
		filepath.Join(appDir, "out"),
		filepath.Join(appDir, "src-tauri", "target"),
	}

	for _, fb := range fallbacks {
		if info, err := os.Stat(fb); err == nil && info.IsDir() {
			return extractFromDir(fb, opts)
		}
	}

	// Last resort: scan the entire app directory
	return extractFromDir(appDir, opts)
}
