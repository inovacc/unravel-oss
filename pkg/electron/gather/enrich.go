/*
Copyright (c) 2026 Security Research
*/
package gather

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/asar"
)

const maxBinarySize = 50 * 1024 * 1024 // 50MB

var (
	reChromiumElectron = regexp.MustCompile(`Chrome/([\d.]+)\s+Electron/([\d.]+)`)
	reNodeVersion      = regexp.MustCompile(`(?:node/v|Node\.js v)([\d.]+)`)
	reTauriVersion     = regexp.MustCompile(`tauri@([\d.]+)`)
)

// frameworkMap maps dependency names to framework display names.
var frameworkMap = map[string]string{
	"react":         "React",
	"react-dom":     "React",
	"vue":           "Vue",
	"@angular/core": "Angular",
	"svelte":        "Svelte",
	"next":          "Next.js",
	"nuxt":          "Nuxt",
	"solid-js":      "Solid",
}

// enrichEntry populates runtime metadata on an AppEntry by inspecting
// the application's binary, ASAR archive, and package.json files.
func enrichEntry(entry *AppEntry) {
	switch entry.Type {
	case "electron":
		enrichElectron(entry)
	case "tauri":
		enrichTauri(entry)
	}
}

func enrichElectron(entry *AppEntry) {
	// 1. Scan main binary for version strings
	if bin := findMainBinary(entry.Path); bin != "" {
		if data, err := readFileCapped(bin, maxBinarySize); err == nil {
			if m := reChromiumElectron.Find(data); m != nil {
				subs := reChromiumElectron.FindSubmatch(data)
				entry.ChromiumVersion = string(subs[1])
				entry.ElectronVersion = string(subs[2])
			}
			if m := reNodeVersion.FindSubmatch(data); m != nil {
				entry.NodeVersion = string(m[1])
			}
		}
	}

	// 2. Try reading package.json from ASAR
	asarPath := filepath.Join(entry.Path, "resources", "app.asar")
	if deps := readPackageJSONFromASAR(asarPath); deps != nil {
		entry.Frameworks = detectFrameworks(deps)
		return
	}

	// 3. Fallback: read resources/app/package.json directly
	pkgPath := filepath.Join(entry.Path, "resources", "app", "package.json")
	if deps := readPackageJSONDeps(pkgPath); deps != nil {
		entry.Frameworks = detectFrameworks(deps)
	}
}

func enrichTauri(entry *AppEntry) {
	// 1. Binary regex for tauri version
	if bin := findMainBinary(entry.Path); bin != "" {
		if data, err := readFileCapped(bin, maxBinarySize); err == nil {
			if m := reTauriVersion.FindSubmatch(data); m != nil {
				entry.TauriVersion = string(m[1])
			}
		}
	}

	// 2. Read tauri.conf.json for version/productName
	for _, rel := range []string{"tauri.conf.json", "src-tauri/tauri.conf.json"} {
		confPath := filepath.Join(entry.Path, rel)
		if data, err := os.ReadFile(confPath); err == nil {
			var conf struct {
				Package struct {
					Version     string `json:"version"`
					ProductName string `json:"productName"`
				} `json:"package"`
			}
			if json.Unmarshal(data, &conf) == nil && conf.Package.Version != "" {
				if entry.Version == "" {
					entry.Version = conf.Package.Version
				}
			}
			break
		}
	}

	// 3. Read package.json for framework deps
	pkgPath := filepath.Join(entry.Path, "package.json")
	if deps := readPackageJSONDeps(pkgPath); deps != nil {
		entry.Frameworks = detectFrameworks(deps)
	}
}

// findMainBinary locates the largest executable/binary in the app directory (depth 1).
func findMainBinary(appPath string) string {
	entries, err := os.ReadDir(appPath)
	if err != nil {
		return ""
	}

	var best string
	var bestSize int64

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size > bestSize {
			name := e.Name()
			// Skip non-binary files
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".md") ||
				strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".yaml") ||
				strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".xml") ||
				strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".css") ||
				strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".png") ||
				strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".ico") ||
				strings.HasSuffix(lower, ".svg") {
				continue
			}
			best = filepath.Join(appPath, name)
			bestSize = size
		}
	}

	return best
}

// readFileCapped reads up to maxSize bytes from a file.
func readFileCapped(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := min(info.Size(), maxSize)

	buf := make([]byte, size)
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// readPackageJSONFromASAR extracts and parses package.json from an ASAR archive,
// returning the combined dependencies map.
func readPackageJSONFromASAR(asarPath string) map[string]any {
	f, header, _, dataOffset, err := asar.OpenAndParse(asarPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	files := asar.CollectFiles(header.Files, "")
	for _, ef := range files {
		if ef.IsDir || ef.Path != "package.json" {
			continue
		}
		content, err := asar.ReadFileContent(f, dataOffset, ef.Offset, ef.Size)
		if err != nil {
			return nil
		}
		return parseDepsFromJSON(content)
	}

	return nil
}

// readPackageJSONDeps reads and parses a package.json file from disk.
func readPackageJSONDeps(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseDepsFromJSON(data)
}

// parseDepsFromJSON extracts dependencies + devDependencies from package.json content.
func parseDepsFromJSON(data []byte) map[string]any {
	var pkg struct {
		Dependencies    map[string]any `json:"dependencies"`
		DevDependencies map[string]any `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	merged := make(map[string]any)
	maps.Copy(merged, pkg.Dependencies)
	maps.Copy(merged, pkg.DevDependencies)

	if len(merged) == 0 {
		return nil
	}

	return merged
}

// detectFrameworks returns sorted framework names found in the dependencies map.
func detectFrameworks(deps map[string]any) []string {
	seen := make(map[string]bool)
	for depName := range deps {
		if fw, ok := frameworkMap[depName]; ok {
			seen[fw] = true
		}
	}

	if len(seen) == 0 {
		return nil
	}

	result := make([]string, 0, len(seen))
	for fw := range seen {
		result = append(result, fw)
	}
	sort.Strings(result)

	return result
}
