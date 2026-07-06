package dotnet

import (
	"os"
	"path/filepath"
	"strings"
)

// dotnetMarkers are file patterns that indicate a .NET application directory.
var dotnetMarkers = []string{
	"*.deps.json",
	"*.runtimeconfig.json",
	"*.dll",
	"coreclr.dll",
	"libcoreclr.so",
	"libcoreclr.dylib",
	"hostfxr.dll",
	"libhostfxr.so",
	"libhostfxr.dylib",
}

// IsDotNetApp checks if a directory contains .NET self-contained app markers.
// It looks for deps.json, runtimeconfig.json, and CoreCLR runtime files.
func IsDotNetApp(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	hasDeps := false
	hasRuntime := false

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)

		if strings.HasSuffix(lower, ".deps.json") {
			hasDeps = true
		}
		if strings.HasSuffix(lower, ".runtimeconfig.json") {
			hasRuntime = true
		}
		// CoreCLR runtime presence is a strong signal.
		switch lower {
		case "coreclr.dll", "libcoreclr.so", "libcoreclr.dylib",
			"hostfxr.dll", "libhostfxr.so", "libhostfxr.dylib":
			hasRuntime = true
		}
	}

	return hasDeps || hasRuntime
}

// FindDepsJSON finds all .deps.json files in a directory (non-recursive).
func FindDepsJSON(dir string) []string {
	return findByPattern(dir, ".deps.json")
}

// FindRuntimeConfig finds all .runtimeconfig.json files in a directory (non-recursive).
func FindRuntimeConfig(dir string) []string {
	return findByPattern(dir, ".runtimeconfig.json")
}

// findByPattern returns files in dir whose names end with the given suffix.
func findByPattern(dir, suffix string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "*"+suffix))
	if err != nil {
		return nil
	}
	return matches
}
