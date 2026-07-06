package dotnet

import (
	"os"
	"path/filepath"
	"strings"
)

// ServiceSignal describes why a .NET app was classified as a Windows service/daemon.
type ServiceSignal struct {
	HasASPNETCore   bool `json:"has_aspnet_core"`
	HasGenericHost  bool `json:"has_generic_host"`
	HasWorkerSuffix bool `json:"has_worker_suffix"`
	HasExe          bool `json:"has_exe"`
}

// ServiceResult holds the Windows service detection outcome.
type ServiceResult struct {
	IsService bool          `json:"is_service"`
	Signals   ServiceSignal `json:"signals"`
}

// DetectWindowsService checks whether a .NET application directory looks like
// a Windows service or long-running daemon. The heuristics are:
//
//  1. runtimeconfig.json includes the Microsoft.AspNetCore.App framework
//  2. deps.json references Microsoft.Extensions.Hosting (Generic Host)
//  3. the primary executable name ends with "Service" or "Worker"
//
// Any of these combined with the presence of a sibling .exe is considered a
// positive signal. The function returns a structured result so callers can
// inspect individual signals.
func DetectWindowsService(dir string) ServiceResult {
	result := ServiceResult{}

	// Check for a sibling .exe file and look for naming conventions.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return result
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".exe") {
			result.Signals.HasExe = true
			base := strings.TrimSuffix(lower, ".exe")
			if strings.HasSuffix(base, "service") || strings.HasSuffix(base, "worker") {
				result.Signals.HasWorkerSuffix = true
			}
		}
	}

	// Parse runtimeconfig.json files for ASP.NET Core framework.
	for _, rcPath := range FindRuntimeConfig(dir) {
		rc, err := ParseRuntimeConfig(rcPath)
		if err != nil {
			continue
		}
		if rc.IsASPNET {
			result.Signals.HasASPNETCore = true
		}
	}

	// Parse deps.json files for Generic Host / Hosting references.
	for _, depsPath := range FindDepsJSON(dir) {
		deps, err := ParseDeps(depsPath)
		if err != nil {
			continue
		}
		for _, fw := range deps.Frameworks {
			if fw == "Generic Host" {
				result.Signals.HasGenericHost = true
			}
		}
		// Also scan package libraries directly for hosting packages.
		for _, lib := range deps.PackageLibs {
			lower := strings.ToLower(lib.Name)
			if strings.HasPrefix(lower, "microsoft.extensions.hosting") {
				result.Signals.HasGenericHost = true
			}
		}
	}

	// A .NET app is likely a Windows service if it has an exe and at least one
	// hosting/framework signal, OR if the binary name explicitly says so.
	result.IsService = result.Signals.HasWorkerSuffix ||
		(result.Signals.HasExe && (result.Signals.HasASPNETCore || result.Signals.HasGenericHost))

	return result
}

// IsWindowsService is a convenience wrapper that returns true if the directory
// appears to contain a .NET Windows service or background worker.
func IsWindowsService(dir string) bool {
	return DetectWindowsService(dir).IsService
}

// FindExe returns the first .exe file found in the given directory, or empty string.
func FindExe(dir string) string {
	matches, err := filepath.Glob(filepath.Join(dir, "*.exe"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}
