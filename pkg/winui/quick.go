/*
Copyright (c) 2026 Security Research
*/

package winui

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dotnet"
)

// Detector signature constants — duplicated locally to avoid an import
// cycle with pkg/winui/detect (which imports winui for FrameworkInfo).
// Keep these in sync with pkg/winui/detect/signatures.go.
const (
	dllMUX                 = "Microsoft.UI.Xaml.dll"
	dllWUX                 = "Windows.UI.Xaml.dll"
	pkgPrefixWinUI         = "Microsoft.WinUI"
	pkgPrefixWindowsAppSDK = "Microsoft.WindowsAppSDK"
	pkgPrefixWindowsAppRT  = "Microsoft.WindowsAppRuntime"
)

// quickFallback runs a lightweight detection over already-parsed deps and
// PE imports without touching the filesystem. Used by AnalyzeQuick when
// the orchestrator sub-package has not registered an implementation
// (avoids forcing callers to blank-import the orchestrator just to use
// the cheap path).
func quickFallback(deps *dotnet.DepsResult, imports []string) *Result {
	res := &Result{}
	if deps != nil {
		res.Frameworks = append(res.Frameworks, DetectFromDepsLocal(deps)...)
	}
	if len(imports) > 0 {
		res.Signals = append(res.Signals, DetectFromImportsLocal(imports)...)
	}
	for _, fi := range res.Frameworks {
		if fi.Name == "WinUI 3" {
			res.IsWinUI = true
			break
		}
	}
	return res
}

// DetectFromDepsLocal mirrors pkg/winui/detect.DetectFromDeps. Exposed so
// the orchestrator sub-package can reuse it without re-implementing the
// recognition rules.
func DetectFromDepsLocal(deps *dotnet.DepsResult) []FrameworkInfo {
	if deps == nil {
		return nil
	}
	all := make([]dotnet.LibrarySummary, 0, len(deps.PackageLibs)+len(deps.ProjectLibs))
	all = append(all, deps.PackageLibs...)
	all = append(all, deps.ProjectLibs...)
	var out []FrameworkInfo
	seen := map[string]struct{}{}
	for _, lib := range all {
		if lib.Name == "" {
			continue
		}
		lower := strings.ToLower(lib.Name)
		switch {
		case strings.HasPrefix(lower, strings.ToLower(pkgPrefixWinUI)):
			key := "WinUI 3|" + lib.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, FrameworkInfo{
				Name:       "WinUI 3",
				Version:    lib.Version,
				Confidence: "high",
				Evidence:   []string{evidenceLocal(lib.Name, lib.Version)},
				Source:     "dotnet-deps",
			})
		case strings.HasPrefix(lower, strings.ToLower(pkgPrefixWindowsAppSDK)):
			key := "WindowsAppSDK|" + lib.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, FrameworkInfo{
				Name:       "WindowsAppSDK",
				Version:    lib.Version,
				Confidence: "high",
				Evidence:   []string{evidenceLocal(lib.Name, lib.Version)},
				Source:     "dotnet-deps",
			})
		case strings.HasPrefix(lower, strings.ToLower(pkgPrefixWindowsAppRT)):
			key := "WindowsAppRuntime|" + lib.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, FrameworkInfo{
				Name:       "WindowsAppRuntime",
				Version:    lib.Version,
				Confidence: "medium",
				Evidence:   []string{evidenceLocal(lib.Name, lib.Version)},
				Source:     "dotnet-deps",
			})
		}
	}
	return out
}

// DetectFromImportsLocal mirrors pkg/winui/detect.DetectFromImports.
func DetectFromImportsLocal(imports []string) []Signal {
	if len(imports) == 0 {
		return nil
	}
	var out []Signal
	for _, dll := range imports {
		switch {
		case strings.EqualFold(dll, dllMUX):
			out = append(out, Signal{Kind: "pe-import", Confidence: "high", Detail: dllMUX})
		case strings.EqualFold(dll, dllWUX):
			out = append(out, Signal{Kind: "pe-import", Confidence: "medium", Detail: dllWUX})
		}
	}
	return out
}

func evidenceLocal(name, version string) string {
	if version == "" {
		return name
	}
	return name + " " + version
}
