/*
Copyright (c) 2026 Security Research
*/

// Package detect provides WinUI 3 / WindowsAppSDK detection signals from
// already-parsed inputs (deps.json package refs, PE import DLL lists). The
// detectors are intentionally pure functions over structured input — no
// filesystem access — so they compose freely with upstream parsers.
package detect

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// PackageRef is a minimal local view of a deps.json package reference.
// Children-own-their-types pattern (Phase 3 lesson) — we avoid importing
// pkg/dotnet's full DepsResult to keep this package decoupled and to side-
// step potential import-cycle pressure once the dissect analyzer wires
// both sides together.
type PackageRef struct {
	Name    string
	Version string
}

// DetectFromDeps inspects parsed deps.json package references and returns
// FrameworkInfo entries for any WinUI 3 / WindowsAppSDK / WindowsAppRuntime
// references found. Pass the already-parsed package slice; this function
// does NOT touch the filesystem.
//
// Confidence rules (D-05, RESEARCH.md):
//   - Microsoft.WinUI -> "WinUI 3", confidence "high"
//   - Microsoft.WindowsAppSDK -> "WindowsAppSDK", confidence "high"
//   - Microsoft.WindowsAppRuntime -> "WindowsAppRuntime", confidence "medium"
//
// The matcher is case-insensitive on the prefix and preserves original
// package casing in Evidence for greppability.
func DetectFromDeps(packages []PackageRef) []winui.FrameworkInfo {
	if len(packages) == 0 {
		return nil
	}
	var out []winui.FrameworkInfo
	seen := make(map[string]struct{})
	for _, p := range packages {
		if p.Name == "" {
			continue
		}
		lower := strings.ToLower(p.Name)
		switch {
		case strings.HasPrefix(lower, strings.ToLower(PkgPrefixWinUI)):
			key := "WinUI 3|" + p.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, winui.FrameworkInfo{
				Name:       "WinUI 3",
				Version:    p.Version,
				Confidence: "high",
				Evidence:   []string{evidence(p)},
				Source:     "dotnet-deps",
			})
		case strings.HasPrefix(lower, strings.ToLower(PkgPrefixWindowsAppSDK)):
			key := "WindowsAppSDK|" + p.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, winui.FrameworkInfo{
				Name:       "WindowsAppSDK",
				Version:    p.Version,
				Confidence: "high",
				Evidence:   []string{evidence(p)},
				Source:     "dotnet-deps",
			})
		case strings.HasPrefix(lower, strings.ToLower(PkgPrefixWindowsAppRT)):
			key := "WindowsAppRuntime|" + p.Name
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, winui.FrameworkInfo{
				Name:       "WindowsAppRuntime",
				Version:    p.Version,
				Confidence: "medium",
				Evidence:   []string{evidence(p)},
				Source:     "dotnet-deps",
			})
		}
	}
	return out
}

// DetectFromImports inspects PE import DLL names and returns Signal entries
// for each WinUI/UWP-XAML host DLL found. Case-insensitive (strings.EqualFold).
//
// Confidence rules:
//   - Microsoft.UI.Xaml.dll -> "high" (WinUI 3 / WinUI 2 — caller demotes
//     to "medium" when no deps.json corroboration is present).
//   - Windows.UI.Xaml.dll  -> "medium" (UWP / WinUI 2 ambiguity per
//     RESEARCH.md disambiguation table).
func DetectFromImports(imports []string) []winui.Signal {
	if len(imports) == 0 {
		return nil
	}
	var out []winui.Signal
	for _, dll := range imports {
		switch {
		case strings.EqualFold(dll, DLLMUX):
			out = append(out, winui.Signal{
				Kind:       "pe-import",
				Confidence: "high",
				Detail:     DLLMUX,
			})
		case strings.EqualFold(dll, DLLWUX):
			out = append(out, winui.Signal{
				Kind:       "pe-import",
				Confidence: "medium",
				Detail:     DLLWUX,
			})
		}
	}
	return out
}

// evidence formats a stable, greppable evidence string from a PackageRef.
// Format: "<Name> <Version>" (trailing space stripped when version empty).
func evidence(p PackageRef) string {
	if p.Version == "" {
		return p.Name
	}
	return p.Name + " " + p.Version
}
