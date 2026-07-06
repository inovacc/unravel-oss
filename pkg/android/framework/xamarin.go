/*
Copyright (c) 2026 Security Research
*/

package framework

import (
	"strings"
)

var xamarinNativeLibs = []string{
	"libmonodroid.so",
	"libmonosgen-2.0.so",
	"libxamarin-app.so",
	"libxa-internal-api.so",
}

func detectXamarin(entries []zipEntry, classes []string) *XamarinInfo {
	var nativeLibs []string
	var abis []string
	var assemblies []string
	hasAOT := false

	for _, e := range entries {
		base := libBaseName(e.Name)

		for _, lib := range xamarinNativeLibs {
			if base == lib {
				nativeLibs = append(nativeLibs, e.Name)
				if abi := extractABI(e.Name); abi != "" {
					abis = append(abis, abi)
				}
			}
		}

		// Check for .NET assemblies in assemblies/ directory
		if strings.HasPrefix(e.Name, "assemblies/") && strings.HasSuffix(e.Name, ".dll") {
			assemblies = append(assemblies, libBaseName(e.Name))
		}

		// AOT compiled assemblies appear as .dll.so
		if strings.HasSuffix(e.Name, ".dll.so") {
			hasAOT = true
		}
	}

	// Check DEX classes
	hasDEXMarker := false
	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.HasPrefix(cn, "mono/android/") || strings.HasPrefix(cn, "md/mono/android/") {
			hasDEXMarker = true
			break
		}
	}

	if len(nativeLibs) == 0 && len(assemblies) == 0 && !hasDEXMarker {
		return nil
	}

	info := &XamarinInfo{
		HasAOT:        hasAOT,
		Assemblies:    assemblies,
		AssemblyCount: len(assemblies),
		NativeLibs:    nativeLibs,
		ABIs:          uniqueStrings(abis),
	}

	// Detect Xamarin.Forms vs MAUI
	for _, asm := range assemblies {
		lower := strings.ToLower(asm)
		if strings.Contains(lower, "xamarin.forms") {
			info.IsXamarinForms = true
		}
		if strings.Contains(lower, "microsoft.maui") {
			info.IsMAUI = true
		}
	}

	return info
}
