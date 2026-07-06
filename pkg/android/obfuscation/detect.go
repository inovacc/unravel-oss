/*
Copyright (c) 2026 Security Research
*/
package obfuscation

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/garble"
)

// Analyze inspects a DEX parse result and returns an obfuscation analysis.
func Analyze(dexResult *dex.ParseResult) *Result {
	if dexResult == nil {
		return &Result{Type: ObfNone, Label: "none"}
	}

	var allClasses []dex.ClassDef
	var allMethods []dex.MethodRef
	var allStrings []string

	for _, df := range dexResult.DexFiles {
		allClasses = append(allClasses, df.Classes...)
		allMethods = append(allMethods, df.Methods...)
		allStrings = append(allStrings, df.Strings...)
	}

	indicators := analyzeIndicators(allClasses, allMethods, allStrings)

	var confidence float64
	for _, ind := range indicators {
		if ind.Detected {
			confidence += ind.Weight
		}
	}
	if confidence > 100 {
		confidence = 100
	}

	obfType := determineType(indicators, allStrings, allClasses)
	shortClassPct, shortMethodPct := computeShortPercentages(allClasses, allMethods)
	avgNameLen := computeAvgClassNameLen(allClasses)
	avgDepth := computeAvgPkgDepth(allClasses)

	return &Result{
		Type:            obfType,
		Confidence:      confidence,
		Label:           confidenceLabel(confidence),
		Indicators:      indicators,
		ShortClassPct:   shortClassPct,
		ShortMethodPct:  shortMethodPct,
		AvgClassNameLen: avgNameLen,
		AvgPkgDepth:     avgDepth,
	}
}

func analyzeIndicators(classes []dex.ClassDef, methods []dex.MethodRef, strs []string) []Indicator {
	return []Indicator{
		checkShortClassNames(classes),
		checkShortMethodNames(methods),
		checkR8Markers(classes),
		checkPackageDepth(classes),
		checkClassNameEntropy(classes),
		checkSequentialNaming(classes),
		checkDexGuardMarkers(strs, classes),
	}
}

func checkShortClassNames(classes []dex.ClassDef) Indicator {
	ind := Indicator{
		Name:        "short_class_names",
		Description: "High percentage of single/double-letter class names",
		Weight:      25,
	}
	if len(classes) == 0 {
		return ind
	}

	var shortCount int
	for _, c := range classes {
		simple := simpleName(c.ClassName)
		if len(simple) <= 2 && isAllLower(simple) {
			shortCount++
		}
	}

	pct := float64(shortCount) / float64(len(classes)) * 100
	if pct > 30 {
		ind.Detected = true
		ind.Details = fmt.Sprintf("%.1f%% of classes have short names (%d/%d)", pct, shortCount, len(classes))
	}

	return ind
}

func checkShortMethodNames(methods []dex.MethodRef) Indicator {
	ind := Indicator{
		Name:        "short_method_names",
		Description: "High percentage of single-letter method names",
		Weight:      20,
	}
	if len(methods) == 0 {
		return ind
	}

	var shortCount int
	for _, m := range methods {
		if len(m.Name) == 1 && isAllLower(m.Name) {
			shortCount++
		}
	}

	pct := float64(shortCount) / float64(len(methods)) * 100
	if pct > 20 {
		ind.Detected = true
		ind.Details = fmt.Sprintf("%.1f%% of methods have single-letter names (%d/%d)", pct, shortCount, len(methods))
	}

	return ind
}

func checkR8Markers(classes []dex.ClassDef) Indicator {
	ind := Indicator{
		Name:        "r8_markers",
		Description: "R8 synthetic class markers ($$) detected",
		Weight:      15,
	}

	var count int
	for _, c := range classes {
		if strings.Contains(c.ClassName, "$$") {
			count++
		}
	}

	if count > 0 {
		ind.Detected = true
		ind.Details = fmt.Sprintf("found %d classes with $$ marker", count)
	}

	return ind
}

func checkPackageDepth(classes []dex.ClassDef) Indicator {
	ind := Indicator{
		Name:        "package_depth",
		Description: "Unusually flat package hierarchy",
		Weight:      10,
	}
	if len(classes) == 0 {
		return ind
	}

	avg := computeAvgPkgDepth(classes)
	if avg < 2.0 {
		ind.Detected = true
		ind.Details = fmt.Sprintf("average package depth %.2f (threshold: 2.0)", avg)
	}

	return ind
}

func checkClassNameEntropy(classes []dex.ClassDef) Indicator {
	ind := Indicator{
		Name:        "class_name_entropy",
		Description: "Low Shannon entropy in class names",
		Weight:      10,
	}
	if len(classes) == 0 {
		return ind
	}

	var totalEntropy float64
	var count int
	for _, c := range classes {
		simple := simpleName(c.ClassName)
		if simple == "" {
			continue
		}
		totalEntropy += garble.ShannonEntropy(simple)
		count++
	}

	if count == 0 {
		return ind
	}

	avg := totalEntropy / float64(count)
	if avg < 3.0 {
		ind.Detected = true
		ind.Details = fmt.Sprintf("average class name entropy %.2f (threshold: 3.0)", avg)
	}

	return ind
}

func checkSequentialNaming(classes []dex.ClassDef) Indicator {
	ind := Indicator{
		Name:        "sequential_naming",
		Description: "Sequential single-letter class naming pattern (a.a, a.b, a.c)",
		Weight:      10,
	}

	var seqCount int
	for _, c := range classes {
		parts := strings.Split(strings.TrimPrefix(c.ClassName, "L"), "/")
		allSingle := true
		for _, p := range parts {
			p = strings.TrimSuffix(p, ";")
			if p == "" {
				continue
			}
			if len(p) != 1 || !isAllLower(p) {
				allSingle = false
				break
			}
		}
		if allSingle && len(parts) >= 2 {
			seqCount++
		}
	}

	if seqCount > 5 {
		ind.Detected = true
		ind.Details = fmt.Sprintf("found %d classes with sequential single-letter naming", seqCount)
	}

	return ind
}

func checkDexGuardMarkers(strs []string, classes []dex.ClassDef) Indicator {
	ind := Indicator{
		Name:        "dexguard_markers",
		Description: "DexGuard-specific patterns detected",
		Weight:      10,
	}

	for _, s := range strs {
		if strings.Contains(strings.ToLower(s), "dexguard") {
			ind.Detected = true
			ind.Details = "found 'dexguard' string reference"
			return ind
		}
	}

	// Check for OooO pattern typical of DexGuard
	for _, c := range classes {
		simple := simpleName(c.ClassName)
		if matchesDexGuardPattern(simple) {
			ind.Detected = true
			ind.Details = fmt.Sprintf("found DexGuard-style class name: %s", simple)
			return ind
		}
	}

	return ind
}

func determineType(indicators []Indicator, _ []string, _ []dex.ClassDef) ObfuscationType {
	indicatorMap := make(map[string]bool, len(indicators))
	for _, ind := range indicators {
		indicatorMap[ind.Name] = ind.Detected
	}

	if indicatorMap["dexguard_markers"] {
		return ObfDexGuard
	}
	if indicatorMap["r8_markers"] {
		return ObfR8
	}

	var confidence float64
	for _, ind := range indicators {
		if ind.Detected {
			confidence += ind.Weight
		}
	}

	if confidence > 30 {
		return ObfUnknown
	}

	return ObfNone
}

func confidenceLabel(confidence float64) string {
	switch {
	case confidence <= 20:
		return "none"
	case confidence <= 40:
		return "low"
	case confidence <= 60:
		return "medium"
	case confidence <= 80:
		return "high"
	default:
		return "very high"
	}
}

// simpleName returns the last component of a class name, stripping L prefix and ; suffix.
func simpleName(className string) string {
	name := strings.TrimPrefix(className, "L")
	name = strings.TrimSuffix(name, ";")

	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		name = name[idx+1:]
	}

	return name
}

func isAllLower(s string) bool {
	for _, r := range s {
		if !unicode.IsLower(r) {
			return false
		}
	}
	return len(s) > 0
}

func computeShortPercentages(classes []dex.ClassDef, methods []dex.MethodRef) (classPct, methodPct float64) {
	if len(classes) > 0 {
		var shortClasses int
		for _, c := range classes {
			simple := simpleName(c.ClassName)
			if len(simple) <= 2 && isAllLower(simple) {
				shortClasses++
			}
		}
		classPct = float64(shortClasses) / float64(len(classes)) * 100
	}

	if len(methods) > 0 {
		var shortMethods int
		for _, m := range methods {
			if len(m.Name) == 1 && isAllLower(m.Name) {
				shortMethods++
			}
		}
		methodPct = float64(shortMethods) / float64(len(methods)) * 100
	}

	return classPct, methodPct
}

func computeAvgClassNameLen(classes []dex.ClassDef) float64 {
	if len(classes) == 0 {
		return 0
	}

	var total int
	for _, c := range classes {
		total += len(simpleName(c.ClassName))
	}

	return float64(total) / float64(len(classes))
}

func computeAvgPkgDepth(classes []dex.ClassDef) float64 {
	if len(classes) == 0 {
		return 0
	}

	var totalDepth int
	for _, c := range classes {
		name := strings.TrimPrefix(c.ClassName, "L")
		name = strings.TrimSuffix(name, ";")
		totalDepth += strings.Count(name, "/")
	}

	return float64(totalDepth) / float64(len(classes))
}

// matchesDexGuardPattern detects names like OooO, OoOo, etc.
func matchesDexGuardPattern(name string) bool {
	if len(name) < 4 {
		return false
	}
	for _, r := range name {
		if r != 'O' && r != 'o' {
			return false
		}
	}
	return true
}
