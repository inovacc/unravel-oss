/*
Copyright (c) 2026 Security Research
*/

package kotlin

import (
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

var (
	versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)
)

func ScanDEX(dexResult *dex.ParseResult) *ScanResult {
	if dexResult == nil {
		return &ScanResult{}
	}

	result := &ScanResult{
		Features: make([]FeatureInfo, 0),
		Stats: KotlinStats{
			TotalClasses: countTotalClasses(dexResult),
		},
	}

	allStrings := collectStrings(dexResult)
	allClasses := collectClasses(dexResult)
	allMethods := collectMethods(dexResult)

	result.HasKotlin = detectKotlin(allStrings, allClasses)
	if !result.HasKotlin {
		return result
	}

	result.KotlinVersion = detectVersion(allStrings)
	result.Stats.KotlinClasses = countKotlinClasses(allClasses)
	result.Stats.CompanionObjects = countCompanionObjects(allClasses)
	result.Stats.InlineClasses = countInlineClasses(allClasses)

	if result.Stats.TotalClasses > 0 {
		result.Stats.KotlinPercent = float64(result.Stats.KotlinClasses) / float64(result.Stats.TotalClasses) * 100
	}

	result.DataClasses = detectDataClasses(allClasses, allMethods)
	result.Coroutines = detectCoroutines(allStrings, allClasses, allMethods)
	result.Serialization = detectSerialization(allClasses)
	result.Compose = detectCompose(allClasses)

	result.Features = buildFeatures(result)

	return result
}

func collectStrings(dexResult *dex.ParseResult) []string {
	var all []string
	for _, df := range dexResult.DexFiles {
		all = append(all, df.Strings...)
	}
	return all
}

func collectClasses(dexResult *dex.ParseResult) []string {
	var all []string
	for _, df := range dexResult.DexFiles {
		for _, c := range df.Classes {
			all = append(all, c.ClassName)
		}
	}
	return all
}

func collectMethods(dexResult *dex.ParseResult) []dex.MethodRef {
	var all []dex.MethodRef
	for _, df := range dexResult.DexFiles {
		all = append(all, df.Methods...)
	}
	return all
}

func countTotalClasses(dexResult *dex.ParseResult) int {
	count := 0
	for _, df := range dexResult.DexFiles {
		count += len(df.Classes)
	}
	return count
}

func detectKotlin(allStrings []string, classes []string) bool {
	for _, s := range allStrings {
		if strings.Contains(s, "kotlin.") || strings.Contains(s, "kotlin-stdlib") {
			return true
		}
	}

	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.HasPrefix(cn, "kotlin/") {
			return true
		}
	}

	return false
}

func detectVersion(allStrings []string) string {
	hasKotlin := false
	for _, s := range allStrings {
		if strings.Contains(s, "kotlin") {
			hasKotlin = true
		}
	}

	if hasKotlin {
		for _, s := range allStrings {
			if versionPattern.MatchString(s) {
				match := versionPattern.FindString(s)
				if match != "" && len(match) > 0 {
					parts := strings.Split(match, ".")
					if len(parts) >= 2 {
						return match
					}
				}
			}
		}
	}

	return ""
}

func countKotlinClasses(classes []string) int {
	count := 0
	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.HasPrefix(cn, "kotlin/") || strings.HasSuffix(c, "$Companion;") {
			count++
		}
	}
	return count
}

func countCompanionObjects(classes []string) int {
	count := 0
	for _, c := range classes {
		if strings.HasSuffix(c, "$Companion;") {
			count++
		}
	}
	return count
}

func countInlineClasses(classes []string) int {
	count := 0
	for _, c := range classes {
		if strings.Contains(c, "KMappedMarker") {
			count++
		}
	}
	return count
}

func detectDataClasses(classes []string, methods []dex.MethodRef) []DataClassInfo {
	classMethods := make(map[string][]string)

	for _, m := range methods {
		classMethods[m.ClassName] = append(classMethods[m.ClassName], m.Name)
	}

	var dataClasses []DataClassInfo
	for className, methodNames := range classMethods {
		if !isDataClass(methodNames) {
			continue
		}

		props := extractProperties(methodNames)
		dataClasses = append(dataClasses, DataClassInfo{
			ClassName:  className,
			Properties: props,
		})

		if len(dataClasses) >= 50 {
			break
		}
	}

	return dataClasses
}

func isDataClass(methods []string) bool {
	hasComponent := false
	hasCopy := false

	for _, m := range methods {
		if strings.HasPrefix(m, "component") {
			hasComponent = true
		}
		if m == "copy" || m == "copy$default" {
			hasCopy = true
		}
		if hasComponent && hasCopy {
			return true
		}
	}

	return false
}

func extractProperties(methods []string) []string {
	maxComponent := 0
	for _, m := range methods {
		if after, ok := strings.CutPrefix(m, "component"); ok {
			numStr := after
			if len(numStr) > 0 && numStr[0] >= '0' && numStr[0] <= '9' {
				num := int(numStr[0] - '0')
				if num > maxComponent {
					maxComponent = num
				}
			}
		}
	}

	if maxComponent == 0 {
		return nil
	}

	props := make([]string, maxComponent)
	for i := 0; i < maxComponent; i++ {
		props[i] = "property" + string(rune('0'+i+1))
	}
	return props
}

func detectCoroutines(allStrings []string, classes []string, methods []dex.MethodRef) *CoroutineInfo {
	info := &CoroutineInfo{
		Dispatchers: make([]string, 0),
		Evidence:    make([]string, 0),
	}

	dispatcherSet := make(map[string]bool)

	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.Contains(cn, "kotlinx/coroutines/") {
			info.HasCoroutines = true
			if len(info.Evidence) < 5 {
				info.Evidence = append(info.Evidence, cn)
			}
		}
		if strings.Contains(cn, "kotlinx/coroutines/flow/") {
			info.HasFlow = true
		}
		if strings.Contains(cn, "kotlinx/coroutines/channels/") {
			info.HasChannel = true
		}
		if strings.Contains(cn, "kotlin/coroutines/") {
			info.HasCoroutines = true
		}
	}

	for _, s := range allStrings {
		if strings.Contains(s, "Dispatchers.Main") {
			dispatcherSet["Main"] = true
		}
		if strings.Contains(s, "Dispatchers.IO") {
			dispatcherSet["IO"] = true
		}
		if strings.Contains(s, "Dispatchers.Default") {
			dispatcherSet["Default"] = true
		}
		if strings.Contains(s, "Dispatchers.Unconfined") {
			dispatcherSet["Unconfined"] = true
		}
	}

	for d := range dispatcherSet {
		info.Dispatchers = append(info.Dispatchers, d)
	}

	for _, m := range methods {
		if strings.Contains(m.Name, "$suspendImpl") {
			info.SuspendFuncs++
		}
	}

	for _, c := range classes {
		if strings.HasSuffix(c, "$ContinuationImpl;") {
			info.SuspendFuncs++
		}
	}

	if !info.HasCoroutines && !info.HasFlow && !info.HasChannel && len(info.Dispatchers) == 0 && info.SuspendFuncs == 0 {
		return nil
	}

	return info
}

func detectSerialization(classes []string) *SerializationInfo {
	info := &SerializationInfo{
		Evidence: make([]string, 0),
	}

	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.Contains(cn, "kotlinx/serialization/") {
			info.HasSerialization = true
			if len(info.Evidence) < 5 {
				info.Evidence = append(info.Evidence, cn)
			}

			if info.Format == "" {
				if strings.Contains(cn, "kotlinx/serialization/json/") {
					info.Format = "json"
				} else if strings.Contains(cn, "kotlinx/serialization/protobuf/") {
					info.Format = "protobuf"
				} else if strings.Contains(cn, "kotlinx/serialization/cbor/") {
					info.Format = "cbor"
				}
			}
		}
	}

	if !info.HasSerialization {
		return nil
	}

	return info
}

func detectCompose(classes []string) *ComposeInfo {
	info := &ComposeInfo{
		Evidence: make([]string, 0),
	}

	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.Contains(cn, "androidx/compose/") {
			info.HasCompose = true
			info.Composables++
			if len(info.Evidence) < 5 {
				info.Evidence = append(info.Evidence, cn)
			}
		}
	}

	if !info.HasCompose {
		return nil
	}

	return info
}

func buildFeatures(result *ScanResult) []FeatureInfo {
	features := []FeatureInfo{
		{
			Name:     "Coroutines",
			Detected: result.Coroutines != nil && result.Coroutines.HasCoroutines,
			Evidence: joinEvidence(result.Coroutines),
		},
		{
			Name:     "Flow",
			Detected: result.Coroutines != nil && result.Coroutines.HasFlow,
			Evidence: "kotlinx.coroutines.flow",
		},
		{
			Name:     "Jetpack Compose",
			Detected: result.Compose != nil && result.Compose.HasCompose,
			Evidence: joinComposeEvidence(result.Compose),
		},
		{
			Name:     "Kotlinx Serialization",
			Detected: result.Serialization != nil && result.Serialization.HasSerialization,
			Evidence: joinSerializationEvidence(result.Serialization),
		},
		{
			Name:     "Data Classes",
			Detected: len(result.DataClasses) > 0,
			Evidence: joinDataClassEvidence(result.DataClasses),
		},
		{
			Name:     "Companion Objects",
			Detected: result.Stats.CompanionObjects > 0,
			Evidence: "",
		},
		{
			Name:     "Inline Classes",
			Detected: result.Stats.InlineClasses > 0,
			Evidence: "",
		},
	}

	return features
}

func joinEvidence(info *CoroutineInfo) string {
	if info == nil || len(info.Evidence) == 0 {
		return ""
	}
	return info.Evidence[0]
}

func joinComposeEvidence(info *ComposeInfo) string {
	if info == nil || len(info.Evidence) == 0 {
		return ""
	}
	return info.Evidence[0]
}

func joinSerializationEvidence(info *SerializationInfo) string {
	if info == nil || len(info.Evidence) == 0 {
		return ""
	}
	return info.Evidence[0]
}

func joinDataClassEvidence(classes []DataClassInfo) string {
	if len(classes) == 0 {
		return ""
	}
	return classes[0].ClassName
}
