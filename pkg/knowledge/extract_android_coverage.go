/*
Copyright (c) 2026 Security Research
*/

// extract_android.go: P37 Plan 37-02 — wire pkg/android/* extractor outputs
// into KnowledgeResult.Android additive coverage fields.
//
// DEVIATION FROM PLAN 37-02: the plan specified
// `func extractAndroid(dr *dissect.DissectResult, kr *KnowledgeResult)` but
// `extractAndroid(r) *AndroidKnowledge` already exists in extract.go and
// produces the legacy AndroidKnowledge. This file adds a new mutator
// `extractAndroidCoverage(dr, kr)` that runs AFTER the existing
// extractAndroid populates kr.Android, and wires the additional D-37
// coverage dimensions (resources, telemetry list, kotlin features, network
// endpoints, plus DEX class/method ref slices). The existing extractAndroid
// is preserved unchanged.
//
// Empty input fields stay empty (D-35-NO-FALLBACK-INFERENCE).
// Single slog.Warn per platform when AndroidInfo source is nil.
package knowledge

import (
	"log/slog"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// extractAndroidCoverage adds the P37 D-37 additive coverage dimensions to
// kr.Android. Must run AFTER the legacy extractAndroid populates the base
// AndroidKnowledge. No-op when kr.Platform != "android" or kr.Android == nil.
func extractAndroidCoverage(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr == nil || kr == nil {
		return
	}
	if kr.Platform != "android" {
		return
	}
	if kr.Android == nil {
		// Legacy extractAndroid returned nil (no manifest/dex/native data).
		// Nothing to enrich; depth audit will surface absence as ratio 0/0
		// across the board (RatioOK true, no defect).
		slog.Warn("knowledge: android dispatch hit but kr.Android nil",
			"source", dr.Path)
		return
	}

	// 1. DEX class/method refs (path-index only per D-37-SOURCE-FILES-PATH-INDEX).
	extractAndroidDexRefs(dr, kr)

	// 2. Resources path-index.
	extractAndroidResources(dr, kr)

	// 3. Telemetry SDKs.
	extractAndroidTelemetry(dr, kr)

	// 4. Kotlin features.
	extractAndroidKotlin(dr, kr)

	// 5. Network endpoints.
	extractAndroidNetwork(dr, kr)
}

func extractAndroidDexRefs(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.DEXAnalysis == nil {
		return
	}
	for _, df := range dr.DEXAnalysis.DexFiles {
		for _, c := range df.Classes {
			kr.Android.DexClasses = append(kr.Android.DexClasses, DexClassRef{
				Name:       c.ClassName,
				Superclass: c.Superclass,
				SourceFile: c.SourceFile,
			})
		}
		for _, m := range df.Methods {
			kr.Android.DexMethods = append(kr.Android.DexMethods, DexMethodRef{
				ClassName:  m.ClassName,
				Name:       m.Name,
				Descriptor: m.Descriptor,
			})
		}
	}
}

func extractAndroidResources(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.ResourceAnalysis == nil {
		return
	}
	for _, asset := range dr.ResourceAnalysis.Assets {
		kr.Android.Resources = append(kr.Android.Resources, ResourceRef{
			Path:     asset.Path,
			Category: string(asset.Category),
			Size:     asset.Size,
		})
	}
}

func extractAndroidTelemetry(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.TelemetryAnalysis == nil {
		return
	}
	for _, s := range dr.TelemetryAnalysis.SDKs {
		kr.Android.Telemetry = append(kr.Android.Telemetry, AndroidTelemetrySDK{
			Name:       s.Name,
			Category:   string(s.Category),
			Package:    s.Package,
			Version:    s.Version,
			Confidence: s.Confidence,
		})
	}
}

func extractAndroidKotlin(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.KotlinAnalysis == nil {
		return
	}
	for _, f := range dr.KotlinAnalysis.Features {
		if f.Detected {
			kr.Android.KotlinFeatures = append(kr.Android.KotlinFeatures, f.Name)
		}
	}
}

func extractAndroidNetwork(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.NetworkAnalysis == nil {
		return
	}
	for _, ep := range dr.NetworkAnalysis.Endpoints {
		kr.Android.Network = append(kr.Android.Network, AndroidNetworkEndpoint{
			URL:    ep.URL,
			Scheme: ep.Scheme,
			Host:   ep.Host,
			Path:   ep.Path,
			Source: ep.Source,
		})
	}
}

// ---- depth.AndroidCoverageView adapter ----------------------------------
//
// androidCoverageView wraps *KnowledgeResult so it implements
// depth.AndroidCoverageView without forcing pkg/knowledge/kb/depth to
// import pkg/knowledge (cycle would otherwise form once Extract embeds
// []depth.Dimension in KnowledgeResult.DepthCovered).

type androidCoverageView struct {
	kr *KnowledgeResult
}

func (v androidCoverageView) AndroidPackagePresent() bool {
	return v.kr != nil && v.kr.Android != nil && v.kr.Android.Package != ""
}

func (v androidCoverageView) AndroidDEXClasses() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	if v.kr.Android.DEXStats != nil {
		return v.kr.Android.DEXStats.TotalClasses
	}
	return len(v.kr.Android.DexClasses)
}

func (v androidCoverageView) AndroidDEXMethods() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	if v.kr.Android.DEXStats != nil {
		return v.kr.Android.DEXStats.TotalMethods
	}
	return len(v.kr.Android.DexMethods)
}

func (v androidCoverageView) AndroidNativeLibCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.NativeLibs)
}

func (v androidCoverageView) AndroidResourcesCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.Resources)
}

func (v androidCoverageView) AndroidTelemetrySDKsCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.Telemetry)
}

func (v androidCoverageView) AndroidKotlinFeatureCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.KotlinFeatures)
}

func (v androidCoverageView) AndroidFrameworkPresent() bool {
	return v.kr != nil && v.kr.Android != nil && v.kr.Android.Framework != nil && v.kr.Android.Framework.Name != ""
}

func (v androidCoverageView) AndroidSecretsCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.Secrets)
}

func (v androidCoverageView) AndroidNetworkEndpointsCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.Network)
}

func (v androidCoverageView) AndroidObfuscationPresent() bool {
	if v.kr == nil || v.kr.Android == nil || v.kr.Android.Obfuscation == nil {
		return false
	}
	t := v.kr.Android.Obfuscation.Type
	return t != "" && t != "none"
}

func (v androidCoverageView) AndroidPermissionsCount() int {
	if v.kr == nil || v.kr.Android == nil {
		return 0
	}
	return len(v.kr.Android.Permissions)
}
