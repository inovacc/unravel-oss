/*
Copyright (c) 2026 Security Research
*/

// audit.go: per-platform extractor coverage audits.
package depth

import (
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// AndroidCoverageView is the read-only projection of the parts of
// KnowledgeResult that AuditAndroid inspects to decide what propagated
// from the dissect side. The interface lets pkg/knowledge implement an
// adapter without requiring this package to import pkg/knowledge (which
// would cycle once KnowledgeResult.DepthCovered references depth.Dimension).
//
// Each method returns 0 / "" / false when the KnowledgeResult lacks the
// information; D-37 absent != defect rule applies.
type AndroidCoverageView interface {
	AndroidPackagePresent() bool
	AndroidDEXClasses() int
	AndroidDEXMethods() int
	AndroidNativeLibCount() int
	AndroidResourcesCount() int
	AndroidTelemetrySDKsCount() int
	AndroidKotlinFeatureCount() int
	AndroidFrameworkPresent() bool
	AndroidSecretsCount() int
	AndroidNetworkEndpointsCount() int
	AndroidObfuscationPresent() bool
	AndroidPermissionsCount() int
}

// AuditAndroid returns one Dimension per audited Android sub-extractor.
// Each Dimension's Total is the number of items the sub-extractor produced
// in the dissect result; Covered is the number that propagated to the
// KnowledgeResult.Android struct or the top-level aggregators.
//
// Returns nil when there is nothing to audit (dr == nil || view == nil).
//
// Audited dimensions (canonical order, stable for downstream JSON consumers):
//
//	manifest, dex_classes, dex_methods, native_libs, resources_xml,
//	telemetry_sdks, kotlin_features, framework, secrets, network_endpoints,
//	obfuscation_signals, permissions
func AuditAndroid(dr *dissect.DissectResult, view AndroidCoverageView) []Dimension {
	if dr == nil {
		return nil
	}
	if view == nil {
		return nil
	}
	covManifest := 0
	if view.AndroidPackagePresent() {
		covManifest = 1
	}
	covFramework := 0
	if view.AndroidFrameworkPresent() {
		covFramework = 1
	}
	covObf := 0
	if view.AndroidObfuscationPresent() {
		covObf = 1
	}
	return []Dimension{
		NewDimension("manifest", covManifest, totalManifest(dr)),
		NewDimension("dex_classes", view.AndroidDEXClasses(), totalDexClasses(dr)),
		NewDimension("dex_methods", view.AndroidDEXMethods(), totalDexMethods(dr)),
		NewDimension("native_libs", view.AndroidNativeLibCount(), totalNative(dr)),
		NewDimension("resources_xml", view.AndroidResourcesCount(), totalResources(dr)),
		NewDimension("telemetry_sdks", view.AndroidTelemetrySDKsCount(), totalTelemetry(dr)),
		NewDimension("kotlin_features", view.AndroidKotlinFeatureCount(), totalKotlin(dr)),
		NewDimension("framework", covFramework, totalFramework(dr)),
		NewDimension("secrets", view.AndroidSecretsCount(), totalSecrets(dr)),
		NewDimension("network_endpoints", view.AndroidNetworkEndpointsCount(), totalNetwork(dr)),
		NewDimension("obfuscation_signals", covObf, totalObf(dr)),
		NewDimension("permissions", view.AndroidPermissionsCount(), totalPermissions(dr)),
	}
}

// ---- total_* helpers (read dissect side) -------------------------------

func totalManifest(dr *dissect.DissectResult) int {
	if dr.ManifestInfo == nil || dr.ManifestInfo.Package == "" {
		return 0
	}
	return 1
}

func totalDexClasses(dr *dissect.DissectResult) int {
	if dr.DEXAnalysis == nil {
		return 0
	}
	return dr.DEXAnalysis.TotalClasses
}

func totalDexMethods(dr *dissect.DissectResult) int {
	if dr.DEXAnalysis == nil {
		return 0
	}
	return dr.DEXAnalysis.TotalMethods
}

func totalNative(dr *dissect.DissectResult) int {
	if dr.NativeAnalysis == nil {
		return 0
	}
	return len(dr.NativeAnalysis.Libraries)
}

func totalResources(dr *dissect.DissectResult) int {
	if dr.ResourceAnalysis == nil {
		return 0
	}
	return dr.ResourceAnalysis.TotalAssets
}

func totalTelemetry(dr *dissect.DissectResult) int {
	if dr.TelemetryAnalysis == nil {
		return 0
	}
	return len(dr.TelemetryAnalysis.SDKs)
}

func totalKotlin(dr *dissect.DissectResult) int {
	if dr.KotlinAnalysis == nil {
		return 0
	}
	n := 0
	for _, f := range dr.KotlinAnalysis.Features {
		if f.Detected {
			n++
		}
	}
	return n
}

func totalFramework(dr *dissect.DissectResult) int {
	if dr.FrameworkAnalysis == nil || dr.FrameworkAnalysis.Framework == "" {
		return 0
	}
	return 1
}

func totalSecrets(dr *dissect.DissectResult) int {
	if dr.Secrets == nil {
		return 0
	}
	return len(dr.Secrets.Findings)
}

func totalNetwork(dr *dissect.DissectResult) int {
	if dr.NetworkAnalysis == nil {
		return 0
	}
	return len(dr.NetworkAnalysis.Endpoints)
}

func totalObf(dr *dissect.DissectResult) int {
	if dr.ObfuscationAnalysis == nil {
		return 0
	}
	if dr.ObfuscationAnalysis.Type == "none" {
		return 0
	}
	return 1
}

func totalPermissions(dr *dissect.DissectResult) int {
	if dr.ManifestInfo == nil {
		return 0
	}
	return len(dr.ManifestInfo.Permissions)
}
