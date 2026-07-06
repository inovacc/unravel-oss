/*
Copyright (c) 2026 Security Research
*/

// audit_webview2.go: WebView2 extractor coverage audit (D-38-DIMENSIONS-PER-STACK).
package depth

import "github.com/inovacc/unravel-oss/pkg/dissect"

// AuditWebView2 returns one Dimension per audited WebView2 sub-extractor.
// Returns nil when dr is nil OR view is nil.
//
// Dimensions (canonical order):
//
//	webview2.udf, webview2.profiles, webview2.cache, webview2.preferences
func AuditWebView2(dr *dissect.DissectResult, view WebView2CoverageView) []Dimension {
	if dr == nil || view == nil {
		return nil
	}
	return []Dimension{
		NewDimension("webview2.udf", view.UDFCovered(), totalWebView2UDF(dr)),
		NewDimension("webview2.profiles", view.ProfilesCovered(), totalWebView2Profiles(dr)),
		NewDimension("webview2.cache", view.CacheCovered(), totalWebView2Cache(dr)),
		NewDimension("webview2.preferences", view.PreferencesCovered(), totalWebView2Preferences(dr)),
	}
}

// ---- total_webview2_* helpers -------------------------------------------

func totalWebView2UDF(dr *dissect.DissectResult) int {
	if dr.WebView2Info == nil {
		return 0
	}
	return len(dr.WebView2Info.UDFs)
}

func totalWebView2Profiles(dr *dissect.DissectResult) int {
	if dr.WebView2Info == nil {
		return 0
	}
	return len(dr.WebView2Info.Profiles)
}

func totalWebView2Cache(dr *dissect.DissectResult) int {
	if dr.WebView2Info == nil {
		return 0
	}
	// ProfileData blocks carry per-profile cache summaries; one block per
	// profile that webview2.Analyze inspected.
	return len(dr.WebView2Info.ProfileData)
}

func totalWebView2Preferences(dr *dissect.DissectResult) int {
	if dr.WebView2Info == nil {
		return 0
	}
	// Same upper bound as cache: each ProfileData block can carry a
	// Preferences blob (DPAPI-flagged per D-18). Coverage view reports
	// how many were actually surfaced into KnowledgeResult.
	return len(dr.WebView2Info.ProfileData)
}
