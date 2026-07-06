/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-05-ipc-api.ps1:100):
//
//	legacy step on total raw URL/API hits (non-JSAnalysis sources):
//	  hits > 50 -> 75
//	  hits > 10 -> 50
//	  else      -> 20
//
//	W-12 +15 / W-14 +10 quality-weighted deepening (P57 / Phase 84-04):
//	when r.JSAnalysis is populated, endpoints are classified + deduped and
//	PKI/CRL/cert noise is dropped BEFORE scoring (count-as-quality pitfall,
//	T-84-12); evidence-gated adders then lift the score past 75 on the
//	distinct quality endpoint count, each with a real Evidence citation
//	(no curve inflation, D-05). Gated behind populated r.JSAnalysis so
//	legacy fixtures (nil JSAnalysis) are byte/score-identical.
//
// Sources: JSAnalysisResult.URLs, AppAnalysis.Analysis.APIEndpoints,
// per-binary URLCount, MSIXInfo.URLs.
package scorecard

import (
	"net/url"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// apiNoiseHosts are PKI/CRL/OCSP/cert-distribution hosts whose endpoints are
// infrastructure noise, not application API surface. Classified out before
// quality scoring (T-84-12 — noisy endpoints must not inflate api).
var apiNoiseHosts = []string{
	"crl.microsoft.com", "www.microsoft.com/pkiops", "ocsp.",
	"crl.", "pki.", ".crl", "crl3.", "crl4.", "digicert.com/crl",
	"symcb.com", "verisign.com/crl", "thawte.com/crl",
}

// isAPINoise reports whether a raw endpoint string is PKI/CRL/cert
// distribution noise rather than real application API surface.
func isAPINoise(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return true
	}
	for _, n := range apiNoiseHosts {
		if strings.Contains(s, n) {
			return true
		}
	}
	if strings.HasSuffix(s, ".crl") || strings.HasSuffix(s, ".crt") ||
		strings.HasSuffix(s, ".cer") || strings.HasSuffix(s, ".p7c") {
		return true
	}
	return false
}

// classifyEndpoints dedupes by normalized host+path and drops PKI/CRL/cert
// noise, returning the count of distinct quality endpoints. Pure, no I/O.
func classifyEndpoints(urls []string) int {
	seen := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		if isAPINoise(raw) {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(raw))
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Host != "" {
			key = strings.ToLower(u.Host + u.Path)
		}
		if key == "" {
			continue
		}
		seen[key] = struct{}{}
	}
	return len(seen)
}

func init() { Register(apiScorer{}) }

type apiScorer struct{}

func (apiScorer) ID() string   { return "api" }
func (apiScorer) Name() string { return "API surface" }

func (apiScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "api", Name: "API surface"}
	if r == nil {
		return out
	}
	hits := 0
	if r.JSAnalysis != nil {
		hits += len(r.JSAnalysis.URLs)
		hits += len(r.JSAnalysis.NetworkCalls)
	}
	if r.AppAnalysis != nil {
		hits += len(r.AppAnalysis.Analysis.APIEndpoints)
		for _, b := range r.AppAnalysis.Binaries {
			hits += b.URLCount
		}
	}
	if r.MSIXInfo != nil {
		hits += len(r.MSIXInfo.URLs)
	}
	if r.NetworkAnalysis != nil {
		hits += 1
	}
	switch {
	case hits > 50:
		out.Score = 75
	case hits > 10:
		out.Score = 50
	default:
		out.Score = 20
	}
	if hits > 0 {
		// P58C-01 (P64-06): URL pattern source — JSAnalysis.File when
		// present (where the URL strings were discovered), else SourcePath.
		var cite *Citation
		if r.JSAnalysis != nil && r.JSAnalysis.File != "" {
			cite = &Citation{File: r.JSAnalysis.File}
		} else {
			cite = newCitation("", r.SourcePath, 0)
		}
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "JSAnalysis.URLs|AppAnalysis.APIEndpoints|MSIXInfo.URLs", Citation: cite})
	}

	// W-12/W-14 quality-weighted deepening (P57-deferred). Gated behind a
	// populated r.JSAnalysis: legacy fixtures set nil JSAnalysis so they
	// never reach here and stay byte/score-identical (expected_score_w13_
	// final.json + corpus tests). Classify+dedupe drops PKI/CRL noise so a
	// raw-count inflation cannot move the score (T-84-12); each adder
	// appends a real Evidence citation — no curve bump without evidence
	// (D-05).
	if r.JSAnalysis != nil {
		jsCite := &Citation{File: r.JSAnalysis.File}
		if r.JSAnalysis.File == "" {
			jsCite = newCitation("", r.SourcePath, 0)
		}
		quality := classifyEndpoints(r.JSAnalysis.URLs)

		// If the raw count put us in the high tier purely on noise, the
		// classified quality count re-grounds the score so noise cannot
		// hold the 75 step.
		if out.Score == 75 && quality <= 10 {
			if quality > 0 {
				out.Score = 50
			} else {
				out.Score = 20
			}
			out.Evidence = append(out.Evidence, Evidence{
				Kind: "field", Path: "JSAnalysis.URLs",
				Source: "static", Detail: "raw count was PKI/CRL noise; regrounded to quality count (T-84-12)",
				Citation: jsCite,
			})
		}

		// W-12: distinct quality-endpoint depth. >25 distinct real API
		// endpoints is materially deeper surface than the legacy step
		// rewards. +15, evidence-gated on the classified count.
		if quality > 25 {
			out.Score += 15
			out.Evidence = append(out.Evidence, Evidence{
				Kind: "field", Path: "JSAnalysis.URLs",
				Source: "static", Detail: "25+ distinct quality endpoints (W-12)",
				Citation: jsCite,
			})
		} else if quality > 10 {
			out.Score += 8
			out.Evidence = append(out.Evidence, Evidence{
				Kind: "field", Path: "JSAnalysis.URLs",
				Source: "static", Detail: "10+ distinct quality endpoints (W-12)",
				Citation: jsCite,
			})
		}

		// W-14: network-call method diversity is a quality signal distinct
		// from endpoint count (fetch/XHR/WebSocket reachability). +10 when
		// multiple distinct network-call kinds are observed.
		if distinctNetworkCalls(r.JSAnalysis.NetworkCalls) >= 3 {
			out.Score += 10
			out.Evidence = append(out.Evidence, Evidence{
				Kind: "field", Path: "JSAnalysis.NetworkCalls",
				Source: "static", Detail: "3+ distinct network-call kinds (W-14)",
				Citation: jsCite,
			})
		}

		if out.Score > 95 {
			out.Score = 95
		}
	}
	return out
}

// distinctNetworkCalls counts unique network-call kinds (case-insensitive),
// the W-14 method-diversity quality signal.
func distinctNetworkCalls(calls []string) int {
	seen := make(map[string]struct{}, len(calls))
	for _, c := range calls {
		k := strings.ToLower(strings.TrimSpace(c))
		if k == "" {
			continue
		}
		seen[k] = struct{}{}
	}
	return len(seen)
}
