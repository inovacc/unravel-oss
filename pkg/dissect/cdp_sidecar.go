/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/webview2"
)

// cdpSidecarMaxCombinedBytes bounds the combined CDP-pulled JS buffer fed to
// ApplyPulledJS. It mirrors maxRecoveredJSConcatBytes (32 MiB) so a hostile or
// huge sidecar cannot exhaust memory even though applyCombinedJS self-clamps.
const cdpSidecarMaxCombinedBytes = maxRecoveredJSConcatBytes

// loadCDPSourceSidecar reads the attach-time CDP source sidecar persisted by
// `unravel capture webview2-attach` (pkg/capture/webview2.WriteCDPSourceSidecar),
// keyed by the resolved package id. The webview2-attach command verifies a
// live CDP session and pulls JS/CSS while it is still up, then the true-UWP
// app idle-exits before the slow dissect pipeline runs; this loader bridges
// that gap so a later dissect can consume the live-pulled source.
//
// Behaviour (all non-fatal, honest-empty — never panic, never synthesize):
//   - sidecar file absent          → ok=false (expected: no prior attach)
//   - read / unmarshal error       → ok=false (corrupt — ignore, don't spam)
//   - time.Since(PulledAt) > maxAge→ ok=false (stale: a different session/day)
//   - no non-empty JS and no CSS   → ok=false (analyzed-empty)
//
// On success the combined JS is "// pulled-from: <url>\n<source>\n" joined per
// entry, clamped to cdpSidecarMaxCombinedBytes, and the CSS entries are mapped
// to []CSSEntry{{Path:url, Source:source}} for the existing aggregation.
//
// Import note: pkg/capture/webview2 does NOT import pkg/dissect (verified via
// `go list -deps`), so importing it here is acyclic — the path helper and
// JSON shape are reused directly rather than replicated.
func loadCDPSourceSidecar(pkgKey string, maxAge time.Duration) (js string, css []CSSEntry, ok bool) {
	if pkgKey == "" {
		return "", nil, false
	}

	path := webview2.CDPSourceSidecarPath(pkgKey)
	data, err := os.ReadFile(path) //nolint:gosec // deterministic Unravel cache path, sanitized pkgKey
	if err != nil {
		// Absent is the common, expected case (no prior attach). A read
		// failure is also non-fatal — honest-empty, no error spam.
		return "", nil, false
	}

	var sc webview2.CDPSourceSidecar
	if uerr := json.Unmarshal(data, &sc); uerr != nil {
		// Corrupt sidecar — ignore rather than fail the whole dissect.
		return "", nil, false
	}

	// Stale guard: a sidecar from a totally different session/day must not
	// be silently attributed to this dissect run.
	if maxAge > 0 && time.Since(sc.PulledAt) > maxAge {
		return "", nil, false
	}

	var b strings.Builder
	for _, e := range sc.JS {
		if e.Source == "" {
			continue
		}
		// Stop appending once the bound would be exceeded (the final
		// applyCombinedJS also self-clamps; this keeps the buffer sane).
		if b.Len() >= cdpSidecarMaxCombinedBytes {
			break
		}
		b.WriteString("// pulled-from: ")
		b.WriteString(e.URL)
		b.WriteByte('\n')
		b.WriteString(e.Source)
		b.WriteByte('\n')
	}
	combined := b.String()
	if len(combined) > cdpSidecarMaxCombinedBytes {
		combined = combined[:cdpSidecarMaxCombinedBytes]
	}

	cssEntries := make([]CSSEntry, 0, len(sc.CSS))
	for _, e := range sc.CSS {
		if e.Source == "" {
			continue
		}
		cssEntries = append(cssEntries, CSSEntry{Path: e.URL, Source: e.Source})
	}

	if combined == "" && len(cssEntries) == 0 {
		return "", nil, false // analyzed-empty: nothing usable
	}
	return combined, cssEntries, true
}

// resolveUWPPackageKey derives the package id used to key the CDP source
// sidecar. It mirrors extractIdentity's UWP/MSIX precedence so the key equals
// the webview2-attach preset PkgName (e.g. WhatsApp → 5319275A.WhatsAppDesktop)
// and the knowledge.json package_id. Returns "" when no UWP/MSIX identity is
// resolvable (honest-empty — the sidecar block is then skipped).
func resolveUWPPackageKey(r *DissectResult) string {
	if r == nil {
		return ""
	}
	if r.MSIXInfo != nil && r.MSIXInfo.PackageName != "" {
		return r.MSIXInfo.PackageName
	}
	if r.UWPInfo != nil && r.UWPInfo.Manifest != nil && r.UWPInfo.Manifest.Identity.Name != "" {
		return r.UWPInfo.Manifest.Identity.Name
	}
	return ""
}

// applyCDPSourceSidecar is the non-fatal, additive bridge invoked at the end
// of the UWP webview2 wiring: when the cache/iterate paths left JSAnalysis /
// RecoveredCSS empty, fill them from a FRESH attach-time CDP source sidecar so
// the byte-unchanged source_layer / crypto scorers light up. It never clobbers
// an already-populated JSAnalysis or RecoveredCSS (cache/iterate wins).
func applyCDPSourceSidecar(r *DissectResult) {
	if r == nil {
		return
	}
	pkgKey := resolveUWPPackageKey(r)
	if pkgKey == "" {
		return // no UWP/MSIX identity — nothing to key on, honest-empty
	}
	combined, css, ok := loadCDPSourceSidecar(pkgKey, 24*time.Hour)
	if !ok {
		return // absent or stale — honest-empty, non-fatal
	}
	// Stash a bounded copy for downstream consumers (obfuscation rearm)
	// that cannot import pkg/capture/webview2. json:"-" on the field keeps
	// knowledge.json byte-shape unchanged. Honest-empty: only set when the
	// sidecar carried real combined JS.
	if combined != "" {
		const recoveredJSSourceCap = 256 * 1024
		rjs := combined
		if len(rjs) > recoveredJSSourceCap {
			rjs = rjs[:recoveredJSSourceCap]
		}
		r.RecoveredJSSource = rjs
	}
	applied := false
	// Richer-wins: the attach-time live CDP pull is the authoritative
	// clean-room source for WebView2-UWP. Apply it when JSAnalysis is unset
	// OR when the cache/ScriptCache path produced only a materially smaller
	// analysis (e.g. 4 tiny Service-Worker stubs vs the full app bundle) —
	// otherwise a shallow ScriptCache analysis would block the real source.
	if combined != "" && (r.JSAnalysis == nil || r.JSAnalysis.Size < len(combined)) {
		ApplyPulledJS(r, combined)
		if r.JSAnalysis != nil {
			applied = true
		}
	}
	if r.RecoveredCSS == nil && len(css) > 0 {
		ApplyPulledCSS(r, css)
		if r.RecoveredCSS != nil {
			applied = true
		}
	}
	if applied {
		r.Errors = append(r.Errors, fmt.Sprintf(
			"uwp cdp-source-sidecar: applied attach-time CDP source for %q (js=%v css=%d)",
			pkgKey, r.JSAnalysis != nil, len(css)))
	}
}
