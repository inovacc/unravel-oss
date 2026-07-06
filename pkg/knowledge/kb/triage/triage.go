// Package triage implements the deterministic, DB-free triage classifier
// for KB-OVERSEG P2 (docs/improving/2026-06-02-kb-oversegmentation-analysis.md
// and docs/superpowers/plans/2026-07-01-kb-overseg-dedup-triage.md).
//
// It ports the prose heuristics of the unravel-triage plugin agent
// (pkg/aihost/assets/ops/recovered.go) into pure Go so a module can be
// classified without spending an LLM call, memoized trivially by
// body_sha256, and rerun deterministically at ingest or via a backfill
// command.
//
// This package intentionally has no database dependency: callers own
// persistence (a future `modules.triage_class` column, per the plan) and
// any repeat-hash/vendored_shas-table lookups. Classify only inspects the
// module name and body bytes handed to it, reusing
// pkg/knowledge/kb/scanner's existing vendored-body/vendored-name signal
// rather than re-implementing it.
package triage

import (
	"bytes"
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/scanner"
)

// Class is the deterministic triage verdict for a module body.
type Class string

const (
	// Skip means the module should never be enriched: it is too small to
	// carry signal, is a known-vendored body/name, or is a pure re-export
	// shim with no first-party logic of its own.
	Skip Class = "SKIP"
	// StaticOK means the module's role is inferrable from its shape alone
	// (icon factory, lazy-binding wrapper, GraphQL fragment-only module) —
	// worth a terse static summary, but not worth an LLM enrich call.
	StaticOK Class = "STATIC_OK"
	// Enrich means the module carries first-party signal and should be
	// queued for LLM enrichment.
	Enrich Class = "ENRICH"
)

// DefaultMinBody is the minimum body size (bytes) below which a module is
// always classified Skip, mirroring the unravel-triage agent's documented
// min_body default (pkg/aihost/assets/ops/recovered.go).
const DefaultMinBody = 256

// Classify applies the deterministic SKIP/STATIC_OK/ENRICH rules to a
// single module. name is the module/chunk display name (used for the
// vendored-name signal); body is the raw module source. minBody overrides
// DefaultMinBody when > 0.
//
// Precedence (first match wins), mirroring the unravel-triage prose rules:
//  1. Skip   — body shorter than minBody.
//  2. Skip   — scanner.IsVendored(name, body) (known third-party library,
//     by name or content fingerprint).
//  3. Skip   — pure re-export shim (only webpack __webpack_require__.r/.d
//     calls, no first-party logic).
//  4. StaticOK — recognizable boilerplate shape (icon factory, lazy-binding
//     wrapper, GraphQL fragment-only module). The icon-factory and
//     GraphQL-fragment-only detectors additionally require the body to be
//     under maxStaticOKBodyBytes — above that cap they fall through to
//     Enrich, since a substantial module can legitimately embed an inline
//     SVG or a fragment literal alongside real first-party logic.
//  5. Enrich — everything else.
func Classify(name string, body []byte, minBody int) Class {
	if minBody <= 0 {
		minBody = DefaultMinBody
	}
	if len(body) < minBody {
		return Skip
	}
	if scanner.IsVendored(name, body) {
		return Skip
	}
	if isPureReexport(body) {
		return Skip
	}
	if isIconFactory(body) || isLazyBindingWrapper(body) || isGraphQLFragmentOnly(body) {
		return StaticOK
	}
	return Enrich
}

// stripASCIISpace removes ASCII whitespace so shape matching survives
// minification (which collapses spaces/newlines unpredictably). Mirrors
// scanner.stripASCIISpace, duplicated locally to avoid depending on an
// unexported symbol across packages.
func stripASCIISpace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			continue
		default:
			out = append(out, c)
		}
	}
	return out
}

// reReexportStatement matches one webpack re-export helper call, commonly
// minified to `n.r(t)` or `n.d(t,"a",function(){return o})` —
// __webpack_require__.r (mark as ES module) and .d (define a re-exported
// getter). `"use strict"` is tolerated as a leading statement. Matched
// against a whitespace-stripped body (see stripASCIISpace), so the
// two-word string literal `"use strict"` appears here with its interior
// space also collapsed to `"usestrict"`.
var reReexportStatement = regexp.MustCompile(
	`^(?:"usestrict";?)?(?:[A-Za-z_$][\w$]*\.r\([\w$]+\)[,;]?|` +
		`[A-Za-z_$][\w$]*\.d\([\w$]+,"[^"]+",function\(\)\{return[\w$.]+\}\)[,;]?)+$`,
)

// isPureReexport reports whether body is nothing but webpack re-export
// helper calls (__webpack_require__.r/.d) with no other first-party logic —
// the "only n.d + n.r calls" shape the unravel-triage prose describes.
// Conservative: any statement outside the r()/d() shape fails the match, so
// false negatives (a re-export shim classified ENRICH) are expected and
// acceptable; false positives (first-party logic wrongly SKIPped) should
// not occur because the whole-body anchor (^...$) requires an exact match.
func isPureReexport(body []byte) bool {
	stripped := stripASCIISpace(body)
	if len(stripped) == 0 {
		return false
	}
	return reReexportStatement.Match(stripped)
}

// maxStaticOKBodyBytes caps how large a module body may be before the
// icon-factory / GraphQL-fragment-only STATIC_OK detectors are allowed to
// fire. Both markers are shape *signals*, not whole-body anchors — an
// `createElement("svg"...viewBox...)` call or a `"kind":"FragmentDefinition"`
// literal can legitimately appear as one small piece of a much larger,
// substantial first-party module (e.g. a component that renders an inline
// SVG icon alongside real event-handling logic, or a data loader that embeds
// a compiled GraphQL fragment next to caching/error-handling code). Treating
// the whole module as boilerplate in that case would wrongly SKIP first-party
// logic from LLM enrichment. Real icon-factory / fragment-only modules are
// compact generated boilerplate — a single element tree or a bare JSON
// fragment literal — comfortably under this cap; anything larger falls
// through to ENRICH, the safe direction.
const maxStaticOKBodyBytes = 2048

// iconFactoryMarkers are shape signals of a generated SVG-icon-factory
// module: a createElement("svg"...) call plus an SVG-specific attribute.
// Icon factories are near-identical boilerplate across an app's icon set —
// worth a static summary, not an LLM call per icon.
var iconFactoryMarkers = [][]byte{
	[]byte(`createElement("svg"`),
	[]byte(`createElement('svg'`),
	[]byte(`h("svg"`),
	[]byte(`jsx("svg"`),
}

// isIconFactory reports whether body is (plausibly) nothing but a generated
// SVG-icon-factory function. Gated by maxStaticOKBodyBytes (see doc comment
// there): the markers alone are not anchored to the whole body, so a large
// module that merely embeds an inline SVG must NOT be classified as
// icon-factory boilerplate.
func isIconFactory(body []byte) bool {
	if len(body) > maxStaticOKBodyBytes {
		return false
	}
	hasSVGCall := false
	for _, m := range iconFactoryMarkers {
		if bytes.Contains(body, m) {
			hasSVGCall = true
			break
		}
	}
	if !hasSVGCall {
		return false
	}
	return bytes.Contains(body, []byte("viewBox"))
}

// reLazyBindingOnly matches a module body consisting solely of a
// `"use strict"` prologue, an `Object.defineProperty(exports,"__esModule"`
// marker, and one or more `Object.defineProperty(exports,"x",{get:...})`
// (or `enumerable:true,get:function(){...}`) getter re-bindings — the
// classic Babel/TS "lazy re-export" wrapper with no logic of its own beyond
// forwarding a getter to another module. Matched against a
// whitespace-stripped body (see stripASCIISpace), so `"use strict"`
// appears here as `"usestrict"`.
var reLazyBindingOnly = regexp.MustCompile(
	`^"usestrict";?Object\.defineProperty\(exports,"__esModule",\{value:!?0?\}\);?` +
		`(?:Object\.defineProperty\(exports,"[^"]+",\{(?:enumerable:!?0?,)?get:function\(\)\{return[^}]+\}(?:,set:function[^}]*\})?\}\);?)+$`,
)

func isLazyBindingWrapper(body []byte) bool {
	stripped := stripASCIISpace(body)
	if len(stripped) == 0 {
		return false
	}
	return reLazyBindingOnly.Match(stripped)
}

// graphQLFragmentMarkers are shape signals of a module whose entire payload
// is a compiled GraphQL fragment/document definition (Relay/Apollo codegen
// output) with no handwritten logic.
var graphQLFragmentMarkers = [][]byte{
	[]byte(`"kind":"FragmentDefinition"`),
	[]byte(`"kind":"Fragment"`),
}

// isGraphQLFragmentOnly reports whether body is (plausibly) nothing but a
// compiled GraphQL fragment/document literal. Gated by maxStaticOKBodyBytes
// (see doc comment there): the marker is a substring check, not a whole-body
// anchor, so a large module that merely embeds a fragment literal alongside
// real logic must NOT be classified fragment-only boilerplate.
func isGraphQLFragmentOnly(body []byte) bool {
	if len(body) > maxStaticOKBodyBytes {
		return false
	}
	for _, m := range graphQLFragmentMarkers {
		if bytes.Contains(body, m) {
			return true
		}
	}
	return false
}
