/*
Copyright (c) 2026 Security Research
*/
package framework

import (
	"bytes"
	"regexp"
)

// matcher captures one framework's fingerprint patterns. patterns are
// general; uniquePatterns are uniquely identifying ones whose presence
// alone bumps confidence to 0.85.
//
// quickPrefilter is a list of cheap literal substrings — if NONE of
// them appear in src, the regex pass is skipped entirely. This caps the
// pathological-input cost: 9 matchers × bytes.Contains is far cheaper
// than 9 × ~5 regex.MustCompile.Match over multi-MB input.
type matcher struct {
	name           string
	specificity    int
	patterns       []*regexp.Regexp
	uniquePatterns []*regexp.Regexp
	versionRx      *regexp.Regexp
	quickPrefilter [][]byte
}

// Precompiled per-framework fingerprints. Patterns are derived verbatim
// from RESEARCH.md "Framework Detection Corpus (D-06)" table.
var (
	// React (R17+ new JSX transform + classic markers).
	rxReactJSX        = regexp.MustCompile(`_jsx\(`)
	rxReactJSXs       = regexp.MustCompile(`_jsxs\(`)
	rxReactJSXDev     = regexp.MustCompile(`_jsxDEV\(`)
	rxReactSecret     = regexp.MustCompile(`__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED`)
	rxReactProdMin    = regexp.MustCompile(`react\.production\.min\.js`)
	rxReactCreateElem = regexp.MustCompile(`React\.createElement`)

	// Preact (lightweight React clone — uses single-letter `h` factory).
	rxPreactCreate  = regexp.MustCompile(`preact\.createElement`)
	rxPreactInternB = regexp.MustCompile(`\b__b\b`)
	rxPreactInternD = regexp.MustCompile(`\b__d\b`)
	rxPreactInternP = regexp.MustCompile(`\b__P\b`)
	rxPreactHFactor = regexp.MustCompile(`h\(\s*"`)

	// Vue.
	rxVueDefineComp = regexp.MustCompile(`defineComponent\(`)
	rxVueHMR        = regexp.MustCompile(`__VUE_HMR_RUNTIME__`)
	rxVueElementVN  = regexp.MustCompile(`_createElementVNode`)
	rxVueSfcMain    = regexp.MustCompile(`_sfc_main`)
	rxVueRuntime    = regexp.MustCompile(`@vue/runtime-core`)

	// Angular (Ivy compiler).
	rxAngularDefineC = regexp.MustCompile(`ɵɵdefineComponent`)
	rxAngularElement = regexp.MustCompile(`ɵɵelement`)
	rxAngularText    = regexp.MustCompile(`ɵɵtext`)
	rxAngularCore    = regexp.MustCompile(`@angular/core`)

	// Svelte.
	rxSvelteFragment  = regexp.MustCompile(`create_fragment\b`)
	rxSvelteInstance  = regexp.MustCompile(`instance\(\$\$self`)
	rxSvelteSafeNotEq = regexp.MustCompile(`safe_not_equal`)
	rxSvelteDollarDol = regexp.MustCompile(`\$\$_h`)

	// Solid.
	rxSolidDevcomp    = regexp.MustCompile(`\$DEVCOMP`)
	rxSolidInsert     = regexp.MustCompile(`_\$insert`)
	rxSolidDelegate   = regexp.MustCompile(`_\$delegateEvents`)
	rxSolidLib        = regexp.MustCompile(`['"]solid-js['"]`)
	rxSolidCreateComp = regexp.MustCompile(`createComponent\(`)

	// Next.js.
	rxNextData     = regexp.MustCompile(`__NEXT_DATA__`)
	rxNextWebpack  = regexp.MustCompile(`webpackJsonp_N_E`)
	rxNextDistBld  = regexp.MustCompile(`next/dist/build/`)
	rxNextManifest = regexp.MustCompile(`pages-manifest\.json`)

	// Nuxt.
	rxNuxtData    = regexp.MustCompile(`__NUXT__`)
	rxNuxtUseApp  = regexp.MustCompile(`useNuxtApp\(`)
	rxNuxtPayload = regexp.MustCompile(`nuxtApp\.payload`)

	// Remix.
	rxRemixCtx      = regexp.MustCompile(`__remixContext`)
	rxRemixManifest = regexp.MustCompile(`__remixManifest`)
	rxRemixServer   = regexp.MustCompile(`RemixServer`)
	rxRemixRun      = regexp.MustCompile(`@remix-run`)

	// Generic version literal: ` 'react@1.2.3' ` or ` "@vue/runtime@1.2.3" `.
	// Capture group 1: framework slug (lowercase), group 2: version.
	rxVersionLiteral = regexp.MustCompile(
		`(react|preact|vue|@?angular[/\-]?core|svelte|solid-js|next|nuxt|remix)['"]?\s*[:@]\s*['"]?(\d+(?:\.\d+){0,3})`,
	)
)

// matchers is the ordered framework registry. Order does not affect
// detection correctness — Detect() applies specificity sort at the end —
// but a stable iteration order keeps Evidence slices deterministic.
var matchers = []matcher{
	{
		name:        "React",
		specificity: 5,
		patterns: []*regexp.Regexp{
			rxReactJSX, rxReactJSXs, rxReactJSXDev, rxReactCreateElem, rxReactProdMin,
		},
		uniquePatterns: []*regexp.Regexp{rxReactSecret},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("_jsx"), []byte("React.createElement"), []byte("__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED"), []byte("react.production.min.js")},
	},
	{
		name:        "Preact",
		specificity: 5,
		patterns: []*regexp.Regexp{
			rxPreactCreate, rxPreactHFactor, rxPreactInternB, rxPreactInternD, rxPreactInternP,
		},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("preact.createElement"), []byte("__b"), []byte("__d"), []byte("__P"), []byte(`h("`)},
	},
	{
		name:        "Vue",
		specificity: 7,
		patterns: []*regexp.Regexp{
			rxVueDefineComp, rxVueElementVN, rxVueSfcMain, rxVueRuntime,
		},
		uniquePatterns: []*regexp.Regexp{rxVueHMR},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("defineComponent"), []byte("__VUE_HMR_RUNTIME__"), []byte("_createElementVNode"), []byte("_sfc_main"), []byte("@vue/runtime-core")},
	},
	{
		name:        "Angular",
		specificity: 8,
		patterns: []*regexp.Regexp{
			rxAngularElement, rxAngularText, rxAngularCore,
		},
		uniquePatterns: []*regexp.Regexp{rxAngularDefineC},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("ɵɵ"), []byte("@angular/core")},
	},
	{
		name:        "Svelte",
		specificity: 7,
		patterns: []*regexp.Regexp{
			rxSvelteFragment, rxSvelteInstance, rxSvelteSafeNotEq, rxSvelteDollarDol,
		},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("create_fragment"), []byte("instance($$self"), []byte("safe_not_equal"), []byte("$$_h")},
	},
	{
		name:        "Solid",
		specificity: 5,
		patterns: []*regexp.Regexp{
			rxSolidCreateComp, rxSolidInsert, rxSolidDelegate, rxSolidLib,
		},
		uniquePatterns: []*regexp.Regexp{rxSolidDevcomp},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("$DEVCOMP"), []byte("_$insert"), []byte("_$delegateEvents"), []byte("solid-js"), []byte("createComponent(")},
	},
	{
		name:        "Next.js",
		specificity: 10,
		patterns: []*regexp.Regexp{
			rxNextWebpack, rxNextDistBld, rxNextManifest,
		},
		uniquePatterns: []*regexp.Regexp{rxNextData},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("__NEXT_DATA__"), []byte("webpackJsonp_N_E"), []byte("next/dist/build/"), []byte("pages-manifest.json")},
	},
	{
		name:        "Nuxt",
		specificity: 10,
		patterns: []*regexp.Regexp{
			rxNuxtUseApp, rxNuxtPayload,
		},
		uniquePatterns: []*regexp.Regexp{rxNuxtData},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("__NUXT__"), []byte("useNuxtApp("), []byte("nuxtApp.payload")},
	},
	{
		name:        "Remix",
		specificity: 10,
		patterns: []*regexp.Regexp{
			rxRemixManifest, rxRemixServer, rxRemixRun,
		},
		uniquePatterns: []*regexp.Regexp{rxRemixCtx},
		versionRx:      rxVersionLiteral,
		quickPrefilter: [][]byte{[]byte("__remixContext"), []byte("__remixManifest"), []byte("RemixServer"), []byte("@remix-run")},
	},
}

// runMatcher applies all patterns of m to src and returns
// (matched, evidence, version, uniqueHits). matched=true iff at least
// one pattern (general OR unique) hit. evidence is the list of pattern
// string-ids that fired.
func runMatcher(src []byte, m matcher, versionBySlug map[string]string) (bool, []string, string, int) {
	// Cheap literal-substring prefilter: if NONE of m.quickPrefilter
	// markers appear in src, no regex of m can match. Skip entirely.
	if len(m.quickPrefilter) > 0 {
		anyHit := false
		for _, lit := range m.quickPrefilter {
			if bytes.Contains(src, lit) {
				anyHit = true
				break
			}
		}
		if !anyHit {
			return false, nil, "", 0
		}
	}

	hits := []string{}
	uniqueHits := 0

	for _, rx := range m.uniquePatterns {
		if rx.Match(src) {
			hits = append(hits, rx.String())
			uniqueHits++
		}
	}
	for _, rx := range m.patterns {
		if rx.Match(src) {
			hits = append(hits, rx.String())
		}
	}
	if len(hits) == 0 {
		return false, nil, "", 0
	}
	version := versionBySlug[frameworkSlug(m.name)]
	return true, hits, version, uniqueHits
}

// scanVersions runs the version-literal regex once across src and
// returns a slug→version map. Called from Detect so the O(n) regex pass
// is amortised across all 9 matchers (avoids quadratic blow-up on
// multi-MB input). Cheap byte-level prefilter — if no `@` followed by
// digit-leading literal exists in src, skip entirely.
func scanVersions(src []byte) map[string]string {
	out := map[string]string{}
	if rxVersionLiteral == nil {
		return out
	}
	if !bytes.Contains(src, []byte("@")) {
		return out
	}
	for _, mm := range rxVersionLiteral.FindAllSubmatch(src, -1) {
		if len(mm) < 3 {
			continue
		}
		slug := frameworkSlug(string(mm[1]))
		if _, ok := out[slug]; !ok {
			out[slug] = string(mm[2])
		}
	}
	return out
}

// frameworkSlug normalises a framework display-name or version-literal
// slug to a canonical key for matching version literals back to
// frameworks.
func frameworkSlug(name string) string {
	switch name {
	case "React", "react":
		return "react"
	case "Preact", "preact":
		return "preact"
	case "Vue", "vue":
		return "vue"
	case "Angular", "angular", "@angular/core", "angular-core", "angular/core":
		return "angular"
	case "Svelte", "svelte":
		return "svelte"
	case "Solid", "solid-js":
		return "solid"
	case "Next.js", "next":
		return "next"
	case "Nuxt", "nuxt":
		return "nuxt"
	case "Remix", "remix":
		return "remix"
	}
	return name
}
