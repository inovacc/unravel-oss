/*
Copyright (c) 2026 Security Research
*/

// strip_bundler.go ships the minification-reversal enhancement called
// out in ROADMAP Phase 11 as the last open item. Common bundler outputs
// (webpack / esbuild / rollup / vite) inject runtime boilerplate that
// adds dozens of lines of noise to every module without carrying any
// behavioural meaning. Stripping that noise improves recall on
// downstream string + URL + symbol extraction and shrinks
// kb_search snippets so enriched modules surface cleanly.
//
// KEEP semantics — runtime calls that ARE part of the module's
// observable API (e.g. `__webpack_require__.d(exports, {...})` which
// names the exported symbols) are preserved verbatim. Only pure
// runtime plumbing is stripped.

package jsdeob

import "regexp"

var (
	// esbuild aliases at the top of CommonJS bundles:
	//   var __defProp = Object.defineProperty;
	//   var __getOwnPropNames = Object.getOwnPropertyNames;
	//   var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
	//   var __getProtoOf = Object.getPrototypeOf;
	//   var __hasOwnProp = Object.prototype.hasOwnProperty;
	//   var __create = Object.create;
	reEsbuildAliases = regexp.MustCompile(`(?m)^\s*var\s+__[A-Za-z]{3,40}\s*=\s*Object\.(?:defineProperty|getOwnProperty(?:Names|Descriptor|Descriptors)|getPrototypeOf|prototype\.hasOwnProperty|create|assign|keys|freeze)\s*;\s*$`)

	// esbuild's IIFE wrapper around each module's CJS shim:
	//   var __commonJS = (cb, mod) => function __require() { ... };
	reEsbuildCommonJSWrap = regexp.MustCompile(`(?m)^\s*var\s+__commonJS\s*=\s*\(\s*cb\s*,\s*mod\s*\)\s*=>\s*function\s+__require\s*\(\s*\)\s*\{[^}]*\}\s*;?\s*$`)

	// esbuild's ESM marker line:
	//   Object.defineProperty(exports, "__esModule", { value: true });
	// kept-but-noisy in every entry; strip safely (the symbol map carries
	// the same information via __webpack_require__.d / export ASTs).
	reESMMarker = regexp.MustCompile(`(?m)^\s*Object\.defineProperty\s*\(\s*(?:exports|t|e|n|module\.exports)\s*,\s*["']__esModule["']\s*,\s*\{\s*value\s*:\s*(?:true|!0)\s*\}\s*\)\s*;\s*$`)

	// webpack's "mark module as ESM" runtime call. PRESERVE
	// __webpack_require__.d (the export-name table) — only strip .r
	// (the ESM-ness flag).
	reWebpackRMarker = regexp.MustCompile(`(?m)^\s*__webpack_require__\.r\s*\(\s*[a-zA-Z_$][\w$]*\s*\)\s*;\s*$`)

	// webpack's per-module "use strict" lead-in (kept at file top by
	// some toolchains too — only strip when it's followed by another
	// statement, never as the sole content of a module).
	reUseStrictLine = regexp.MustCompile(`(?m)^\s*["']use strict["']\s*;\s*$`)
)

// StripBundlerBoilerplate removes runtime cruft injected by
// webpack / esbuild / rollup / vite that adds line count without
// behavioural meaning. Returns (new_code, count_of_stripped_lines).
//
// Safety: each pattern matches FULL-LINE so partial-match collisions
// with user code (e.g. a string literal containing __webpack_require__.r)
// don't trigger. The `(?m)^...$` anchors are load-bearing — do not
// soften them.
//
// Use Cases that PRESERVE original lines:
//   - `__webpack_require__.d(exports, {Foo: () => Foo})` — names a real
//     export; survives because reWebpackRMarker matches `.r(` only.
//   - `Object.defineProperty(target, "myCustomProp", ...)` — survives
//     because reESMMarker anchors on the literal "__esModule" key.
func StripBundlerBoilerplate(code string) (string, int) {
	total := 0
	for _, re := range []*regexp.Regexp{
		reEsbuildAliases,
		reEsbuildCommonJSWrap,
		reESMMarker,
		reWebpackRMarker,
		reUseStrictLine,
	} {
		matches := re.FindAllStringIndex(code, -1)
		if len(matches) == 0 {
			continue
		}
		total += len(matches)
		code = re.ReplaceAllString(code, "")
	}
	return code, total
}
