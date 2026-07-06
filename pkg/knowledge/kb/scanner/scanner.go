// Package scanner extracts JS module definitions from app bundles. It
// recognises Meta's __d("Name", function...) format (WhatsApp Web) and the
// standard webpack numeric-id factory format (Teams / Slack / LinkedIn),
// plus a single-file fallback for plain CommonJS / ES module .js files.
//
// All functions in this package are pure — no DB or filesystem access.
package scanner

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// NameQuality is the provenance label for a module name. The 06-04
// Task 3 (D-14) extension adds recovered_<bundler> values for modules
// surfaced by RECON-07 bundle reconstruction.
type NameQuality string

const (
	// NameQualityRaw is the default (no enrichment / unnamed).
	NameQualityRaw NameQuality = "raw"
	// NameQualityRecoveredWebpack tags a module recovered from a
	// webpack bundle by pkg/jsdeob/bundle (D-14).
	NameQualityRecoveredWebpack NameQuality = "recovered_webpack"
	// NameQualityRecoveredVite tags a module recovered from a Vite
	// bundle.
	NameQualityRecoveredVite NameQuality = "recovered_vite"
	// NameQualityRecoveredEsbuild tags a module recovered from an
	// esbuild bundle.
	NameQualityRecoveredEsbuild NameQuality = "recovered_esbuild"
	// NameQualityRecoveredRollup tags a module recovered from a
	// Rollup bundle.
	NameQualityRecoveredRollup NameQuality = "recovered_rollup"
)

// Mod describes one module observed in a bundle: its name (or synthesised
// app_module_NNN id), its byte offset in the source, and its size.
type Mod struct {
	Name   string
	Offset int
	Size   int
	// NameQuality records the provenance of Name. Default empty
	// (interpreted as NameQualityRaw).
	NameQuality NameQuality
}

// Body returns up to max bytes of the module body starting at Offset.
func (m Mod) Body(src []byte, max int) string {
	end := m.Offset + m.Size
	if end-m.Offset > max {
		end = m.Offset + max
	}
	if end > len(src) {
		end = len(src)
	}
	return string(src[m.Offset:end])
}

// Prefix returns "WAWeb" + the first capitalised run after it. Useful filter
// bucket. Empty for non-WAWeb names.
func (m Mod) Prefix() string {
	if !strings.HasPrefix(m.Name, "WAWeb") {
		return ""
	}
	rest := m.Name[5:]
	end := 0
	for i, r := range rest {
		if i == 0 {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			end = i
			break
		}
	}
	if end == 0 {
		return "WAWeb" + rest
	}
	return "WAWeb" + rest[:end]
}

// ScanMeta picks up Meta's __d("Name", function...) module definitions.
func ScanMeta(src []byte) []Mod {
	var out []Mod
	needle := []byte(`__d("`)
	i := 0
	for i < len(src) {
		j := bytes.Index(src[i:], needle)
		if j < 0 {
			break
		}
		j += i
		nameStart := j + len(needle)
		nameEnd := bytes.Index(src[nameStart:], []byte(`"`))
		if nameEnd < 0 || nameEnd > 256 {
			i = j + len(needle)
			continue
		}
		nameEnd += nameStart
		next := bytes.Index(src[nameEnd:], needle)
		var nextAbs int
		if next < 0 {
			nextAbs = len(src)
		} else {
			nextAbs = nameEnd + next
		}
		size := min(nextAbs-nameStart, 1<<20)
		out = append(out, Mod{Name: string(src[nameStart:nameEnd]), Offset: nameStart, Size: size})
		i = nameEnd
	}
	return out
}

// ScanWebpack picks up `,DDDDDD:` followed by a factory (function or arrow).
// Used by Teams / Slack / LinkedIn — module ids are minified to short
// integers so we synthesise `<app>_module_<id>`.
func ScanWebpack(src []byte, app string) []Mod {
	var out []Mod
	prefix := app + "_module_"
	n := len(src)
	for i := 0; i < n; {
		c := src[i]
		if c != '{' && c != ',' {
			i++
			continue
		}
		j := i + 1
		for j < n && src[j] >= '0' && src[j] <= '9' {
			j++
		}
		if j == i+1 || j == n || src[j] != ':' {
			i++
			continue
		}
		idStart, idEnd, colon := i+1, j, j
		k := colon + 1
		factory := false
		switch {
		case k+8 < n && string(src[k:k+8]) == "function":
			factory = true
		case k < n && src[k] == '(':
			limit := min(k+64, n)
			seg := src[k:limit]
			for x := 0; x < len(seg)-2; x++ {
				if seg[x] == ')' && seg[x+1] == '=' && seg[x+2] == '>' {
					factory = true
					break
				}
			}
		case k+3 < n && src[k] >= 'a' && src[k] <= 'z':
			limit := min(k+32, n)
			seg := src[k:limit]
			for x := 0; x < len(seg)-1; x++ {
				if seg[x] == '=' && seg[x+1] == '>' {
					factory = true
					break
				}
			}
		}
		if !factory {
			i = colon + 1
			continue
		}
		next := -1
		for x := colon + 1; x < n-2; x++ {
			if (src[x] == ',' || src[x] == '{') && src[x+1] >= '0' && src[x+1] <= '9' {
				y := x + 1
				for y < n && src[y] >= '0' && src[y] <= '9' {
					y++
				}
				if y < n && src[y] == ':' {
					next = x
					break
				}
			}
		}
		if next < 0 {
			next = n
		}
		size := min(next-colon, 1<<20)
		out = append(out, Mod{Name: prefix + string(src[idStart:idEnd]), Offset: colon + 1, Size: size})
		i = next
	}
	return out
}

// recoveredBundleManifest is the subset of pkg/jsdeob/bundle.Manifest
// the scanner needs to map a recovered-modules directory to a
// NameQuality value (D-14).
type recoveredBundleManifest struct {
	BundleKind string `json:"bundle_kind"`
}

// NameQualityForBundleDir returns the NameQuality value for modules
// living under <bundleDir>/modules/* when <bundleDir>/manifest.json
// declares a bundle_kind. Returns NameQualityRaw when no manifest is
// present or the kind is unrecognised. 06-04 Task 3 / D-14.
func NameQualityForBundleDir(bundleDir string) NameQuality {
	manifestPath := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return NameQualityRaw
	}
	// Bounded JSON parse (T-06-03): cap at 1 MiB.
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	var m recoveredBundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return NameQualityRaw
	}
	switch strings.ToLower(m.BundleKind) {
	case "webpack":
		return NameQualityRecoveredWebpack
	case "vite":
		return NameQualityRecoveredVite
	case "esbuild":
		return NameQualityRecoveredEsbuild
	case "rollup":
		return NameQualityRecoveredRollup
	}
	return NameQualityRaw
}

// ScanRecoveredBundleDir walks <bundleDir>/modules/ and returns one Mod
// per .js file with the NameQuality field populated from the
// manifest's bundle_kind. Used by knowledge sweeps to tag
// reconstruction provenance.
func ScanRecoveredBundleDir(bundleDir string) ([]Mod, error) {
	defer func() { _ = recover() }()
	quality := NameQualityForBundleDir(bundleDir)
	modulesDir := filepath.Join(bundleDir, "modules")
	out := []Mod{}
	err := filepath.WalkDir(modulesDir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".js") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(modulesDir, path)
		name := strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
		out = append(out, Mod{
			Name:        name,
			Offset:      0,
			Size:        len(data),
			NameQuality: quality,
		})
		return nil
	})
	if err != nil {
		return out, err
	}
	return out, nil
}

// reVendoredScopedImport matches a scoped npm specifier inside an import or
// require, e.g. require("@scope/pkg") / from "@scope/pkg". Scoped packages are
// almost always third-party (first-party app code rarely publishes under an
// @scope it then re-imports by specifier).
var reVendoredScopedImport = regexp.MustCompile(`(?:require\(|from\s+|import\s+)["']@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*["']`)

// IsVendoredBody reports whether a module body carries vendored-OSS
// fingerprints. It is deliberately conservative: false negatives are
// acceptable (a vendored module slips through and gets enriched), but false
// positives must be rare (first-party code wrongly excluded from enrichment).
// Used by KB-OVERSEG P3 to MARK modules.is_vendored at ingest — never to skip
// persisting a row.
func IsVendoredBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	// 1) A node_modules/ path substring — build tools leave these in source
	//    maps, banners, and webpack module-path comments for bundled deps.
	if bytes.Contains(body, []byte("node_modules/")) {
		return true
	}
	// 2) License banner comments minifiers preserve verbatim from vendored
	//    libs: `/*!`, `/** @license`, or a bare `@license` tag.
	if bytes.Contains(body, []byte("/*!")) ||
		bytes.Contains(body, []byte("@license")) {
		return true
	}
	// 3) UMD wrapper banner — the classic universal-module-definition preamble
	//    emitted by bundled libraries (React, lodash, etc.). Match the two most
	//    stable shapes, tolerant of minifier whitespace removal.
	stripped := stripASCIISpace(body)
	if bytes.Contains(stripped, []byte("(function(global,factory)")) ||
		bytes.Contains(stripped, []byte(`typeofexports==="object"&&typeofmodule!=="undefined"`)) ||
		bytes.Contains(stripped, []byte("typeofexports==='object'&&typeofmodule!=='undefined'")) {
		return true
	}
	// 4) A scoped npm specifier (@scope/pkg) inside an import/require.
	if reVendoredScopedImport.Match(body) {
		return true
	}
	// 5) TextMate / shiki syntax-highlighter grammar: bundled language
	//    definitions carry a quoted "scopeName" plus a "patterns" or
	//    "repository" array. First-party app code never ships TextMate
	//    grammars, so requiring the quoted marker is high-precision. Matched
	//    over the FULL body: bundlers place the grammar JSON after a wrapper
	//    preamble, so the marker routinely sits tens of KB in (e.g. shiki's
	//    markdown grammar has "scopeName" at byte ~59000).
	if bytes.Contains(body, []byte(`"scopeName"`)) &&
		(bytes.Contains(body, []byte(`"patterns"`)) || bytes.Contains(body, []byte(`"repository"`))) {
		return true
	}
	// 6) shiki / VS Code color theme: carries a quoted "tokenColors" array.
	if bytes.Contains(body, []byte(`"tokenColors"`)) {
		return true
	}
	// 7) Known bundled-library body fingerprints — distinctive literals that
	//    survive minification for a few high-frequency OSS libraries whose
	//    webpack chunk names are NOT diagnostic (Clerk auth UI is split across
	//    chunks named SignIn/Modal/Alert/…; mermaid across vennDiagram/
	//    xychartDiagram/…). Kept deliberately narrow + distinctive.
	for _, fp := range vendoredBodyFingerprints {
		if bytes.Contains(body, fp) {
			return true
		}
	}
	// NB: Object.defineProperty(exports,"__esModule",…) alone is intentionally
	// NOT treated as vendored — Babel emits it for first-party code too.
	return false
}

// vendoredBodyFingerprints are distinctive substrings of specific bundled OSS
// libraries. Narrow by design: "clerk.com" is a Clerk-only URL host; "mermaid"
// is the diagram library's name string. Add only literals unlikely to appear
// in first-party application code.
var vendoredBodyFingerprints = [][]byte{
	[]byte("clerk.com"), // Clerk auth UI: dashboard/go/support URLs
	[]byte("Clerk: "),   // Clerk's error-throw prefix ("Clerk: useX called outside")
	[]byte("@clerk/"),   // surviving Clerk scoped specifier, if any
	[]byte("mermaid"),   // mermaid diagram library (vennDiagram/xychart/… chunks)
}

// vendoredNameLibs lists distinctive third-party library identifiers that show
// up as webpack/rollup chunk basenames (e.g. "react-<contenthash>",
// "cytoscape.esm-<hash>", "pdf.worker"). Minified bundles routinely strip the
// license banner these libs ship, so the chunk NAME is the surviving signal.
// Entries are deliberately distinctive — generic words (index/main/app/utils/
// chart/three) are excluded so first-party chunks are never wrongly flagged.
var vendoredNameLibs = []string{
	"react", "react-dom", "react-dom-client", "scheduler",
	"cytoscape", "d3", "rxjs", "mobx", "immer", "redux", "zod", "axios",
	"apollo", "graphql", "lodash", "moment", "dayjs", "tslib", "core-js",
	"regenerator-runtime", "bluebird",
	"firebase", "firebase-app", "firebase-auth", "firebase-storage", "firebase-firestore",
	"pdfjs", "pdf.js", "pdf.worker", "cff_parser",
	"monaco", "codemirror", "prismjs", "katex", "mermaid", "streamdown",
	"shiki", "vscode-oniguruma", "vscode-textmate",
}

// IsVendoredName reports whether a module/chunk name matches a known
// third-party library. Matches case-insensitively when the (lowercased) name
// equals a library id or begins with "<lib>-" or "<lib>." (the contenthash or
// sub-entrypoint suffix bundlers append). Conservative by construction.
func IsVendoredName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, lib := range vendoredNameLibs {
		if n == lib || strings.HasPrefix(n, lib+"-") || strings.HasPrefix(n, lib+".") {
			return true
		}
	}
	return false
}

// IsVendored combines the name and body signals. Used by ingest and the
// backfill-vendored command to MARK modules.is_vendored. Same conservative
// philosophy as IsVendoredBody: false negatives acceptable, false positives rare.
func IsVendored(name string, body []byte) bool {
	return IsVendoredName(name) || IsVendoredBody(body)
}

// vendoredAssemblyPrefixes are .NET assembly/namespace roots treated as
// framework / well-known third-party (highest-precedence vendored signal,
// supplied by the clr engine's AssemblyRef identity).
var vendoredAssemblyPrefixes = []string{
	"System", "Microsoft", "WinRT", "CommunityToolkit", "protobuf-net",
}

// IsVendoredAssembly reports whether a .NET assembly-qualified type/assembly
// name belongs to a framework or well-known vendor. Matches a prefix only at a
// namespace boundary ("System." or exactly "System") so "SystemicRisk" is NOT
// matched. This is the top tier of the ingest vendored-precedence chain.
func IsVendoredAssembly(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" {
		return false
	}
	for _, p := range vendoredAssemblyPrefixes {
		if n == p || strings.HasPrefix(n, p+".") || strings.HasPrefix(n, p+"-") {
			return true
		}
	}
	return false
}

// stripASCIISpace removes ASCII whitespace so UMD banner matching survives
// minification (which collapses spaces/newlines unpredictably).
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

// ScanSingle returns a single Mod treating the whole file body as one module
// named after its base path. Used as fallback when neither meta nor webpack
// formats matched and the file is at least minBytes in size.
func ScanSingle(data []byte, srcRoot, path string, minBytes int) []Mod {
	if len(data) < minBytes {
		return nil
	}
	rel, _ := filepath.Rel(srcRoot, path)
	modName := strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
	return []Mod{{Name: modName, Offset: 0, Size: len(data)}}
}

// All regexes used by Promote + Symbols. Compiled once at startup.
var (
	rePathComment  = regexp.MustCompile(`["'](src/[^"']+\.[a-z]{1,4})["']`)
	reLogTag       = regexp.MustCompile(`\["\[([A-Za-z][A-Za-z0-9_-]{2,40})\]`)
	reWAWebIdent   = regexp.MustCompile(`WAWeb[A-Z][A-Za-z0-9]{2,60}`)
	reTSGlobal     = regexp.MustCompile(`TS\.([A-Z][A-Z0-9_]{2,40})`)
	reURL          = regexp.MustCompile(`["'](https?://[A-Za-z0-9._/\-?=&%~:#@+,]{4,300})["']`)
	reEventName    = regexp.MustCompile(`(?:\.on|\.emit|\.trigger|addEventListener)\(["']([a-zA-Z][a-zA-Z0-9_:.\-]{1,60})["']`)
	reIDBStore     = regexp.MustCompile(`createObjectStore\(["']([a-zA-Z0-9_-]{2,60})["']`)
	reLocalStorage = regexp.MustCompile(`localStorage\.(?:getItem|setItem|removeItem)\(["']([a-zA-Z0-9_:.\-]{2,60})["']`)
	reBracketTag   = regexp.MustCompile(`\[([A-Z][A-Z0-9_-]{2,30})\]`)
	reWAWebRequire = regexp.MustCompile(`require\(["'](WAWeb[A-Za-z0-9]{2,60})["']\)`)
	reAPIPath      = regexp.MustCompile(`["'](/api/[A-Za-z0-9_/.-]{2,80}|/v\d+/[A-Za-z0-9_/.-]{2,80})["']`)

	// Webpack runtime chunk-id-to-name map: `{0:"foo",17:"bar.chunk"}` lookup
	// inside the `__webpack_require__.u = function(e){return ...+{...}[e]+...}`
	// runtime. The map literal is what we want — pull it out then index per id.
	reWebpackChunkMap = regexp.MustCompile(`\{((?:\d+:["'][A-Za-z0-9_./~\-]{2,80}["'][,}])+)`)
	reWebpackChunkKV  = regexp.MustCompile(`(\d+):["']([A-Za-z0-9_./~\-]{2,80})["']`)
	// __webpack_require__.d(t,"NAME",function(){…}) — explicit export name.
	reWebpackExport = regexp.MustCompile(`__webpack_require__\.d\([a-zA-Z_$][a-zA-Z0-9_$]*,["']([A-Za-z_$][A-Za-z0-9_$]{1,60})["']`)
	// Modern minified webpack export define: `n.d(t,{Foo:()=>x,Bar:()=>y})`
	// or older quoted form `n.d(t,"Foo",function(){…})`. Used heavily by
	// LinkedIn / Teams / Slack post-2022 builds. Skip 1-letter alias keys
	// like `Z` — they're the default-export marker and not informative.
	reWebpackDExport = regexp.MustCompile(`\b[a-zA-Z_$][a-zA-Z0-9_$]?\.d\([a-zA-Z_$][a-zA-Z0-9_$]*\s*,\s*\{\s*([A-Za-z_$][A-Za-z0-9_$]{2,60})\s*:`)
	// CommonJS export-property assignment: `t.QueueBackend = ` /
	// `exports.SendMessage = `. Filter out common Babel runtime markers so
	// we don't promote modules to "__esModule" or "default".
	reCJSExport = regexp.MustCompile(`\b(?:t|e|exports|module\.exports)\.([A-Z][A-Za-z0-9_$]{2,60})\s*=`)
	// Object.defineProperty(t, "NAME", ...). Used heavily by Babel-emitted
	// LinkedIn modules.
	reDefineProp = regexp.MustCompile(`Object\.defineProperty\([a-zA-Z_$][a-zA-Z0-9_$]*\s*,\s*["']([A-Z][A-Za-z0-9_$]{2,60})["']`)
	// MicrosoftTeams.Foo / TeamsClient.Foo namespaced identifiers.
	reTeamsNS = regexp.MustCompile(`\b(?:MicrosoftTeams|TeamsClient|TeamsApp)\.([A-Z][A-Za-z0-9]{2,60})`)
	// First named function declaration: `function FooBar(`.
	reFirstFunc = regexp.MustCompile(`function\s+([A-Z][A-Za-z0-9_$]{2,60})\s*\(`)
	// `class FooBar` — top-level class declaration.
	reClassDecl = regexp.MustCompile(`\bclass\s+([A-Z][A-Za-z0-9_$]{2,60})\b`)

	// Symbols-only patterns (broader symbol density).
	reFuncDecl   = regexp.MustCompile(`\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]{1,60})\s*\(`)
	reConstDecl  = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{2,60})\s*=`)
	reMethodDecl = regexp.MustCompile(`(?m)(?:^|[{,;\s])([A-Za-z_$][A-Za-z0-9_$]{2,60})\s*\([^)]{0,200}\)\s*\{`)
	reExports    = regexp.MustCompile(`\bexports\.([A-Za-z_$][A-Za-z0-9_$]{1,60})\s*=`)
)

// Promote turns a synthesised app_module_NNN into something searchable by
// scanning the body for distinctive WAWeb*-style identifiers, log tags, or
// webpack source-path comments left by the build. Returns "" if no
// confident promotion candidate is found.
func Promote(body string) string {
	// 1) Webpack still emits source-path comments in many builds: `/* harmony export ... */ src/foo/bar.ts`
	if m := rePathComment.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSuffix(filepath.Base(m[1]), filepath.Ext(m[1]))
	}
	// 2) Log tags inside WAWeb-style modules: WALogger.LOG(["[WAWebMsgCollection] ..."]).
	if m := reLogTag.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 3) Distinctive WAWeb identifier in body — usually a require() target.
	if m := reWAWebIdent.FindString(body); m != "" {
		return m
	}
	// 4) Slack/Discord channel-style identifier: window.TS_GLOBAL.CHANNEL_NAME.foo
	if m := reTSGlobal.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 5) Webpack explicit export: `__webpack_require__.d(t,"FooBar",function(){…})`.
	if m := reWebpackExport.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 5b) Modern minified webpack export object: `n.d(t,{FooBar:()=>x,...})`.
	if m := reWebpackDExport.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 5c) Object.defineProperty(t,"FooBar",...) — Babel pattern.
	if m := reDefineProp.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 5d) CommonJS named export: `t.FooBar = …` / `exports.FooBar = …`.
	if m := reCJSExport.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 6) Teams-namespaced API: MicrosoftTeams.SomeFeature.do().
	if m := reTeamsNS.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 7) First class declaration in module body.
	if m := reClassDecl.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// 8) First named function declaration starting with capital — likely the
	//    module's primary export, even when minifiers leave it intact.
	if m := reFirstFunc.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	return ""
}

// PromoteFromChunkMap parses a webpack runtime chunk-id-to-name map (the
// `{0:"foo",17:"bar.chunk"}` literal inside `__webpack_require__.u`) and
// returns the chunk name for the given numeric id, or "" if not found.
// Used to recover real names for synthesised `<app>_module_<id>` ids when
// the runtime chunk is sighted alongside the data chunks.
func PromoteFromChunkMap(runtimeBody, id string) string {
	m := reWebpackChunkMap.FindStringSubmatch(runtimeBody)
	if len(m) < 2 {
		return ""
	}
	for _, pair := range reWebpackChunkKV.FindAllStringSubmatch(m[1], -1) {
		if len(pair) == 3 && pair[1] == id {
			return pair[2]
		}
	}
	return ""
}

// Symbols pulls a small set of high-signal substrings from the body and
// returns them as a JSON object. The pg_trgm index covers this column so
// users can search by URL fragment, event name, IndexedDB store, etc., even
// when the minified function bodies are otherwise opaque.
func Symbols(body string) string {
	out := map[string][]string{
		"urls":           uniqueMatches(reURL, body, 16),
		"events":         uniqueMatches(reEventName, body, 32),
		"db_stores":      uniqueMatches(reIDBStore, body, 16),
		"ls_keys":        uniqueMatches(reLocalStorage, body, 16),
		"log_tags":       uniqueMatches(reBracketTag, body, 16),
		"wa_modules":     uniqueMatches(reWAWebRequire, body, 32),
		"json_endpoints": uniqueMatches(reAPIPath, body, 16),
		// Broader symbol density (defect 3): pull function decls, class names,
		// const/let bindings, method-shorthand, and exports.X assignments.
		// Cap each bucket so a single huge minified module can't blow up the
		// indexed search_text row.
		"functions": uniqueMatches(reFuncDecl, body, 80),
		"classes":   uniqueMatches(reClassDecl, body, 32),
		"consts":    uniqueMatches(reConstDecl, body, 80),
		"methods":   uniqueMatches(reMethodDecl, body, 80),
		"exports":   uniqueMatches(reExports, body, 32),
	}
	for k, v := range out {
		if len(v) == 0 {
			delete(out, k)
		}
	}
	if len(out) == 0 {
		return ""
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func uniqueMatches(re *regexp.Regexp, body string, max int) []string {
	all := re.FindAllStringSubmatch(body, -1)
	if len(all) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(all))
	out := make([]string, 0, len(all))
	for _, m := range all {
		if len(m) < 2 {
			continue
		}
		v := m[1]
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
		if len(out) >= max {
			break
		}
	}
	return out
}
