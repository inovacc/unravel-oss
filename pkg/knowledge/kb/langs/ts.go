package langs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/jsdeob"
)

// init registers TypeScript extensions. Matches .ts and .tsx — the JSX
// variant is handled by the same regex extractor since we only care about
// top-level declaration names.
func init() {
	Register(".ts", "ts", extractTS)
	Register(".tsx", "ts", extractTS)
}

var (
	// matches: function NAME(, export function NAME(, async function NAME(
	tsFnRe = regexp.MustCompile(`(?m)^(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*[\(<]`)
	// matches: class NAME, export class NAME, abstract class NAME
	tsClassRe = regexp.MustCompile(`(?m)^(?:export\s+)?(?:abstract\s+)?class\s+(\w+)`)
	// matches: interface NAME, export interface NAME
	tsIfaceRe = regexp.MustCompile(`(?m)^(?:export\s+)?interface\s+(\w+)`)
	// matches: type NAME =
	tsTypeRe = regexp.MustCompile(`(?m)^(?:export\s+)?type\s+(\w+)\s*=`)
	// matches: const|let|var NAME = (top-level) — also export const NAME =
	tsConstRe = regexp.MustCompile(`(?m)^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*[:=]`)
	// matches: enum NAME
	tsEnumRe = regexp.MustCompile(`(?m)^(?:export\s+)?(?:const\s+)?enum\s+(\w+)`)
	// matches: import ... from "spec"
	tsImportRe = regexp.MustCompile(`import\s+[^'"\n;]*from\s+['"]([^'"]+)['"]`)
	// matches: import "side-effect"
	tsBareImportRe = regexp.MustCompile(`import\s+['"]([^'"]+)['"]`)
	// matches: require("spec")
	tsRequireRe = regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`)
)

// tsRegexSpec returns the regexLangSpec used by extractTS. Extracted so tests
// and extractTS share one definition (DRY).
func tsRegexSpec() regexLangSpec {
	return regexLangSpec{
		funcs:   []*regexp.Regexp{tsFnRe},
		classes: []*regexp.Regexp{tsClassRe, tsIfaceRe, tsTypeRe, tsEnumRe},
		consts:  []*regexp.Regexp{tsConstRe},
		imports: []*regexp.Regexp{tsImportRe, tsBareImportRe, tsRequireRe},
	}
}

func extractTS(path string, body []byte) (Module, error) {
	spec := tsRegexSpec()
	raw, err := regexExtract(path, body, "ts", spec)
	if err != nil {
		return raw, err
	}
	if looksMinified(body) && len(body) <= maxBeautifyBytes {
		func() {
			defer func() { _ = recover() }() // beautify is best-effort; never fail extraction
			be := []byte(jsdeob.Beautify(string(body)))
			if len(be) == 0 {
				return
			}
			bz, bErr := regexExtract(path, be, "ts", spec)
			if bErr == nil {
				raw = mergeSymbolModules(raw, bz)
			}
		}()
		return raw, nil
	}
	// non-minified: canonicalize through the same merge so output is stable
	return mergeSymbolModules(raw, Module{}), nil
}

// regexLangSpec is the per-language pattern bundle handed to regexExtract.
type regexLangSpec struct {
	funcs   []*regexp.Regexp
	classes []*regexp.Regexp // also covers interfaces, structs, enums, types
	consts  []*regexp.Regexp
	imports []*regexp.Regexp
}

// regexExtract is the shared regex-based extractor used by every non-Go
// language. It produces the same Module shape as extractGo.
func regexExtract(path string, body []byte, lang string, spec regexLangSpec) (Module, error) {
	const excerptCap = 4096
	excerpt := body
	if len(excerpt) > excerptCap {
		excerpt = excerpt[:excerptCap]
	}
	sum := sha256.Sum256(body)

	collect := func(res []*regexp.Regexp) []string {
		seen := map[string]struct{}{}
		var out []string
		for _, re := range res {
			for _, m := range re.FindAllSubmatch(body, -1) {
				if len(m) < 2 {
					continue
				}
				name := string(m[1])
				if name == "" {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				out = append(out, name)
				if len(out) >= symbolCap {
					return out
				}
			}
		}
		return out
	}

	funcs := collect(spec.funcs)
	types := collect(spec.classes)
	consts := collect(spec.consts)

	// Collect imports (deduped, no cap — usually small).
	importsSeen := map[string]struct{}{}
	var imports []string
	for _, re := range spec.imports {
		for _, m := range re.FindAllSubmatch(body, -1) {
			if len(m) < 2 {
				continue
			}
			p := strings.TrimSpace(string(m[1]))
			if p == "" {
				continue
			}
			if _, ok := importsSeen[p]; ok {
				continue
			}
			importsSeen[p] = struct{}{}
			imports = append(imports, p)
		}
	}

	symbolsObj := map[string][]string{}
	if len(funcs) > 0 {
		symbolsObj["functions"] = funcs
	}
	if len(types) > 0 {
		symbolsObj["types"] = types
	}
	if len(consts) > 0 {
		symbolsObj["consts"] = consts
	}
	if len(imports) > 0 {
		symbolsObj["imports"] = imports
	}
	var symbolsJSON string
	if len(symbolsObj) > 0 {
		raw, err := json.Marshal(symbolsObj)
		if err == nil {
			symbolsJSON = string(raw)
		}
	}

	// Name = parent_dir/basename relative-ish — use last two path segments
	// for stability across abs/rel paths.
	dir := filepath.Base(filepath.Dir(path))
	base := filepath.Base(path)
	name := base
	if dir != "" && dir != "." && dir != string(filepath.Separator) {
		name = dir + "/" + base
	}

	return Module{
		Name:        name,
		BodyExcerpt: string(excerpt),
		BodySHA256:  hex.EncodeToString(sum[:]),
		FullBody:    body,
		SymbolsJSON: symbolsJSON,
		Lang:        lang,
		Imports:     imports,
		Size:        len(body),
	}, nil
}
