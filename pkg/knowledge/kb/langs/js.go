package langs

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/jsdeob"
)

// maxBeautifyBytes is the size cap below which we attempt jsdeob.Beautify on
// minified input. 4 MiB keeps ingest bounded.
const maxBeautifyBytes = 4 << 20

// init registers JavaScript extensions. Reuses the TS regex bundle since
// JS is a syntactic subset for the things we extract (function/class
// declarations, top-level consts, import/require). The .ts patterns
// already tolerate the absence of type annotations.
func init() {
	for _, ext := range []string{".js", ".jsx", ".mjs", ".cjs"} {
		Register(ext, "js", extractJS)
	}
}

// jsClassRe is identical in shape to tsClassRe but without the abstract
// modifier — kept separate for clarity of intent.
var jsClassRe = regexp.MustCompile(`(?m)^(?:export\s+)?class\s+(\w+)`)

// jsRegexSpec returns the regexLangSpec used by extractJS. Extracted so tests
// and extractJS share one definition (DRY).
func jsRegexSpec() regexLangSpec {
	return regexLangSpec{
		funcs:   []*regexp.Regexp{tsFnRe},
		classes: []*regexp.Regexp{jsClassRe},
		consts:  []*regexp.Regexp{tsConstRe},
		imports: []*regexp.Regexp{tsImportRe, tsBareImportRe, tsRequireRe},
	}
}

func extractJS(path string, body []byte) (Module, error) {
	spec := jsRegexSpec()
	raw, err := regexExtract(path, body, "js", spec)
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
			bz, bErr := regexExtract(path, be, "js", spec)
			if bErr == nil {
				raw = mergeSymbolModules(raw, bz)
			}
		}()
		return raw, nil
	}
	// non-minified: canonicalize through the same merge so output is stable
	return mergeSymbolModules(raw, Module{}), nil
}
