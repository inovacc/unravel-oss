package langs

import "regexp"

// init registers C / C++ / header extensions. The split between "c" and
// "cpp" follows the file extension: .c/.h → "c"; .cpp/.cc/.cxx/.hpp → "cpp".
func init() {
	for _, ext := range []string{".c", ".h"} {
		Register(ext, "c", extractC)
	}
	for _, ext := range []string{".cpp", ".hpp", ".cc", ".cxx"} {
		Register(ext, "cpp", extractCPP)
	}
}

var (
	// Function definitions: a return type, a name, args, then "{" or newline.
	// Loose — tolerates pointers and qualifiers.
	cFuncRe = regexp.MustCompile(`(?m)^[\w*\s]+\s+(\w+)\s*\([^;{]*\)\s*\{`)
	// class / struct / enum / union — names that follow the keyword.
	cAggRe = regexp.MustCompile(`(?m)^(?:typedef\s+)?(?:class|struct|enum|union)\s+(\w+)`)
	// #include <foo> or #include "foo"
	cIncludeRe = regexp.MustCompile(`#include\s*[<"]([^>"\n]+)[>"]`)
	// #define FOO ...
	cDefineRe = regexp.MustCompile(`(?m)^#define\s+(\w+)`)
)

func extractC(path string, body []byte) (Module, error) {
	return regexExtract(path, body, "c", regexLangSpec{
		funcs:   []*regexp.Regexp{cFuncRe},
		classes: []*regexp.Regexp{cAggRe},
		consts:  []*regexp.Regexp{cDefineRe},
		imports: []*regexp.Regexp{cIncludeRe},
	})
}

func extractCPP(path string, body []byte) (Module, error) {
	return regexExtract(path, body, "cpp", regexLangSpec{
		funcs:   []*regexp.Regexp{cFuncRe},
		classes: []*regexp.Regexp{cAggRe},
		consts:  []*regexp.Regexp{cDefineRe},
		imports: []*regexp.Regexp{cIncludeRe},
	})
}
