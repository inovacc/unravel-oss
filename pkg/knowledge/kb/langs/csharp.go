package langs

import "regexp"

// init registers C# extension.
func init() {
	Register(".cs", "csharp", extractCS)
}

var (
	// Method definition: visibility/modifiers, return type, NAME, "(".
	// Excludes constructors? — actually constructors look the same; we
	// accept them.
	csMethodRe = regexp.MustCompile(`(?m)^\s*(?:\[[^\]]+\]\s*)*(?:public|private|internal|protected|static|virtual|override|async|sealed|abstract|\s)+\s+\S+\s+(\w+)\s*\(`)
	// class / interface / enum / struct / record
	csTypeRe = regexp.MustCompile(`(?m)^\s*(?:public|private|internal|protected|static|sealed|abstract|partial|\s)*\s*(?:class|interface|enum|struct|record)\s+(\w+)`)
	// using foo.bar; or using static foo.bar;
	csUsingRe = regexp.MustCompile(`(?m)^\s*using\s+(?:static\s+)?([\w.]+)\s*;`)
)

func extractCS(path string, body []byte) (Module, error) {
	return regexExtract(path, body, "csharp", regexLangSpec{
		funcs:   []*regexp.Regexp{csMethodRe},
		classes: []*regexp.Regexp{csTypeRe},
		imports: []*regexp.Regexp{csUsingRe},
	})
}
