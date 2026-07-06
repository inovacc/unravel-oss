package langs

import "regexp"

// init registers .zig.
func init() {
	Register(".zig", "zig", extractZig)
}

var (
	// pub fn name( ... or fn name(
	zigFnRe = regexp.MustCompile(`(?m)^\s*(?:pub\s+)?fn\s+(\w+)\s*\(`)
	// pub const Name = struct { ... or const Name = enum { ...
	zigTypeRe = regexp.MustCompile(`(?m)^\s*(?:pub\s+)?(?:const|var)\s+(\w+)\s*=\s*(?:struct|enum|union|opaque)\b`)
	// const Name = @import("spec");
	zigImportRe = regexp.MustCompile(`@import\(\s*"([^"]+)"\s*\)`)
	// @cImport(...) — capture as the literal token "@cImport"
	zigCImportRe = regexp.MustCompile(`(@cImport)\s*\(`)
)

func extractZig(path string, body []byte) (Module, error) {
	return regexExtract(path, body, "zig", regexLangSpec{
		funcs:   []*regexp.Regexp{zigFnRe},
		classes: []*regexp.Regexp{zigTypeRe},
		imports: []*regexp.Regexp{zigImportRe, zigCImportRe},
	})
}
