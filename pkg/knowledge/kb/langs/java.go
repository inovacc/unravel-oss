package langs

import "regexp"

// init registers .java. Overrides the generic-text registration that
// generic.go's init() seeds — Register is last-writer-wins and Go runs
// init() in lexical filename order, so this file's init() runs after
// generic.go's.
func init() {
	Register(".java", "java", extractJava)
}

var (
	// Method definitions: modifiers, then a type chunk (with optional
	// generics), then NAME, then "(". Java requires an explicit return
	// type so we keep the regex tight.
	javaMethodRe = regexp.MustCompile(`(?m)^\s*(?:@\w+\s+)*(?:public|private|protected|static|final|abstract|synchronized|native|\s)+[\w<>\[\],\s\.]+\s+(\w+)\s*\(`)
	// class / interface / enum / record
	javaTypeRe = regexp.MustCompile(`(?m)^\s*(?:public|private|protected|static|final|abstract|sealed|\s)*\s*(?:class|interface|enum|record)\s+(\w+)`)
	// import a.b.c; or import static a.b.c.Foo;
	javaImportRe = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([\w.]+)\s*;`)
)

func extractJava(path string, body []byte) (Module, error) {
	return regexExtract(path, body, "java", regexLangSpec{
		funcs:   []*regexp.Regexp{javaMethodRe},
		classes: []*regexp.Regexp{javaTypeRe},
		imports: []*regexp.Regexp{javaImportRe},
	})
}
