package langs

// init pre-registers a handful of common text-source extensions to the
// generic extractor so the walker reports them with a usable language
// tag instead of the empty fallback. Behavior is otherwise identical
// to DefaultExtractor — no syntactic parsing happens here.
//
// More precise extractors (e.g. .py via go/python's compiler.ast, .rs
// via syn, etc.) are future work; for v1 the JS extension set still
// routes through the existing kbscan pipeline at the call site, not
// through this registry.
func init() {
	for _, x := range []struct {
		ext, lang string
	}{
		{".md", "markdown"},
		{".yaml", "yaml"},
		{".yml", "yaml"},
		{".toml", "toml"},
		{".json", "json"},
		{".sql", "sql"},
		{".sh", "shell"},
		{".py", "python"},
		{".rs", "rust"},
		{".java", "java"},
	} {
		Register(x.ext, x.lang, func(path string, body []byte) (Module, error) {
			m, err := DefaultExtractor(path, body)
			if err == nil {
				m.Lang = x.lang
			}
			return m, err
		})
	}
}
