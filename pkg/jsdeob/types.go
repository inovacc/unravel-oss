package jsdeob

// Options configures the deobfuscation process
type Options struct {
	Beautify          bool
	DecodeStrings     bool
	UnpackPacked      bool
	SimplifyMath      bool
	RenameVars        bool
	ExtractStrings    bool
	Verbose           bool
	StripBundlerCruft bool // Phase 11 enhancement: strip webpack/esbuild runtime boilerplate
}

// Result contains the deobfuscation output
type Result struct {
	Code            string
	ExtractedURLs   []string
	ExtractedStrs   []string
	Transformations []string
}
