/*
Copyright (c) 2026 Security Research
*/
package css

// Source constants identify where a stylesheet was discovered.
const (
	SourceFile       = "file"
	SourceHTMLStyle  = "html-style"
	SourceHTMLInline = "html-inline"
	SourceCSSInJS    = "css-in-js"
)

// Options controls CSS extraction behavior.
type Options struct {
	OutputDir        string   `json:"output_dir"`
	ResolveImports   bool     `json:"resolve_imports"`
	Normalize        bool     `json:"normalize"`
	Deduplicate      bool     `json:"deduplicate"`
	ResolveVars      bool     `json:"resolve_vars"`
	RemoveUnused     bool     `json:"remove_unused"`
	IncludeSourceMap bool     `json:"include_source_map"`
	HTMLFiles        []string `json:"html_files"`
	NodeModulesPath  string   `json:"node_modules_path"`
	Verbose          bool     `json:"verbose"`
	NoCache          bool     `json:"no_cache"`
}

// Result holds the complete CSS extraction output.
type Result struct {
	Stylesheets []Stylesheet        `json:"stylesheets"`
	Components  []Component         `json:"components"`
	ImportGraph map[string][]string `json:"import_graph"`
	Stats       ExtractionStats     `json:"stats"`
	Errors      []string            `json:"errors"`
	OutputDir   string              `json:"output_dir"`
}

// Stylesheet represents a single discovered CSS source.
type Stylesheet struct {
	Path         string `json:"path"`
	OutputPath   string `json:"output_path"`
	Source       string `json:"source"`
	Content      []byte `json:"-"`
	OriginalSize int64  `json:"original_size"`
	CleanedSize  int64  `json:"cleaned_size"`
	RuleCount    int    `json:"rule_count"`
	Component    string `json:"component"`
}

// Component groups stylesheets that belong to the same UI component.
type Component struct {
	Name        string       `json:"name"`
	Dir         string       `json:"dir"`
	Stylesheets []Stylesheet `json:"stylesheets"`
}

// ExtractionStats tracks metrics about the extraction process.
type ExtractionStats struct {
	TotalFiles        int `json:"total_files"`
	CSSFiles          int `json:"css_files"`
	HTMLFiles         int `json:"html_files"`
	JSFiles           int `json:"js_files"`
	CSSInJSFound      int `json:"css_in_js_found"`
	ImportsResolved   int `json:"imports_resolved"`
	RulesRemovedDedup int `json:"rules_removed_dedup"`
	UnusedRemoved     int `json:"unused_removed"`
	ComponentCount    int `json:"component_count"`
}
