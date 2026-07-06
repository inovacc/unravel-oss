// Package prompts is the embedded registry of operation prompts that
// `unravel knowledge` uses to drive Claude (or any other LLM) through
// the gap-resolution loop.
//
// Each prompt is a single .md file with YAML frontmatter delimited by
// "---" lines. The body that follows is the user-facing template — it
// can carry placeholders like {gap_prompt} or {evidence_json} which the
// caller substitutes before sending to the model.
//
// Frontmatter keys (all optional except `op`):
//
//	op             — operation identifier (must match the file name slug)
//	description    — one-line summary
//	language_hint  — "any", "go", "ts", ... (advisory only)
//	output_format  — "json", "text", "markdown"
//	schema         — raw schema string the model must conform to
//	max_tokens     — soft hint at expected response size
//
// New prompts are added by dropping a foo.md file next to prompts.go.
// The //go:embed directive in prompts.go picks them up automatically.
package prompts

// Frontmatter is the parsed YAML preamble attached to every prompt file.
type Frontmatter struct {
	Op           string `yaml:"op"`
	Description  string `yaml:"description"`
	LanguageHint string `yaml:"language_hint"`
	OutputFormat string `yaml:"output_format"`
	Schema       string `yaml:"schema"`
	MaxTokens    int    `yaml:"max_tokens"`
}

// Prompt is a fully-loaded prompt: its frontmatter plus the verbatim
// body string (with placeholders intact).
type Prompt struct {
	Frontmatter
	// Body is the markdown content following the closing "---" delimiter.
	// Trailing whitespace is preserved so callers can safely append.
	Body string
}

// Op constants — kept as strings rather than a typed enum so callers can
// pass user-supplied --op values directly into Get() without conversion.
const (
	OpSymbolSummarize = "symbol_summarize"
	OpTopicClassify   = "topic_classify"
	OpFactResolve     = "fact_resolve"
	OpDepResolve      = "dep_resolve"
	OpSecAudit        = "sec_audit"
	OpArchDescribe    = "arch_describe"
)
