/*
Copyright (c) 2026 Security Research

Package regressions provides Severity classification for KB-diff results.

The package owns the rule schema (Rubric/Rule/Match), the typed snapshot
shapes consumed by Classify (so that pkg/knowledge can construct them
without importing back into us), and the regression vocabulary
(BLOCK | FLAG | PASS).

The single source of truth for the default rubric is the embedded
kb-regressions.yaml — the Go layer is intentionally a thin parser.
*/
package regressions

// Severity vocabulary.
const (
	SeverityBlock = "BLOCK"
	SeverityFlag  = "FLAG"
	SeverityPass  = "PASS"
)

// Dimension vocabulary.
const (
	DimPermissions    = "permissions"
	DimSecurityConfig = "security_config"
	DimStructural     = "structural"
	DimText           = "text"
)

// Source vocabulary — distinguishes where a regression came from.
const (
	SourceHardcoded = "hardcoded"
	SourceRubric    = "rubric"
	SourceAI        = "ai"
)

// Rubric is the YAML-decoded rule list.
type Rubric struct {
	SchemaVersion int    `yaml:"schema_version"`
	Rules         []Rule `yaml:"rules"`
}

// Rule is a single regression rule.
type Rule struct {
	ID        string `yaml:"id"`
	Dimension string `yaml:"dimension"`
	Severity  string `yaml:"severity"`
	Match     Match  `yaml:"match"`
	// Source is set during merge — "hardcoded" for embedded defaults,
	// "rubric" for user-overridden or user-added rules.
	Source string `yaml:"-"`
}

// Match is the rule predicate.
type Match struct {
	Key       string `yaml:"key"`
	Condition string `yaml:"condition"`
	Value     string `yaml:"value,omitempty"`
}

// Regression is a single classified delta.
type Regression struct {
	RuleID    string   `json:"rule_id"`
	Dimension string   `json:"dimension"`
	Severity  string   `json:"severity"`
	Source    string   `json:"source"`
	Message   string   `json:"message"`
	Evidence  []string `json:"evidence,omitempty"`
}

// AndroidPermission is the smallest shape the regressions package needs to
// reason about Android permission deltas.
type AndroidPermission struct {
	Name      string `json:"name"`
	Dangerous bool   `json:"dangerous"`
}

// ValueChange records the prior and new value of a security setting.
type ValueChange struct {
	Old any `json:"old"`
	New any `json:"new"`
}

// Permissions is the typed permissions delta.
type Permissions struct {
	AndroidAdded   []AndroidPermission `json:"android_added,omitempty"`
	AndroidRemoved []AndroidPermission `json:"android_removed,omitempty"`
	AppXAdded      []string            `json:"appx_added,omitempty"`
	ChromeAdded    []string            `json:"chrome_added,omitempty"`
}

// SecurityConfig is the typed security-config delta.
type SecurityConfig struct {
	CSPAdditions       []string               `json:"csp_additions,omitempty"`
	CSPRemovals        []string               `json:"csp_removals,omitempty"`
	WebPrefsChanged    map[string]ValueChange `json:"web_prefs_changed,omitempty"`
	CertPinningRemoved bool                   `json:"cert_pinning_removed,omitempty"`
}

// Structural is the typed structural delta.
type Structural struct {
	ModulesAdded      []string `json:"modules_added,omitempty"`
	ModulesRemoved    []string `json:"modules_removed,omitempty"`
	EndpointsAdded    []string `json:"endpoints_added,omitempty"`
	TelemetryAdded    []string `json:"telemetry_added,omitempty"`
	TelemetryCountOld int      `json:"telemetry_count_old"`
	TelemetryCountNew int      `json:"telemetry_count_new"`
	EndpointsCountOld int      `json:"endpoints_count_old"`
	EndpointsCountNew int      `json:"endpoints_count_new"`
}

// TextEquivalence is the typed text-equivalence delta.
type TextEquivalence struct {
	ModulesEquivalent []string `json:"modules_equivalent,omitempty"`
	ModulesChanged    []string `json:"modules_changed,omitempty"`
	Bypassed          []string `json:"bypassed_large_input,omitempty"`
}

// Snapshot is the typed view of a DiffResult that Classify consumes.
//
// pkg/knowledge.DiffResult implements this implicitly by exposing pointers
// to the four typed dimensions — using a struct (not an interface) keeps the
// dependency direction one-way (knowledge -> regressions) and lets us
// evolve the dimensions without touching consumers.
type Snapshot struct {
	Permissions     *Permissions
	SecurityConfig  *SecurityConfig
	Structural      *Structural
	TextEquivalence *TextEquivalence
}
