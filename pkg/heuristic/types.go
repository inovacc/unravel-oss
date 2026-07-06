package heuristic

// Category classifies what kind of malicious behavior a pattern detects.
type Category string

const (
	CategoryNetwork     Category = "network"      // External connections, data exfiltration
	CategoryObfuscation Category = "obfuscation"  // Code obfuscation, encoding, packing
	CategoryExecution   Category = "execution"    // Dynamic code execution, shell commands
	CategoryDataAccess  Category = "data_access"  // Keylogging, clipboard, screen capture
	CategoryPersistence Category = "persistence"  // Auto-start, scheduled tasks, registry
	CategoryEvasion     Category = "evasion"      // Anti-debug, VM detection, sandbox escape
	CategoryCrypto      Category = "crypto"       // Crypto mining, wallet theft
	CategorySupplyChain Category = "supply_chain" // Install scripts, dependency confusion
)

// Severity indicates how dangerous a finding is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Pattern defines a single heuristic detection rule.
type Pattern struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Category    Category `yaml:"category"`
	Severity    Severity `yaml:"severity"`
	Weight      int      `yaml:"weight"`
	Patterns    []string `yaml:"patterns"`            // regex patterns
	Languages   []string `yaml:"languages,omitempty"` // empty = all
}

// Finding represents a single detected suspicious pattern.
type Finding struct {
	PatternID   string   `json:"pattern_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Weight      int      `json:"weight"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Evidence    string   `json:"evidence"`
	MatchedText string   `json:"matched_text"`
}

// CategorySummary summarizes findings for one category.
type CategorySummary struct {
	Category Category  `json:"category"`
	Count    int       `json:"count"`
	MaxSev   Severity  `json:"max_severity"`
	Score    int       `json:"score"`
	Findings []Finding `json:"findings"`
}

// Result holds the complete heuristic scan output.
type Result struct {
	TotalFindings int                           `json:"total_findings"`
	ThreatScore   int                           `json:"threat_score"`
	ThreatLevel   string                        `json:"threat_level"` // CLEAN, LOW, MEDIUM, HIGH, CRITICAL
	FilesScanned  int                           `json:"files_scanned"`
	Categories    map[Category]*CategorySummary `json:"categories"`
	TopFindings   []Finding                     `json:"top_findings"` // highest severity first
}
