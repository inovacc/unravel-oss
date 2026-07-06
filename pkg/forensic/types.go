/*
Copyright (c) 2026 Security Research
*/
package forensic

// Report is the top-level forensic report for a single application.
type Report struct {
	AppID       string            `json:"app_id"`
	PackageName string            `json:"package_name"`
	AppName     string            `json:"app_name,omitempty"`
	Version     string            `json:"version,omitempty"`
	Size        int64             `json:"size"`
	Certificate *CertSummary      `json:"certificate,omitempty"`
	Manifest    *ManifestSummary  `json:"manifest,omitempty"`
	Network     *NetworkSummary   `json:"network"`
	Secrets     *SecretsSummary   `json:"secrets"`
	Telemetry   *TelemetrySummary `json:"telemetry"`
	CurlScripts []CurlScript      `json:"curl_scripts"`
	RiskScore   int               `json:"risk_score"`
	RiskLevel   string            `json:"risk_level"`
	Findings    []Finding         `json:"findings"`
}

// CertSummary holds certificate metadata.
type CertSummary struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	SHA256     string `json:"sha256"`
	SelfSigned bool   `json:"self_signed"`
	Expired    bool   `json:"expired"`
}

// ManifestSummary holds key manifest data.
type ManifestSummary struct {
	Package       string   `json:"package"`
	VersionName   string   `json:"version_name"`
	VersionCode   int      `json:"version_code"`
	MinSDK        int      `json:"min_sdk"`
	TargetSDK     int      `json:"target_sdk"`
	Permissions   []string `json:"permissions"`
	DangerousPerm []string `json:"dangerous_permissions"`
	Debuggable    bool     `json:"debuggable"`
	AllowBackup   bool     `json:"allow_backup"`
	CleartextOK   bool     `json:"cleartext_traffic"`
	ExportedComps int      `json:"exported_components"`
}

// NetworkSummary holds extracted network communication data.
type NetworkSummary struct {
	TotalEndpoints int           `json:"total_endpoints"`
	APIEndpoints   []APIEndpoint `json:"api_endpoints"`
	Domains        []string      `json:"domains"`
	HasCertPinning bool          `json:"has_cert_pinning"`
	HasCleartext   bool          `json:"has_cleartext"`
	Protocols      []string      `json:"protocols,omitempty"`
}

// APIEndpoint is a discovered API endpoint with metadata for curl replay.
type APIEndpoint struct {
	URL      string            `json:"url"`
	Host     string            `json:"host"`
	Path     string            `json:"path"`
	Scheme   string            `json:"scheme"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Category string            `json:"category"` // api, auth, oauth, webhook, cdn, analytics, etc.
}

// SecretsSummary holds extracted secrets data.
type SecretsSummary struct {
	TotalFindings  int             `json:"total_findings"`
	HighConfidence int             `json:"high_confidence"`
	Categories     map[string]int  `json:"categories"`
	TopFindings    []SecretFinding `json:"top_findings"`
}

// SecretFinding is a single high-confidence secret.
type SecretFinding struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	File       string `json:"file"`
	Confidence string `json:"confidence"`
}

// TelemetrySummary holds telemetry/SDK data.
type TelemetrySummary struct {
	SDKCount        int              `json:"sdk_count"`
	SDKs            []SDKInfo        `json:"sdks"`
	StealthFeatures []StealthFeature `json:"stealth_features,omitempty"`
	Categories      map[string]int   `json:"categories"`
}

// SDKInfo is a detected SDK/tracker.
type SDKInfo struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
}

// StealthFeature is a detected stealth capability.
type StealthFeature struct {
	Type        string `json:"type"`
	Component   string `json:"component"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// CurlScript is a generated curl command for replaying API communication.
type CurlScript struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"` // auth, api, analytics, oauth, push, etc.
	Command     string `json:"command"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Risk        string `json:"risk,omitempty"` // info, low, medium, high
}

// Finding is a forensic finding/observation.
type Finding struct {
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // info, low, medium, high, critical
	Evidence    string `json:"evidence,omitempty"`
}

// BatchReport holds results for multiple apps.
type BatchReport struct {
	TotalApps   int                 `json:"total_apps"`
	ReportDir   string              `json:"report_dir"`
	Apps        []Report            `json:"apps"`
	TopRisks    []Report            `json:"top_risks"`
	DomainIndex map[string][]string `json:"domain_index"` // domain → [app_ids]
	SDKIndex    map[string][]string `json:"sdk_index"`    // sdk → [app_ids]
}

// Options controls forensic report generation.
type Options struct {
	TeardownDir string // base teardown directory
	OutputDir   string // where to write reports
	Verbose     bool
	AIEnrich    bool // use Claude Code MCP to enrich findings
}
