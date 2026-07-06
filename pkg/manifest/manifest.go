package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest represents the complete unravel configuration
type Manifest struct {
	Version     string                        `yaml:"version"`
	Name        string                        `yaml:"name"`
	Description string                        `yaml:"description"`
	Detection   []DetectionRule               `yaml:"detection"`
	VersionExt  map[string]VersionExtraction  `yaml:"version_extraction"`
	Extraction  map[string]ExtractionPipeline `yaml:"extraction"`
	Analysis    map[string]AnalysisConfig     `yaml:"analysis"`
	Stealth     StealthConfig                 `yaml:"stealth_detection"`
	Telemetry   TelemetryConfig               `yaml:"telemetry_detection"`
	API         APIConfig                     `yaml:"api_extraction"`
	RiskScoring RiskConfig                    `yaml:"risk_scoring"`
	Reporting   ReportConfig                  `yaml:"reporting"`
	Extension   ExtensionConfig               `yaml:"extension_analysis"`
}

// DetectionRule defines how to identify an app framework
type DetectionRule struct {
	Name        string         `yaml:"name"`
	DisplayName string         `yaml:"display_name"`
	Priority    int            `yaml:"priority"`
	Rules       DetectionRules `yaml:"rules"`
}

// DetectionRules contains the actual detection patterns
type DetectionRules struct {
	Files            []FileRule      `yaml:"files"`
	BinarySignatures []SignatureRule `yaml:"binary_signatures"`
	Threshold        int             `yaml:"threshold"`
}

// FileRule defines a file-based detection rule
type FileRule struct {
	Pattern      string `yaml:"pattern"`
	Required     bool   `yaml:"required"`
	Weight       int    `yaml:"weight"`
	ContentMatch string `yaml:"content_match,omitempty"`
}

// SignatureRule defines a binary signature pattern
type SignatureRule struct {
	Pattern string `yaml:"pattern"`
	Type    string `yaml:"type"` // "string" or "regex"
	Weight  int    `yaml:"weight"`
}

// VersionExtraction defines how to extract version info
type VersionExtraction struct {
	BinaryPatterns []VersionPattern `yaml:"binary_patterns"`
	PackageJSON    []JSONPath       `yaml:"package_json,omitempty"`
	ConfigJSON     []ConfigPath     `yaml:"config_json,omitempty"`
}

type VersionPattern struct {
	Regex string `yaml:"regex"`
	Group int    `yaml:"group"`
}

type JSONPath struct {
	Path string `yaml:"path"`
}

type ConfigPath struct {
	File string `yaml:"file"`
	Path string `yaml:"path"`
}

// ExtractionPipeline defines extraction steps for a framework
type ExtractionPipeline struct {
	Steps []ExtractionStep `yaml:"steps"`
}

type ExtractionStep struct {
	Name      string            `yaml:"name"`
	Tool      string            `yaml:"tool"`
	Condition string            `yaml:"condition,omitempty"`
	SkipFlag  string            `yaml:"skip_flag,omitempty"`
	Args      any               `yaml:"args"`
	Outputs   map[string]string `yaml:"outputs,omitempty"`
}

// AnalysisConfig defines security analysis rules
type AnalysisConfig struct {
	SecuritySettings     []SecuritySetting     `yaml:"security_settings"`
	IPCPatterns          []IPCPattern          `yaml:"ipc_patterns"`
	DangerousIPCKeywords []DangerousKeyword    `yaml:"dangerous_ipc_keywords"`
	DangerousPermissions []DangerousPermission `yaml:"dangerous_permissions,omitempty"`
}

type SecuritySetting struct {
	Name           string   `yaml:"name"`
	SearchPatterns []string `yaml:"search_patterns"`
	SecureValue    string   `yaml:"secure_value"`
	InsecureValue  string   `yaml:"insecure_value"`
	RiskIfInsecure string   `yaml:"risk_if_insecure"`
	Description    string   `yaml:"description"`
}

type IPCPattern struct {
	Pattern      string `yaml:"pattern"`
	Direction    string `yaml:"direction"`
	CaptureGroup int    `yaml:"capture_group"`
}

type DangerousKeyword struct {
	Keyword string `yaml:"keyword"`
	Risk    string `yaml:"risk"`
}

type DangerousPermission struct {
	Permission  string `yaml:"permission"`
	Risk        string `yaml:"risk"`
	Description string `yaml:"description"`
}

// StealthConfig defines stealth feature detection
type StealthConfig struct {
	Electron StealthPatterns `yaml:"electron"`
	Tauri    StealthPatterns `yaml:"tauri"`
}

type StealthPatterns struct {
	Patterns []StealthPattern `yaml:"patterns"`
}

type StealthPattern struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Patterns      []string `yaml:"patterns"`
	ACLPermission string   `yaml:"acl_permission,omitempty"`
	Risk          string   `yaml:"risk"`
}

// TelemetryConfig defines telemetry service detection
type TelemetryConfig struct {
	Services []TelemetryService `yaml:"services"`
}

type TelemetryService struct {
	Name     string   `yaml:"name"`
	Patterns []string `yaml:"patterns"`
	Category string   `yaml:"category"`
}

// APIConfig defines API endpoint extraction
type APIConfig struct {
	URLPatterns     []URLPattern     `yaml:"url_patterns"`
	Classifications []Classification `yaml:"classifications"`
}

type URLPattern struct {
	Pattern string   `yaml:"pattern"`
	Exclude []string `yaml:"exclude,omitempty"`
}

type Classification struct {
	Keywords []string `yaml:"keywords"`
	Purpose  string   `yaml:"purpose"`
}

// RiskConfig defines risk scoring
type RiskConfig struct {
	Weights    map[string]int `yaml:"weights"`
	Thresholds map[string]int `yaml:"thresholds"`
}

// ReportConfig defines reporting settings
type ReportConfig struct {
	SearchPaths    map[string][]string `yaml:"search_paths"`
	SensitiveFiles []SensitiveFile     `yaml:"sensitive_files"`
}

type SensitiveFile struct {
	Pattern string `yaml:"pattern"`
	Risk    string `yaml:"risk"`
	Reason  string `yaml:"reason"`
}

// ExtensionConfig defines browser extension analysis rules
type ExtensionConfig struct {
	DangerousPermissions []ExtPermissionRule `yaml:"dangerous_permissions"`
	SuspiciousPatterns   []SuspiciousPattern `yaml:"suspicious_patterns"`
	StealthPatterns      []StealthPattern    `yaml:"stealth_patterns"`
	CheatingKeywords     []string            `yaml:"cheating_keywords"`
}

// ExtPermissionRule classifies a browser extension permission by risk
type ExtPermissionRule struct {
	Permission  string `yaml:"permission"`
	Risk        string `yaml:"risk"`
	Description string `yaml:"description"`
}

// SuspiciousPattern defines a code pattern to search for in extensions
type SuspiciousPattern struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Patterns    []string `yaml:"patterns"`
	Risk        string   `yaml:"risk"`
}

// Load reads and parses a manifest file
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &m, nil
}

// LoadDefault loads the default manifest from the manifests directory
func LoadDefault() (*Manifest, error) {
	// Try relative to executable
	exe, err := os.Executable()
	if err == nil {
		path := filepath.Join(filepath.Dir(exe), "manifests", "default.yaml")
		if _, err := os.Stat(path); err == nil {
			return Load(path)
		}
	}

	// Try relative to working directory
	path := filepath.Join("manifests", "default.yaml")
	if _, err := os.Stat(path); err == nil {
		return Load(path)
	}

	return nil, fmt.Errorf("default manifest not found")
}

// Detector uses manifest rules to detect app type
type Detector struct {
	manifest *Manifest
	verbose  bool
}

// NewDetector creates a detector using the given manifest
func NewDetector(m *Manifest, verbose bool) *Detector {
	return &Detector{manifest: m, verbose: verbose}
}

// DetectionResult holds the detection outcome
type DetectionResult struct {
	Type        string
	DisplayName string
	Score       int
	Version     string
	Matches     []string
}

// Detect analyzes a path and returns the detected app type
func (d *Detector) Detect(appPath string) (*DetectionResult, error) {
	absPath, err := filepath.Abs(appPath)
	if err != nil {
		return nil, err
	}

	var (
		bestResult *DetectionResult
		bestScore  int
	)

	for _, rule := range d.manifest.Detection {
		score, matches := d.evaluateRule(absPath, rule)

		if d.verbose {
			fmt.Printf("[DETECT] %s: score=%d (threshold=%d)\n", rule.Name, score, rule.Rules.Threshold)
		}

		if score >= rule.Rules.Threshold && score > bestScore {
			bestScore = score
			bestResult = &DetectionResult{
				Type:        rule.Name,
				DisplayName: rule.DisplayName,
				Score:       score,
				Matches:     matches,
			}
		}
	}

	if bestResult == nil {
		return &DetectionResult{Type: "unknown", DisplayName: "Unknown"}, nil
	}

	if vExt, ok := d.manifest.VersionExt[bestResult.Type]; ok {
		bestResult.Version = d.extractVersion(absPath, vExt)
	}

	return bestResult, nil
}

func (d *Detector) evaluateRule(appPath string, rule DetectionRule) (int, []string) {
	score := 0

	var matches []string

	for _, fileRule := range rule.Rules.Files {
		found, match := d.checkFileRule(appPath, fileRule)
		if found {
			score += fileRule.Weight

			matches = append(matches, match)

			if d.verbose {
				fmt.Printf("  [FILE] %s: +%d\n", fileRule.Pattern, fileRule.Weight)
			}
		}
	}

	binaryData := d.readBinaryData(appPath)
	if len(binaryData) > 0 {
		for _, sigRule := range rule.Rules.BinarySignatures {
			if d.checkSignature(binaryData, sigRule) {
				score += sigRule.Weight

				matches = append(matches, "binary:"+sigRule.Pattern)
				if d.verbose {
					fmt.Printf("  [SIG] %s: +%d\n", sigRule.Pattern, sigRule.Weight)
				}
			}
		}
	}

	return score, matches
}

func (d *Detector) checkFileRule(appPath string, rule FileRule) (bool, string) {
	pattern := filepath.Join(appPath, rule.Pattern)

	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return false, ""
	}

	if rule.ContentMatch != "" {
		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			if strings.Contains(string(content), rule.ContentMatch) {
				return true, match
			}
		}

		return false, ""
	}

	return true, matches[0]
}

func (d *Detector) readBinaryData(appPath string) []byte {
	info, err := os.Stat(appPath)
	if err != nil {
		return nil
	}

	var binaryPath string

	if info.IsDir() {
		binaryPath = findMainBinary(appPath)
	} else {
		binaryPath = appPath
	}

	if binaryPath == "" {
		return nil
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil
	}

	limit := 50 * 1024 * 1024
	if len(data) > limit {
		data = data[:limit]
	}

	return data
}

// findMainBinary locates the primary executable in an app directory.
// It picks the largest ELF/Mach-O binary (the main Electron binary is always the biggest).
// Searches the directory itself and one level of subdirectories. Also checks parent
// directory as a fallback for cases like VS Code where detection matches resources/app.
func findMainBinary(appPath string) string {
	// Windows .exe
	if matches, _ := filepath.Glob(filepath.Join(appPath, "*.exe")); len(matches) > 0 {
		return matches[0]
	}

	// Search appPath and one level of subdirs for the largest native binary
	if best := largestNativeBinary(appPath, 1); best != "" {
		return best
	}

	// Fallback: check parent directory (e.g. detection matched resources/app but binary is in ..)
	parent := filepath.Dir(appPath)
	if parent != appPath {
		if best := largestNativeBinary(parent, 0); best != "" {
			return best
		}
	}

	// Last resort: app.asar
	asarPath := filepath.Join(appPath, "resources", "app.asar")
	if _, err := os.Stat(asarPath); err == nil {
		return asarPath
	}

	return ""
}

// largestNativeBinary finds the biggest ELF/Mach-O executable in dir,
// optionally searching subdirectories up to depth levels deep.
func largestNativeBinary(dir string, depth int) string {
	var bestPath string
	var bestSize int64

	scanDir := func(d string) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			if filepath.Ext(e.Name()) != "" {
				continue
			}

			info, err := e.Info()
			if err != nil || info.Size() < 1024 {
				continue
			}

			if info.Mode()&0111 == 0 {
				continue
			}

			path := filepath.Join(d, e.Name())

			if !isNativeBinary(path) {
				continue
			}

			if info.Size() > bestSize {
				bestSize = info.Size()
				bestPath = path
			}
		}
	}

	scanDir(dir)

	if depth > 0 {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				if strings.HasPrefix(e.Name(), ".") {
					continue
				}
				scanDir(filepath.Join(dir, e.Name()))
			}
		}
	}

	return bestPath
}

func isNativeBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}

	magic := make([]byte, 4)
	_, err = f.Read(magic)
	_ = f.Close()

	if err != nil {
		return false
	}

	isELF := magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
	isMachO := (magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa) ||
		(magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed)

	return isELF || isMachO
}

func (d *Detector) checkSignature(data []byte, rule SignatureRule) bool {
	switch rule.Type {
	case "regex":
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return false
		}

		return re.Match(data)
	default:
		return strings.Contains(string(data), rule.Pattern)
	}
}

func (d *Detector) extractVersion(appPath string, ext VersionExtraction) string {
	data := d.readBinaryData(appPath)
	if len(data) > 0 {
		for _, vp := range ext.BinaryPatterns {
			re, err := regexp.Compile(vp.Regex)
			if err != nil {
				continue
			}

			matches := re.FindSubmatch(data)
			if len(matches) > vp.Group {
				return string(matches[vp.Group])
			}
		}
	}

	return ""
}

// ExpandVariables replaces ${VAR} placeholders in a string
func ExpandVariables(s string, vars map[string]string) string {
	result := s
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
	}

	return result
}

// EvaluateCondition checks if a condition is met
func EvaluateCondition(condition string, vars map[string]string) bool {
	if condition == "" {
		return true
	}

	expanded := ExpandVariables(condition, vars)

	if after, ok := strings.CutPrefix(expanded, "file_exists:"); ok {
		path := after
		_, err := os.Stat(path)

		return err == nil
	}

	if after, ok := strings.CutPrefix(expanded, "dir_exists:"); ok {
		path := after
		info, err := os.Stat(path)

		return err == nil && info.IsDir()
	}

	return true
}

// Default returns a built-in fallback manifest for when no YAML file is available.
func Default() *Manifest {
	return &Manifest{
		Version:     "1.0",
		Name:        "Built-in Default",
		Description: "Fallback manifest",
		Detection: []DetectionRule{
			{Name: "electron", DisplayName: "Electron", Priority: 10, Rules: DetectionRules{
				Files:            []FileRule{{Pattern: "resources/app.asar", Weight: 100}},
				BinarySignatures: []SignatureRule{{Pattern: "Electron Framework", Type: "string", Weight: 100}},
				Threshold:        50,
			}},
			{Name: "tauri", DisplayName: "Tauri", Priority: 20, Rules: DetectionRules{
				BinarySignatures: []SignatureRule{{Pattern: "tauri::", Type: "string", Weight: 100}},
				Threshold:        50,
			}},
		},
		Analysis: map[string]AnalysisConfig{
			"electron": {
				SecuritySettings: []SecuritySetting{
					{Name: "nodeIntegration", SearchPatterns: []string{`nodeIntegration:\s*(true|false)`}, SecureValue: "false", InsecureValue: "true", RiskIfInsecure: "CRITICAL", Description: "Allows Node.js in renderer"},
					{Name: "contextIsolation", SearchPatterns: []string{`contextIsolation:\s*(true|false)`}, SecureValue: "true", InsecureValue: "false", RiskIfInsecure: "HIGH", Description: "Isolates preload scripts"},
					{Name: "sandbox", SearchPatterns: []string{`sandbox:\s*(true|false)`}, SecureValue: "true", InsecureValue: "false", RiskIfInsecure: "MEDIUM", Description: "Chromium sandbox"},
				},
				IPCPatterns:          []IPCPattern{{Pattern: `ipcMain\.handle\s*\(\s*["']([^"']+)["']`, Direction: "main", CaptureGroup: 1}},
				DangerousIPCKeywords: []DangerousKeyword{{Keyword: "exec", Risk: "CRITICAL"}, {Keyword: "shell", Risk: "CRITICAL"}},
			},
		},
		Stealth: StealthConfig{
			Electron: StealthPatterns{
				Patterns: []StealthPattern{
					{Name: "Content Protection", Description: "Hidden from screen capture", Patterns: []string{`setContentProtection\s*\(\s*true`}, Risk: "HIGH"},
				},
			},
		},
		Telemetry: TelemetryConfig{
			Services: []TelemetryService{
				{Name: "Sentry", Patterns: []string{"sentry.io"}, Category: "error_tracking"},
				{Name: "Segment", Patterns: []string{"segment.io"}, Category: "analytics"},
			},
		},
		API: APIConfig{
			URLPatterns:     []URLPattern{{Pattern: `https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+`, Exclude: []string{"localhost"}}},
			Classifications: []Classification{{Keywords: []string{"api"}, Purpose: "API"}},
		},
		RiskScoring: RiskConfig{
			Weights:    map[string]int{"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 2},
			Thresholds: map[string]int{"CRITICAL": 100, "HIGH": 50, "MEDIUM": 20, "LOW": 0},
		},
	}
}
