/*
Copyright © 2026 Security Research
*/
package extension

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/inovacc/unravel-oss/pkg/manifest"
	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// readManifestBounded reads a manifest.json (or similar small extension file)
// with a size cap, so a hostile multi-hundred-MiB manifest cannot OOM the host
// via os.ReadFile + json.Unmarshal into map[string]any. It stats first to fail
// fast, then reads through a bounded reader as defense against TOCTOU growth.
func readManifestBounded(path string) ([]byte, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxExtensionReadSize {
		return nil, fmt.Errorf("manifest %s size %d exceeds %d-byte cap", path, fi.Size(), maxExtensionReadSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return safeio.ReadAllLimit(f, maxExtensionReadSize)
}

// BrowserProfile represents a discovered browser profile with extensions
type BrowserProfile struct {
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
	Path     string `json:"path"`
	ExtDir   string `json:"ext_dir"`
	ExtCount int    `json:"ext_count"`
}

// ChromeManifest represents a parsed extension manifest.json (V2 and V3)
type ChromeManifest struct {
	ManifestVersion int               `json:"manifest_version"`
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	DefaultLocale   string            `json:"default_locale,omitempty"`
	Permissions     []any             `json:"permissions,omitempty"`
	OptPermissions  []any             `json:"optional_permissions,omitempty"`
	HostPermissions []string          `json:"host_permissions,omitempty"`
	Background      map[string]any    `json:"background,omitempty"`
	ContentScripts  []ContentScript   `json:"content_scripts,omitempty"`
	WebAccessible   any               `json:"web_accessible_resources,omitempty"`
	ExternallyConn  any               `json:"externally_connectable,omitempty"`
	Icons           map[string]string `json:"icons,omitempty"`
	Action          map[string]any    `json:"action,omitempty"`
	BrowserAction   map[string]any    `json:"browser_action,omitempty"`
}

// ContentScript represents a content script entry
type ContentScript struct {
	Matches []string `json:"matches,omitempty"`
	JS      []string `json:"js,omitempty"`
	CSS     []string `json:"css,omitempty"`
	RunAt   string   `json:"run_at,omitempty"`
}

// ExtensionInfo holds parsed and analyzed information about a single extension
type ExtensionInfo struct {
	ID                      string             `json:"id"`
	Name                    string             `json:"name"`
	Version                 string             `json:"version"`
	Description             string             `json:"description"`
	ManifestVer             int                `json:"manifest_version"`
	ManifestPath            string             `json:"manifest_path,omitempty"`
	Path                    string             `json:"path"`
	Browser                 string             `json:"browser"`
	Profile                 string             `json:"profile"`
	SourceType              string             `json:"source_type,omitempty"`
	Permissions             PermissionAnalysis `json:"permissions"`
	OptionalPermissions     []string           `json:"optional_permissions,omitempty"`
	ContentScripts          []ContentScript    `json:"content_scripts,omitempty"`
	BackgroundScripts       []string           `json:"background_scripts,omitempty"`
	BackgroundServiceWorker string             `json:"background_service_worker,omitempty"`
	WebAccessibleResources  []string           `json:"web_accessible_resources,omitempty"`
	ExternallyConnectable   []string           `json:"externally_connectable,omitempty"`
	ScriptFiles             []string           `json:"script_files,omitempty"`
	NativeMessagingHosts    []string           `json:"native_messaging_hosts,omitempty"`
	WebSocketEndpoints      []string           `json:"websocket_endpoints,omitempty"`
	URLEndpoints            []string           `json:"url_endpoints,omitempty"`
	FileStats               ExtensionFileStats `json:"file_stats"`
	CodeFindings            []CodeFinding      `json:"code_findings,omitempty"`
	StealthFlags            []StealthFinding   `json:"stealth_flags,omitempty"`
	CheatingFlags           []string           `json:"cheating_flags,omitempty"`
	RiskScore               int                `json:"risk_score"`
	RiskLevel               string             `json:"risk_level"`
}

// ExtensionFileStats contains simple inventory metadata for extension files.
type ExtensionFileStats struct {
	TotalFiles      int   `json:"total_files"`
	JavaScriptFiles int   `json:"javascript_files"`
	JSONFiles       int   `json:"json_files"`
	HTMLFiles       int   `json:"html_files"`
	CSSFiles        int   `json:"css_files"`
	TotalBytes      int64 `json:"total_bytes"`
}

// PermissionAnalysis categorizes extension permissions by risk
type PermissionAnalysis struct {
	All      []string            `json:"all"`
	ByRisk   map[string][]string `json:"by_risk"`
	Hosts    []string            `json:"hosts,omitempty"`
	Critical int                 `json:"critical_count"`
	High     int                 `json:"high_count"`
	Medium   int                 `json:"medium_count"`
	Low      int                 `json:"low_count"`
	Unknown  int                 `json:"unknown_count"`
}

// CodeFinding represents a suspicious pattern found in source code
type CodeFinding struct {
	Pattern      string `json:"pattern"`
	Description  string `json:"description"`
	File         string `json:"file"`
	Line         int    `json:"line,omitempty"`
	Context      string `json:"context,omitempty"`
	Risk         string `json:"risk"`
	InFilterList bool   `json:"in_filter_list,omitempty"`
}

// StealthFinding represents a stealth-related pattern found
type StealthFinding struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	File        string `json:"file,omitempty"`
	Risk        string `json:"risk"`
}

// ScanResult holds the result of scanning all extensions
type ScanResult struct {
	Browsers    []BrowserProfile `json:"browsers"`
	Extensions  []ExtensionInfo  `json:"extensions"`
	TotalExts   int              `json:"total_extensions"`
	RiskSummary map[string]int   `json:"risk_summary"`
}

// SearchResult holds results of cross-extension pattern search
type SearchResult struct {
	Pattern string        `json:"pattern"`
	Matches []SearchMatch `json:"matches"`
	Total   int           `json:"total_matches"`
}

// SearchMatch is a single match in the search results
type SearchMatch struct {
	Extension string `json:"extension"`
	Browser   string `json:"browser"`
	Profile   string `json:"profile"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Context   string `json:"context"`
}

// browserDef defines a browser's extension directory paths per OS
type browserDef struct {
	Name    string
	Windows []string
	Darwin  []string
	Linux   []string
}

var knownBrowsers = []browserDef{
	{
		Name:    "chrome",
		Windows: []string{filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data")},
		Darwin:  []string{filepath.Join(homeDir(), "Library", "Application Support", "Google", "Chrome")},
		Linux:   []string{filepath.Join(homeDir(), ".config", "google-chrome")},
	},
	{
		Name:    "edge",
		Windows: []string{filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data")},
		Darwin:  []string{filepath.Join(homeDir(), "Library", "Application Support", "Microsoft Edge")},
		Linux:   []string{filepath.Join(homeDir(), ".config", "microsoft-edge")},
	},
	{
		Name:    "brave",
		Windows: []string{filepath.Join(os.Getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data")},
		Darwin:  []string{filepath.Join(homeDir(), "Library", "Application Support", "BraveSoftware", "Brave-Browser")},
		Linux:   []string{filepath.Join(homeDir(), ".config", "BraveSoftware", "Brave-Browser")},
	},
	{
		Name:    "opera",
		Windows: []string{filepath.Join(os.Getenv("APPDATA"), "Opera Software", "Opera Stable")},
		Darwin:  []string{filepath.Join(homeDir(), "Library", "Application Support", "com.operasoftware.Opera")},
		Linux:   []string{filepath.Join(homeDir(), ".config", "opera")},
	},
	{
		Name:    "vivaldi",
		Windows: []string{filepath.Join(os.Getenv("LOCALAPPDATA"), "Vivaldi", "User Data")},
		Darwin:  []string{filepath.Join(homeDir(), "Library", "Application Support", "Vivaldi")},
		Linux:   []string{filepath.Join(homeDir(), ".config", "vivaldi")},
	},
	{
		Name:    "chromium",
		Windows: []string{filepath.Join(os.Getenv("LOCALAPPDATA"), "Chromium", "User Data")},
		Darwin:  []string{filepath.Join(homeDir(), "Library", "Application Support", "Chromium")},
		Linux:   []string{filepath.Join(homeDir(), ".config", "chromium")},
	},
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return home
}

// DiscoverBrowsers finds all Chromium-based browser profiles with extensions
func DiscoverBrowsers(filterBrowser string) []BrowserProfile {
	var profiles []BrowserProfile

	for _, b := range knownBrowsers {
		if filterBrowser != "" && !strings.EqualFold(b.Name, filterBrowser) {
			continue
		}

		var basePaths []string

		switch runtime.GOOS {
		case "windows":
			basePaths = b.Windows
		case "darwin":
			basePaths = b.Darwin
		default:
			basePaths = b.Linux
		}

		for _, basePath := range basePaths {
			if basePath == "" {
				continue
			}

			if _, err := os.Stat(basePath); err != nil {
				continue
			}

			// Find profiles: Default, Profile 1, Profile 2, etc.
			profileNames := discoverProfiles(basePath)
			for _, profileName := range profileNames {
				extDir := filepath.Join(basePath, profileName, "Extensions")
				if _, err := os.Stat(extDir); err != nil {
					continue
				}

				extCount := countExtensions(extDir)
				if extCount == 0 {
					continue
				}

				profiles = append(profiles, BrowserProfile{
					Browser:  b.Name,
					Profile:  profileName,
					Path:     filepath.Join(basePath, profileName),
					ExtDir:   extDir,
					ExtCount: extCount,
				})
			}
		}
	}

	return profiles
}

func discoverProfiles(basePath string) []string {
	var profiles []string

	// Check "Default"
	if _, err := os.Stat(filepath.Join(basePath, "Default")); err == nil {
		profiles = append(profiles, "Default")
	}

	// Check "Profile N"
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return profiles
	}

	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "Profile ") {
			profiles = append(profiles, e.Name())
		}
	}

	// Opera uses the base directory itself (no profile subfolder)
	if len(profiles) == 0 {
		extDir := filepath.Join(basePath, "Extensions")
		if _, err := os.Stat(extDir); err == nil {
			profiles = append(profiles, ".")
		}
	}

	return profiles
}

func countExtensions(extDir string) int {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return 0
	}

	count := 0

	for _, e := range entries {
		if e.IsDir() && e.Name() != "Temp" {
			count++
		}
	}

	return count
}

// ParseExtension reads and parses an extension from its directory
func ParseExtension(extPath, extID, browser, profile string) (*ExtensionInfo, error) {
	// Extensions are usually stored as extDir/<id>/<version>/manifest.json, but
	// we also support paths where manifest.json is directly in extPath.
	versionDir, err := findLatestVersion(extPath)
	if err != nil {
		return nil, fmt.Errorf("no version directory found: %w", err)
	}

	manifestPath := filepath.Join(versionDir, "manifest.json")

	data, err := readManifestBounded(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest.json: %w", err)
	}

	var cm ChromeManifest
	if err := json.Unmarshal(data, &cm); err != nil {
		return nil, fmt.Errorf("failed to parse manifest.json: %w", err)
	}

	info := &ExtensionInfo{
		ID:                      extID,
		Name:                    resolveLocaleMessage(cm.Name, versionDir, cm.DefaultLocale),
		Version:                 cm.Version,
		Description:             resolveLocaleMessage(cm.Description, versionDir, cm.DefaultLocale),
		ManifestVer:             cm.ManifestVersion,
		ManifestPath:            manifestPath,
		Path:                    versionDir,
		Browser:                 browser,
		Profile:                 profile,
		ContentScripts:          cm.ContentScripts,
		OptionalPermissions:     normalizeOptionalPermissions(cm),
		BackgroundScripts:       extractBackgroundScripts(cm),
		BackgroundServiceWorker: extractBackgroundServiceWorker(cm),
		WebAccessibleResources:  normalizeWebAccessibleResources(cm.WebAccessible),
		ExternallyConnectable:   normalizeExternallyConnectable(cm.ExternallyConn),
	}

	// Normalize permissions (V2 puts host patterns in permissions, V3 uses host_permissions)
	info.Permissions.All = normalizePermissions(cm)
	info.Permissions.Hosts = extractHosts(cm)

	return info, nil
}

func findLatestVersion(extPath string) (string, error) {
	manifestPath := filepath.Join(extPath, "manifest.json")
	if fi, err := os.Stat(manifestPath); err == nil && !fi.IsDir() {
		return extPath, nil
	}

	entries, err := os.ReadDir(extPath)
	if err != nil {
		return "", err
	}

	var latest string

	for _, e := range entries {
		if e.IsDir() && e.Name() != "Temp" && e.Name() != "_metadata" {
			latest = filepath.Join(extPath, e.Name())
		}
	}

	if latest == "" {
		manifestDir, findErr := findManifestDir(extPath)
		if findErr == nil {
			return manifestDir, nil
		}

		return "", fmt.Errorf("no version directory in %s", extPath)
	}

	latestManifest := filepath.Join(latest, "manifest.json")
	if fi, err := os.Stat(latestManifest); err == nil && !fi.IsDir() {
		return latest, nil
	}

	manifestDir, findErr := findManifestDir(latest)
	if findErr == nil {
		return manifestDir, nil
	}

	return latest, nil
}

func normalizePermissions(cm ChromeManifest) []string {
	seen := make(map[string]bool)

	var perms []string

	for _, p := range cm.Permissions {
		s := fmt.Sprintf("%v", p)
		if !isHostPattern(s) && !seen[s] {
			seen[s] = true
			perms = append(perms, s)
		}
	}

	for _, p := range cm.OptPermissions {
		s := fmt.Sprintf("%v", p)
		if !isHostPattern(s) && !seen[s] {
			seen[s] = true
			perms = append(perms, s)
		}
	}
	// V3 host_permissions go to hosts, but also include them in all for risk analysis
	for _, h := range cm.HostPermissions {
		if !seen[h] {
			seen[h] = true
			perms = append(perms, h)
		}
	}

	return perms
}

func extractHosts(cm ChromeManifest) []string {
	var hosts []string

	seen := make(map[string]bool)

	// V2: hosts are in permissions
	for _, p := range cm.Permissions {
		s := fmt.Sprintf("%v", p)
		if isHostPattern(s) && !seen[s] {
			seen[s] = true
			hosts = append(hosts, s)
		}
	}
	// V3: dedicated field
	for _, h := range cm.HostPermissions {
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	return hosts
}

func isHostPattern(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "<all_urls>") ||
		strings.HasPrefix(s, "http") || strings.HasPrefix(s, "*://")
}

// AnalyzePermissions classifies permissions using manifest rules
func AnalyzePermissions(info *ExtensionInfo, rules []manifest.ExtPermissionRule) {
	info.Permissions.ByRisk = map[string][]string{
		"CRITICAL": {},
		"HIGH":     {},
		"MEDIUM":   {},
		"LOW":      {},
		"UNKNOWN":  {},
	}

	ruleMap := make(map[string]string)
	for _, r := range rules {
		ruleMap[r.Permission] = r.Risk
	}

	for _, perm := range info.Permissions.All {
		risk, ok := ruleMap[perm]
		if !ok {
			// Check host patterns
			if isHostPattern(perm) {
				if perm == "<all_urls>" || perm == "http://*/*" || perm == "https://*/*" || perm == "*://*/*" {
					risk = "HIGH"
				} else {
					risk = "MEDIUM"
				}
			} else {
				risk = "UNKNOWN"
			}
		}

		info.Permissions.ByRisk[risk] = append(info.Permissions.ByRisk[risk], perm)
	}

	info.Permissions.Critical = len(info.Permissions.ByRisk["CRITICAL"])
	info.Permissions.High = len(info.Permissions.ByRisk["HIGH"])
	info.Permissions.Medium = len(info.Permissions.ByRisk["MEDIUM"])
	info.Permissions.Low = len(info.Permissions.ByRisk["LOW"])
	info.Permissions.Unknown = len(info.Permissions.ByRisk["UNKNOWN"])
}

// CalculateRiskScore computes a risk score using manifest weights.
// Findings from filter-list files are excluded from scoring to avoid
// inflating risk for ad-blocker extensions whose blocklists contain
// patterns like "coinhive.com" or "eval".
func CalculateRiskScore(info *ExtensionInfo, weights map[string]int) {
	score := 0

	// Permission risk
	score += info.Permissions.Critical * weights["CRITICAL"]
	score += info.Permissions.High * weights["HIGH"]
	score += info.Permissions.Medium * weights["MEDIUM"]
	score += info.Permissions.Low * weights["LOW"]
	score += info.Permissions.Unknown * weights["UNKNOWN"]

	// Code findings (skip filter-list findings)
	for _, f := range info.CodeFindings {
		if f.InFilterList {
			continue
		}
		if w, ok := weights[f.Risk]; ok {
			score += w
		}
	}

	// Stealth findings
	for _, f := range info.StealthFlags {
		if w, ok := weights[f.Risk]; ok {
			score += w
		}
	}

	// Cheating flags
	score += len(info.CheatingFlags) * weights["HIGH"]

	info.RiskScore = score

	info.RiskLevel = "LOW"
	if score >= 100 {
		info.RiskLevel = "CRITICAL"
	} else if score >= 50 {
		info.RiskLevel = "HIGH"
	} else if score >= 20 {
		info.RiskLevel = "MEDIUM"
	}
}

// compiledPattern holds a pre-compiled regex with its metadata
type compiledPattern struct {
	re          *regexp.Regexp
	literal     string // fallback when regex fails to compile
	name        string
	description string
	risk        string
}

// cheatingKW holds original and lowercased keyword for efficient matching
type cheatingKW struct {
	original string
	lower    string
}

// compiledScanner holds all pre-compiled patterns for single-pass file scanning
type compiledScanner struct {
	suspicious []compiledPattern
	stealth    []compiledPattern
	cheating   []cheatingKW
	permRules  []manifest.ExtPermissionRule
	weights    map[string]int
}

func newCompiledScanner(m *manifest.Manifest) *compiledScanner {
	cs := &compiledScanner{
		permRules: m.Extension.DangerousPermissions,
		weights:   m.RiskScoring.Weights,
	}

	for _, pat := range m.Extension.SuspiciousPatterns {
		for _, p := range pat.Patterns {
			cp := compiledPattern{
				name:        pat.Name,
				description: pat.Description,
				risk:        pat.Risk,
			}
			if re, err := regexp.Compile(p); err == nil {
				cp.re = re
			} else {
				cp.literal = p
			}

			cs.suspicious = append(cs.suspicious, cp)
		}
	}

	for _, sp := range m.Extension.StealthPatterns {
		for _, p := range sp.Patterns {
			cp := compiledPattern{
				name:        sp.Name,
				description: sp.Description,
				risk:        sp.Risk,
			}
			if re, err := regexp.Compile(p); err == nil {
				cp.re = re
			} else {
				cp.literal = p
			}

			cs.stealth = append(cs.stealth, cp)
		}
	}

	for _, kw := range m.Extension.CheatingKeywords {
		cs.cheating = append(cs.cheating, cheatingKW{original: kw, lower: strings.ToLower(kw)})
	}

	return cs
}

// isFilterListPath returns true if the relative path belongs to a filter-list,
// blocklist, or declarativeNetRequest rule directory. Findings in these paths
// are typically false positives because the patterns describe what the extension
// blocks, not what it does.
func isFilterListPath(relPath string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(relPath, "\\", "/"))
	filterPrefixes := []string{
		"filter-lists/", "filter_lists/", "filterlists/",
		"blocklist/", "blocklists/", "block-list/", "block-lists/",
		"rules/", "dnr/", "dnr-rules/",
		"adblock/", "adblock-rules/",
		"ublock/", "cosmetic-filters/",
	}
	for _, prefix := range filterPrefixes {
		if strings.HasPrefix(normalized, prefix) || strings.Contains(normalized, "/"+prefix) {
			return true
		}
	}
	filterSuffixes := []string{
		"-blocklist.json", "-blocklist.txt",
		"-filterlist.json", "-filterlist.txt",
		"-rules.json", "-filters.json",
		"_blocklist.json", "_filterlist.json",
	}
	for _, suffix := range filterSuffixes {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

// scanExtensionFiles performs a single walk over extension files,
// applying suspicious, stealth, and cheating pattern checks in one pass.
// Files inside filter-list directories are flagged but not counted toward
// the risk score (see CalculateRiskScore).
func (cs *compiledScanner) scanExtensionFiles(info *ExtensionInfo) {
	const maxFileSize = 5 * 1024 * 1024

	suspiciousExts := map[string]bool{".js": true, ".html": true, ".css": true, ".json": true, ".mjs": true}
	stealthExts := map[string]bool{".js": true, ".html": true, ".mjs": true}
	cheatingExts := map[string]bool{".js": true, ".html": true, ".json": true, ".mjs": true}

	cheatingSeen := make(map[int]bool)

	// Check name/description for cheating keywords
	nameLower := strings.ToLower(info.Name)

	descLower := strings.ToLower(info.Description)
	for i, kw := range cs.cheating {
		if strings.Contains(nameLower, kw.lower) || strings.Contains(descLower, kw.lower) {
			cheatingSeen[i] = true

			info.CheatingFlags = append(info.CheatingFlags, fmt.Sprintf("metadata:%s", kw.original))
		}
	}

	_ = filepath.Walk(info.Path, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > maxFileSize {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		wantSuspicious := suspiciousExts[ext]
		wantStealth := stealthExts[ext]

		wantCheating := cheatingExts[ext]
		if !wantSuspicious && !wantStealth && !wantCheating {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		relPath, _ := filepath.Rel(info.Path, path)
		filterList := isFilterListPath(relPath)

		if wantSuspicious {
			for _, cp := range cs.suspicious {
				if cp.re != nil {
					if loc := cp.re.FindStringIndex(content); loc != nil {
						line := strings.Count(content[:loc[0]], "\n") + 1

						ctxStart := max(loc[0]-40, 0)

						ctxEnd := min(loc[1]+40, len(content))

						ctx := strings.ReplaceAll(content[ctxStart:ctxEnd], "\n", " ")
						info.CodeFindings = append(info.CodeFindings, CodeFinding{
							Pattern:      cp.name,
							Description:  cp.description,
							File:         relPath,
							Line:         line,
							Context:      ctx,
							Risk:         cp.risk,
							InFilterList: filterList,
						})
					}
				} else if strings.Contains(content, cp.literal) {
					info.CodeFindings = append(info.CodeFindings, CodeFinding{
						Pattern:      cp.name,
						Description:  cp.description,
						File:         relPath,
						Risk:         cp.risk,
						InFilterList: filterList,
					})
				}
			}
		}

		if wantStealth {
			for _, cp := range cs.stealth {
				if cp.re != nil {
					if loc := cp.re.FindStringIndex(content); loc != nil {
						ctxStart := max(loc[0]-30, 0)

						ctxEnd := min(loc[1]+30, len(content))

						evidence := strings.ReplaceAll(content[ctxStart:ctxEnd], "\n", " ")
						info.StealthFlags = append(info.StealthFlags, StealthFinding{
							Name:        cp.name,
							Description: cp.description,
							Evidence:    evidence,
							File:        relPath,
							Risk:        cp.risk,
						})
					}
				} else if strings.Contains(content, cp.literal) {
					info.StealthFlags = append(info.StealthFlags, StealthFinding{
						Name:        cp.name,
						Description: cp.description,
						Evidence:    cp.literal,
						File:        relPath,
						Risk:        cp.risk,
					})
				}
			}
		}

		// Skip cheating keyword detection in filter-list files
		if wantCheating && !filterList {
			contentLower := strings.ToLower(content)

			for i, kw := range cs.cheating {
				if cheatingSeen[i] {
					continue
				}

				if strings.Contains(contentLower, kw.lower) {
					cheatingSeen[i] = true

					info.CheatingFlags = append(info.CheatingFlags, fmt.Sprintf("source(%s):%s", relPath, kw.original))
				}
			}
		}

		return nil
	})
}

// ScanAllExtensions discovers and analyzes all extensions
func ScanAllExtensions(m *manifest.Manifest, filterBrowser string, verbose bool) *ScanResult {
	result := &ScanResult{
		RiskSummary: map[string]int{},
	}

	profiles := DiscoverBrowsers(filterBrowser)
	result.Browsers = profiles

	// Pre-compile all patterns once
	scanner := newCompiledScanner(m)

	// Collect extension work items
	type extWork struct {
		path    string
		id      string
		browser string
		profile string
	}

	var work []extWork

	for _, bp := range profiles {
		entries, err := os.ReadDir(bp.ExtDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !e.IsDir() || e.Name() == "Temp" {
				continue
			}

			work = append(work, extWork{
				path:    filepath.Join(bp.ExtDir, e.Name()),
				id:      e.Name(),
				browser: bp.Browser,
				profile: bp.Profile,
			})
		}
	}

	// Process extensions concurrently
	type extResult struct {
		info *ExtensionInfo
		err  error
	}

	results := make([]extResult, len(work))

	var wg sync.WaitGroup

	sem := make(chan struct{}, runtime.NumCPU())

	for i, w := range work {
		wg.Add(1)

		go func(idx int, w extWork) {
			defer wg.Done()

			sem <- struct{}{}

			defer func() { <-sem }()

			info, err := ParseExtension(w.path, w.id, w.browser, w.profile)
			if err != nil {
				results[idx] = extResult{err: err}
				return
			}

			AnalyzePermissions(info, scanner.permRules)
			scanner.scanExtensionFiles(info)
			enrichExtensionData(info)
			CalculateRiskScore(info, scanner.weights)

			results[idx] = extResult{info: info}
		}(i, w)
	}

	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			if verbose {
				fmt.Printf("  [SKIP] %s: %v\n", work[i].id, r.err)
			}

			continue
		}

		result.Extensions = append(result.Extensions, *r.info)

		result.RiskSummary[r.info.RiskLevel]++
		if verbose {
			fmt.Printf("  [EXT] %s (%s) - %s [%s]\n", r.info.Name, r.info.ID, r.info.RiskLevel, r.info.Browser)
		}
	}

	result.TotalExts = len(result.Extensions)

	return result
}

// AnalyzeSingleExtension does a deep analysis of one extension by ID or path
func AnalyzeSingleExtension(m *manifest.Manifest, target string, filterBrowser string, verbose bool) (*ExtensionInfo, error) {
	resolved, err := resolveAnalysisTarget(target, filterBrowser)
	if err != nil {
		return nil, err
	}

	if resolved.Cleanup != nil {
		defer resolved.Cleanup()
	}

	info, err := ParseExtension(resolved.Path, resolved.ID, resolved.Browser, resolved.Profile)
	if err != nil {
		return nil, err
	}

	info.SourceType = resolved.SourceType
	analyzeExtensionFull(info, m, verbose)

	return info, nil
}

func analyzeExtensionFull(info *ExtensionInfo, m *manifest.Manifest, verbose bool) {
	AnalyzePermissions(info, m.Extension.DangerousPermissions)
	scanner := newCompiledScanner(m)
	scanner.scanExtensionFiles(info)
	enrichExtensionData(info)
	CalculateRiskScore(info, m.RiskScoring.Weights)

	if verbose {
		fmt.Printf("  [PERMS] %d critical, %d high, %d medium, %d low\n",
			info.Permissions.Critical, info.Permissions.High,
			info.Permissions.Medium, info.Permissions.Low)
		fmt.Printf("  [CODE]  %d suspicious patterns found\n", len(info.CodeFindings))
		fmt.Printf("  [STEALTH] %d stealth indicators\n", len(info.StealthFlags))
		fmt.Printf("  [CHEAT] %d cheating indicators\n", len(info.CheatingFlags))
	}
}

// SearchExtensions searches a pattern across all extension source files
func SearchExtensions(pattern string, filterBrowser string) *SearchResult {
	result := &SearchResult{
		Pattern: pattern,
	}

	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(pattern))
	if err != nil {
		return result
	}

	scanExts := map[string]bool{".js": true, ".html": true, ".css": true, ".json": true, ".mjs": true}

	const maxFileSize = 5 * 1024 * 1024

	// Collect work items
	type searchWork struct {
		extID      string
		versionDir string
		browser    string
		profile    string
	}

	var work []searchWork

	profiles := DiscoverBrowsers(filterBrowser)
	for _, bp := range profiles {
		entries, err := os.ReadDir(bp.ExtDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !e.IsDir() || e.Name() == "Temp" {
				continue
			}

			extPath := filepath.Join(bp.ExtDir, e.Name())

			versionDir, err := findLatestVersion(extPath)
			if err != nil {
				continue
			}

			work = append(work, searchWork{
				extID:      e.Name(),
				versionDir: versionDir,
				browser:    bp.Browser,
				profile:    bp.Profile,
			})
		}
	}

	// Process extensions concurrently
	perExtMatches := make([][]SearchMatch, len(work))

	var wg sync.WaitGroup

	sem := make(chan struct{}, runtime.NumCPU())

	for i, w := range work {
		wg.Add(1)

		go func(idx int, w searchWork) {
			defer wg.Done()

			sem <- struct{}{}

			defer func() { <-sem }()

			extName := w.extID
			if mData, err := os.ReadFile(filepath.Join(w.versionDir, "manifest.json")); err == nil {
				var cm ChromeManifest
				if json.Unmarshal(mData, &cm) == nil && cm.Name != "" {
					extName = cm.Name
				}
			}

			var matches []SearchMatch

			_ = filepath.Walk(w.versionDir, func(path string, fi os.FileInfo, walkErr error) error {
				if walkErr != nil || fi.IsDir() || fi.Size() > maxFileSize {
					return nil
				}

				ext := strings.ToLower(filepath.Ext(path))
				if !scanExts[ext] {
					return nil
				}

				data, readErr := os.ReadFile(path)
				if readErr != nil {
					return nil
				}

				content := string(data)
				relPath, _ := filepath.Rel(w.versionDir, path)

				locs := re.FindAllStringIndex(content, -1)
				for _, loc := range locs {
					line := strings.Count(content[:loc[0]], "\n") + 1

					ctxStart := max(loc[0]-40, 0)

					ctxEnd := min(loc[1]+40, len(content))

					ctx := strings.ReplaceAll(content[ctxStart:ctxEnd], "\n", " ")

					matches = append(matches, SearchMatch{
						Extension: extName,
						Browser:   w.browser,
						Profile:   w.profile,
						File:      relPath,
						Line:      line,
						Context:   ctx,
					})
				}

				return nil
			})
			perExtMatches[idx] = matches
		}(i, w)
	}

	wg.Wait()

	for _, matches := range perExtMatches {
		result.Matches = append(result.Matches, matches...)
	}

	result.Total = len(result.Matches)

	return result
}
