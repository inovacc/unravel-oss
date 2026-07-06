package npm

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// AnalysisResult holds the security analysis findings for a Node.js package.
type AnalysisResult struct {
	PackageName           string            `json:"package_name"`
	Version               string            `json:"version"`
	Scripts               map[string]string `json:"scripts,omitempty"`
	Dependencies          int               `json:"dependency_count"`
	HasPostInstall        bool              `json:"has_postinstall"`
	NetworkCalls          []string          `json:"network_calls,omitempty"`
	FSAccess              []string          `json:"fs_access,omitempty"`
	ExecCalls             []string          `json:"exec_calls,omitempty"`
	Secrets               []string          `json:"secrets,omitempty"`
	MCPTools              []string          `json:"mcp_tools,omitempty"`
	MCPSDKVersion         string            `json:"mcp_sdk_version,omitempty"`
	MCPTransport          string            `json:"mcp_transport,omitempty"` // "stdio", "sse", "streamable-http"
	ObfuscationIndicators []string          `json:"obfuscation_indicators,omitempty"`
	SupplyChainRisks      []string          `json:"supply_chain_risks,omitempty"`
	InstallScripts        map[string]string `json:"install_scripts,omitempty"` // preinstall, postinstall, etc.
	DynamicRequires       []string          `json:"dynamic_requires,omitempty"`
	DeobfuscatedFiles     int               `json:"deobfuscated_files,omitempty"`
	TelemetrySDKs         []string          `json:"telemetry_sdks,omitempty"`
	VulnerablePackages    []string          `json:"vulnerable_packages,omitempty"`
	Typosquat             *TyposquatResult  `json:"typosquat,omitempty"`
	RiskScore             int               `json:"risk_score"` // 0-100
	RiskFactors           []string          `json:"risk_factors,omitempty"`
}

var (
	networkPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\bfetch\s*\(`), "fetch()"},
		{regexp.MustCompile(`\baxios\b`), "axios"},
		{regexp.MustCompile(`\bhttp\.request\b`), "http.request"},
		{regexp.MustCompile(`\bhttps\.request\b`), "https.request"},
		{regexp.MustCompile(`\bgot\s*\(`), "got()"},
		{regexp.MustCompile(`\bnode-fetch\b`), "node-fetch"},
		{regexp.MustCompile(`\bnew\s+WebSocket\b`), "WebSocket"},
		{regexp.MustCompile(`\bXMLHttpRequest\b`), "XMLHttpRequest"},
	}

	fsPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\bfs\.readFile\b`), "fs.readFile"},
		{regexp.MustCompile(`\bfs\.writeFile\b`), "fs.writeFile"},
		{regexp.MustCompile(`\bfs\.unlink\b`), "fs.unlink"},
		{regexp.MustCompile(`\bfs\.readdir\b`), "fs.readdir"},
		{regexp.MustCompile(`\bfs\.access\b`), "fs.access"},
		{regexp.MustCompile(`\bfs\.mkdir\b`), "fs.mkdir"},
		{regexp.MustCompile(`\bfs\.rmdir\b`), "fs.rmdir"},
		{regexp.MustCompile(`\bfs\.rename\b`), "fs.rename"},
		{regexp.MustCompile(`\bfs\.chmod\b`), "fs.chmod"},
		{regexp.MustCompile(`\bfs\.stat\b`), "fs.stat"},
		{regexp.MustCompile(`\bfs\.createReadStream\b`), "fs.createReadStream"},
		{regexp.MustCompile(`\bfs\.createWriteStream\b`), "fs.createWriteStream"},
	}

	execPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\bchild_process\b`), "child_process"},
		{regexp.MustCompile(`\bexec\s*\(`), "exec()"},
		{regexp.MustCompile(`\bexecSync\s*\(`), "execSync()"},
		{regexp.MustCompile(`\bspawn\s*\(`), "spawn()"},
		{regexp.MustCompile(`\bexecFile\s*\(`), "execFile()"},
		{regexp.MustCompile(`\bspawnSync\s*\(`), "spawnSync()"},
	}

	secretPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`(?i)['"]API_KEY['"]\s*[:=]`), "API_KEY"},
		{regexp.MustCompile(`(?i)['"]SECRET['"]\s*[:=]`), "SECRET"},
		{regexp.MustCompile(`(?i)['"]TOKEN['"]\s*[:=]`), "TOKEN"},
		{regexp.MustCompile(`(?i)['"]PASSWORD['"]\s*[:=]`), "PASSWORD"},
		{regexp.MustCompile(`(?i)['"]PRIVATE_KEY['"]\s*[:=]`), "PRIVATE_KEY"},
		{regexp.MustCompile(`(?i)['"]AWS_SECRET['"]\s*[:=]`), "AWS_SECRET"},
		{regexp.MustCompile(`(?i)['"]DATABASE_URL['"]\s*[:=]`), "DATABASE_URL"},
	}

	mcpPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\bMcpServer\b`), "McpServer"},
		{regexp.MustCompile(`\bserver\.tool\b`), "server.tool"},
		{regexp.MustCompile(`\bserver\.resource\b`), "server.resource"},
		{regexp.MustCompile(`@modelcontextprotocol`), "@modelcontextprotocol"},
		{regexp.MustCompile(`\bserver\.prompt\b`), "server.prompt"},
		{regexp.MustCompile(`\bCallToolResult\b`), "CallToolResult"},
		{regexp.MustCompile(`\bTextContent\b`), "TextContent"},
	}

	mcpTransportPatterns = []struct {
		pattern   *regexp.Regexp
		transport string
	}{
		{regexp.MustCompile(`\bStdioServerTransport\b`), "stdio"},
		{regexp.MustCompile(`\bSSEServerTransport\b`), "sse"},
		{regexp.MustCompile(`\bStreamableHTTPServerTransport\b`), "streamable-http"},
	}

	mcpSDKVersionPattern = regexp.MustCompile(`@modelcontextprotocol/sdk[@/]v?(\d+\.\d+(?:\.\d+)?)`)
	mcpProtocolVersion   = regexp.MustCompile(`["'](\d+\.\d+)["']\s*(?:,\s*["'](?:protocol|version))`)
	mcpProtocolNear      = regexp.MustCompile(`(?:protocol[Vv]ersion|protocolVersion)\s*[:=]\s*["'](\d+\.\d+)["']`)

	obfuscationPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\beval\s*\(`), "eval() dynamic code execution"},
		{regexp.MustCompile(`\bnew\s+Function\s*\(`), "new Function() dynamic code execution"},
		{regexp.MustCompile(`_0x[0-9a-fA-F]+`), "javascript-obfuscator variable naming (_0x...)"},
		{regexp.MustCompile(`\batob\s*\(`), "atob() base64 decoding"},
		{regexp.MustCompile(`\bbtoa\s*\(`), "btoa() base64 encoding"},
		{regexp.MustCompile(`\['push'\]\s*,\s*\['shift'\]`), "string array rotation pattern"},
		{regexp.MustCompile(`\bString\.fromCharCode\s*\(`), "String.fromCharCode encoding"},
	}

	dynamicRequirePattern = regexp.MustCompile(`\brequire\s*\(\s*[^"'` + "`" + `\s]`)

	supplyChainScriptPatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\bcurl\b`), "curl in script"},
		{regexp.MustCompile(`\bwget\b`), "wget in script"},
		{regexp.MustCompile(`\bpowershell\b`), "powershell in script"},
		{regexp.MustCompile(`\bcmd\s+/c\b`), "cmd /c in script"},
		{regexp.MustCompile(`\bbash\s+-c\b`), "bash -c in script"},
	}

	hexEscapePattern     = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	unicodeEscapePattern = regexp.MustCompile(`\\u00[0-9a-fA-F]{2}`)
	envAccessPattern     = regexp.MustCompile(`(?i)\.env\b|dotenv|process\.env`)

	jsExtensions = map[string]bool{
		".js":  true,
		".ts":  true,
		".mjs": true,
		".cjs": true,
		".jsx": true,
		".tsx": true,
	}

	// Telemetry SDK detection patterns (matched against JS source lines)
	telemetrySourcePatterns = []struct {
		pattern *regexp.Regexp
		label   string
	}{
		{regexp.MustCompile(`\bgtag\s*\(`), "Google Analytics (gtag)"},
		{regexp.MustCompile(`\bga\s*\(\s*['"]`), "Google Analytics (ga)"},
		{regexp.MustCompile(`\bGoogleAnalyticsObject\b`), "Google Analytics"},
		{regexp.MustCompile(`\bmixpanel\b`), "Mixpanel"},
		{regexp.MustCompile(`\banalytics\.track\s*\(`), "Segment"},
		{regexp.MustCompile(`\bSentry\.init\s*\(`), "Sentry"},
		{regexp.MustCompile(`\bposthog\b`), "PostHog"},
		{regexp.MustCompile(`\bamplitude\b`), "Amplitude"},
		{regexp.MustCompile(`\bnewrelic\b`), "New Relic"},
		{regexp.MustCompile(`\bplausible\b`), "Plausible"},
		{regexp.MustCompile(`\bheap\s*\.\s*track\b`), "Heap"},
		{regexp.MustCompile(`\bdatadog\b`), "Datadog"},
	}

	// Telemetry package names matched against package.json dependencies
	telemetryPackageNames = map[string]string{
		"analytics":                    "Google Analytics",
		"@google-analytics/data":       "Google Analytics",
		"mixpanel":                     "Mixpanel",
		"mixpanel-browser":             "Mixpanel",
		"@segment/analytics-next":      "Segment",
		"@segment/analytics-node":      "Segment",
		"@amplitude/analytics-browser": "Amplitude",
		"@amplitude/analytics-node":    "Amplitude",
		"posthog-js":                   "PostHog",
		"posthog-node":                 "PostHog",
		"@sentry/node":                 "Sentry",
		"@sentry/browser":              "Sentry",
		"@sentry/electron":             "Sentry",
		"dd-trace":                     "Datadog",
		"@datadog/browser-rum":         "Datadog",
		"@datadog/browser-logs":        "Datadog",
		"newrelic":                     "New Relic",
		"plausible-tracker":            "Plausible",
		"heap-api":                     "Heap",
	}

	// Known-malicious or sabotaged npm packages.
	// Each entry maps package name to a description of the issue.
	knownMaliciousPackages = map[string]string{
		"event-stream":           "contained malicious code targeting copay-dash (v3.3.6)",
		"flatmap-stream":         "injected cryptocurrency-stealing code via event-stream",
		"ua-parser-js":           "hijacked with cryptominer/password stealer (0.7.29, 0.8.0, 1.0.0)",
		"coa":                    "hijacked with malicious code (2.0.3, 2.0.4, 2.1.1, 2.1.3, 3.0.1, 3.1.3)",
		"rc":                     "hijacked with malicious code (1.2.9, 1.3.9, 2.3.9)",
		"colors":                 "sabotaged with infinite loop by maintainer (>1.4.0)",
		"faker":                  "sabotaged with infinite loop by maintainer (>5.5.3)",
		"node-ipc":               "protestware: overwrites files on Russian/Belarusian IPs (>10.1.0)",
		"peacenotwar":            "protestware payload used by node-ipc",
		"es5-ext":                "protestware: logs anti-war message based on timezone",
		"left-pad":               "removed from npm causing widespread breakage",
		"crossenv":               "typosquat of cross-env, steals env vars",
		"getcookies":             "hidden backdoor via express middleware",
		"mailparser":             "hijacked version with credential theft",
		"electron-native-notify": "postinstall script exfiltrates data",
		"load-from-cwd-or-npm":   "contains code to steal npm tokens",
		"@aspect-build/rules_js": "typosquat with data exfiltration",
		"discord.js-selfbot-v13": "steals Discord tokens",
		"lemaaa":                 "steals Discord tokens and browser data",
		"typosquat-alert":        "placeholder to demonstrate typosquat risk",
	}
)

// Analyze performs security analysis on a Node.js package directory.
func Analyze(dir string) (*AnalysisResult, error) {
	pkgPath := filepath.Join(dir, "package.json")
	pkg, err := ParsePackageJSON(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	result := &AnalysisResult{
		PackageName:  pkg.Name,
		Version:      pkg.Version,
		Scripts:      pkg.Scripts,
		Dependencies: len(pkg.Dependencies) + len(pkg.DevDependencies),
	}

	// Check for install hooks and collect install scripts
	hookScripts := []string{"preinstall", "postinstall", "install", "preuninstall", "postuninstall", "prepare"}
	for _, hook := range hookScripts {
		if script, ok := pkg.Scripts[hook]; ok {
			if hook == "postinstall" || hook == "preinstall" || hook == "install" {
				result.HasPostInstall = true
			}
			if result.InstallScripts == nil {
				result.InstallScripts = make(map[string]string)
			}
			result.InstallScripts[hook] = script
		}
	}

	// Detect supply chain risks
	result.SupplyChainRisks = detectSupplyChain(pkg, dir)

	// Detect telemetry SDKs from package.json dependencies
	telemetrySet := make(map[string]bool)
	allDeps := make(map[string]string)
	maps.Copy(allDeps, pkg.Dependencies)
	maps.Copy(allDeps, pkg.DevDependencies)
	for depName := range allDeps {
		if label, ok := telemetryPackageNames[depName]; ok {
			telemetrySet[label] = true
		}
	}

	// Detect known-malicious packages in dependencies
	var vulnPkgs []string
	for depName := range allDeps {
		if desc, ok := knownMaliciousPackages[depName]; ok {
			vulnPkgs = append(vulnPkgs, fmt.Sprintf("%s: %s", depName, desc))
		}
	}

	// Deduplicate findings using sets
	networkSet := make(map[string]bool)
	fsSet := make(map[string]bool)
	execSet := make(map[string]bool)
	secretSet := make(map[string]bool)
	mcpSet := make(map[string]bool)
	obfuscationSet := make(map[string]bool)
	dynamicRequireSet := make(map[string]bool)

	// MCP SDK fingerprint tracking
	mcpSDKVersion := ""
	mcpTransport := ""

	// Walk source files
	deobfCandidates := 0

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !jsExtensions[ext] {
			return nil
		}

		prevObfLen := len(obfuscationSet)

		sdkVer, transport, scanErr := scanFile(path, networkSet, fsSet, execSet, secretSet, mcpSet, obfuscationSet, dynamicRequireSet, telemetrySet)
		if scanErr != nil {
			return scanErr
		}

		// Keep first non-empty SDK version / transport found
		if sdkVer != "" && mcpSDKVersion == "" {
			mcpSDKVersion = sdkVer
		}
		if transport != "" && mcpTransport == "" {
			mcpTransport = transport
		}

		// Count files with obfuscation that are small enough for deobfuscation (<500KB)
		if len(obfuscationSet) > prevObfLen && info.Size() < 500*1024 {
			deobfCandidates++
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	result.NetworkCalls = setToSlice(networkSet)
	result.FSAccess = setToSlice(fsSet)
	result.ExecCalls = setToSlice(execSet)
	result.Secrets = setToSlice(secretSet)
	result.MCPTools = setToSlice(mcpSet)
	result.MCPSDKVersion = mcpSDKVersion
	result.MCPTransport = mcpTransport
	result.ObfuscationIndicators = setToSlice(obfuscationSet)
	result.DynamicRequires = setToSlice(dynamicRequireSet)
	result.DeobfuscatedFiles = deobfCandidates
	result.TelemetrySDKs = setToSlice(telemetrySet)
	result.VulnerablePackages = vulnPkgs

	// Typosquatting check
	if result.PackageName != "" {
		typo := CheckTyposquatting(result.PackageName)
		if typo.IsLikelyTypo || len(typo.SimilarTo) > 0 {
			result.Typosquat = typo
		}
	}

	// Calculate risk score
	result.RiskScore, result.RiskFactors = calculateRisk(result)

	return result, nil
}

func scanFile(path string, network, fs, exec, secrets, mcp, obfuscation, dynamicRequires, telemetry map[string]bool) (sdkVersion, transport string, err error) {
	f, openErr := os.Open(path)
	if openErr != nil {
		return "", "", nil // skip unreadable files
	}
	defer func() { _ = f.Close() }()

	relPath := path // will be shown in context
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line

	lineNum := 0
	hexEscapeCount := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range networkPatterns {
			if p.pattern.MatchString(line) {
				network[fmt.Sprintf("%s (in %s:%d)", p.label, filepath.Base(relPath), lineNum)] = true
			}
		}
		for _, p := range fsPatterns {
			if p.pattern.MatchString(line) {
				fs[fmt.Sprintf("%s (in %s:%d)", p.label, filepath.Base(relPath), lineNum)] = true
			}
		}
		for _, p := range execPatterns {
			if p.pattern.MatchString(line) {
				exec[fmt.Sprintf("%s (in %s:%d)", p.label, filepath.Base(relPath), lineNum)] = true
			}
		}
		for _, p := range secretPatterns {
			if p.pattern.MatchString(line) {
				secrets[fmt.Sprintf("%s (in %s:%d)", p.label, filepath.Base(relPath), lineNum)] = true
			}
		}
		for _, p := range mcpPatterns {
			if p.pattern.MatchString(line) {
				mcp[fmt.Sprintf("%s (in %s:%d)", p.label, filepath.Base(relPath), lineNum)] = true
			}
		}

		// MCP SDK version fingerprinting (from bundled JS)
		if sdkVersion == "" {
			if m := mcpSDKVersionPattern.FindStringSubmatch(line); len(m) > 1 {
				sdkVersion = m[1]
			} else if m := mcpProtocolNear.FindStringSubmatch(line); len(m) > 1 {
				sdkVersion = m[1]
			} else if m := mcpProtocolVersion.FindStringSubmatch(line); len(m) > 1 {
				sdkVersion = m[1]
			}
		}

		// MCP transport detection
		if transport == "" {
			for _, tp := range mcpTransportPatterns {
				if tp.pattern.MatchString(line) {
					transport = tp.transport
					break
				}
			}
		}

		// Obfuscation detection
		for _, p := range obfuscationPatterns {
			if p.pattern.MatchString(line) {
				obfuscation[fmt.Sprintf("%s (in %s:%d)", p.label, filepath.Base(relPath), lineNum)] = true
			}
		}

		// Telemetry SDK detection from source
		for _, p := range telemetrySourcePatterns {
			if p.pattern.MatchString(line) {
				telemetry[p.label] = true
			}
		}

		// Count hex/unicode escape sequences
		hexEscapeCount += len(hexEscapePattern.FindAllString(line, -1))
		hexEscapeCount += len(unicodeEscapePattern.FindAllString(line, -1))

		// Very long single lines suggest heavy minification/obfuscation
		if utf8.RuneCountInString(line) > 5000 {
			obfuscation[fmt.Sprintf("very long line (%d chars) in %s:%d", utf8.RuneCountInString(line), filepath.Base(relPath), lineNum)] = true
		}

		// Dynamic require detection
		if dynamicRequirePattern.MatchString(line) {
			dynamicRequires[fmt.Sprintf("dynamic require() (in %s:%d)", filepath.Base(relPath), lineNum)] = true
		}

		// .env file access patterns
		if envAccessPattern.MatchString(line) {
			// This is tracked but not added to obfuscation — it feeds supply chain
		}
	}

	// Flag heavy hex/unicode encoding (>20 occurrences per file)
	if hexEscapeCount > 20 {
		obfuscation[fmt.Sprintf("heavy hex/unicode encoding (%d sequences in %s)", hexEscapeCount, filepath.Base(relPath))] = true
	}

	return sdkVersion, transport, scanner.Err()
}

func setToSlice(s map[string]bool) []string {
	if len(s) == 0 {
		return nil
	}
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	return result
}

// detectSupplyChain checks package.json scripts and known supply chain attack patterns.
func detectSupplyChain(pkg *PackageJSON, dir string) []string {
	var risks []string

	// Check install hooks for dangerous commands
	installHooks := []string{"preinstall", "postinstall", "install", "preuninstall"}
	for _, hook := range installHooks {
		script, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		risks = append(risks, fmt.Sprintf("%s script defined: %s", hook, truncateStr(script, 80)))
		for _, p := range supplyChainScriptPatterns {
			if p.pattern.MatchString(script) {
				risks = append(risks, fmt.Sprintf("%s in %s script", p.label, hook))
			}
		}
	}

	// Check for typosquatting indicators against popular packages
	popularPackages := []string{
		"express", "lodash", "react", "axios", "chalk", "commander",
		"webpack", "babel", "eslint", "prettier", "typescript", "jest",
		"mocha", "moment", "underscore", "request", "debug", "dotenv",
		"uuid", "yargs", "semver", "minimist", "glob", "rimraf",
	}
	if pkg.Name != "" {
		for _, popular := range popularPackages {
			if pkg.Name != popular && levenshteinClose(pkg.Name, popular) {
				risks = append(risks, fmt.Sprintf("package name '%s' is very similar to popular package '%s' (possible typosquat)", pkg.Name, popular))
			}
		}
	}

	return risks
}

// levenshteinClose returns true if the two strings differ by exactly one character
// (insertion, deletion, or substitution), which is a common typosquatting pattern.
func levenshteinClose(a, b string) bool {
	la, lb := len(a), len(b)
	diff := la - lb
	if diff < -1 || diff > 1 {
		return false
	}

	if la == lb {
		// Check single substitution
		mismatches := 0
		for i := range la {
			if a[i] != b[i] {
				mismatches++
				if mismatches > 1 {
					return false
				}
			}
		}
		return mismatches == 1
	}

	// Check single insertion/deletion
	longer, shorter := a, b
	if lb > la {
		longer, shorter = b, a
	}
	j := 0
	skipped := false
	for i := 0; i < len(longer) && j < len(shorter); i++ {
		if longer[i] != shorter[j] {
			if skipped {
				return false
			}
			skipped = true
			continue
		}
		j++
	}
	return true
}

// truncateStr truncates a string to maxLen characters, appending "..." if truncated.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func calculateRisk(r *AnalysisResult) (int, []string) {
	score := 0
	var factors []string

	// Post-install hooks are a major risk
	if r.HasPostInstall {
		score += 25
		factors = append(factors, "has install lifecycle hooks")
	}

	// Exec calls are high risk
	if len(r.ExecCalls) > 0 {
		score += 20
		factors = append(factors, fmt.Sprintf("executes shell commands (%d locations)", len(r.ExecCalls)))
	}

	// Network access
	if len(r.NetworkCalls) > 0 {
		score += 15
		factors = append(factors, fmt.Sprintf("makes network requests (%d locations)", len(r.NetworkCalls)))
	}

	// Filesystem access
	if len(r.FSAccess) > 0 {
		score += 10
		factors = append(factors, fmt.Sprintf("accesses filesystem (%d locations)", len(r.FSAccess)))
	}

	// Hardcoded secrets
	if len(r.Secrets) > 0 {
		score += 15
		factors = append(factors, fmt.Sprintf("contains hardcoded secrets (%d found)", len(r.Secrets)))
	}

	// High dependency count
	if r.Dependencies > 20 {
		score += 10
		factors = append(factors, fmt.Sprintf("high dependency count (%d)", r.Dependencies))
	} else if r.Dependencies > 10 {
		score += 5
		factors = append(factors, fmt.Sprintf("moderate dependency count (%d)", r.Dependencies))
	}

	// MCP tools (not inherently risky but noteworthy)
	if len(r.MCPTools) > 0 {
		score += 5
		factors = append(factors, fmt.Sprintf("registers MCP tools (%d found)", len(r.MCPTools)))
	}

	// Obfuscation indicators: +15 per indicator, capped at 30
	if len(r.ObfuscationIndicators) > 0 {
		obfScore := min(len(r.ObfuscationIndicators)*15, 30)
		score += obfScore
		factors = append(factors, fmt.Sprintf("obfuscated code detected (%d indicators)", len(r.ObfuscationIndicators)))
		factors = append(factors, "obfuscated JS detected — use 'jsdeob deobfuscate' for analysis")
	}

	// Supply chain risks: +20 per risk, capped at 40
	if len(r.SupplyChainRisks) > 0 {
		scScore := min(len(r.SupplyChainRisks)*20, 40)
		score += scScore
		factors = append(factors, fmt.Sprintf("supply chain risks detected (%d findings)", len(r.SupplyChainRisks)))
	}

	// Dynamic requires: +10 per occurrence, capped at 20
	if len(r.DynamicRequires) > 0 {
		drScore := min(len(r.DynamicRequires)*10, 20)
		score += drScore
		factors = append(factors, fmt.Sprintf("dynamic require() calls (%d locations)", len(r.DynamicRequires)))
	}

	// Telemetry SDKs: +5 total (not per SDK — presence is informational)
	if len(r.TelemetrySDKs) > 0 {
		score += 5
		factors = append(factors, fmt.Sprintf("telemetry SDKs detected (%d: %s)", len(r.TelemetrySDKs), strings.Join(r.TelemetrySDKs, ", ")))
	}

	// Typosquatting: +25 if likely typo
	if r.Typosquat != nil && r.Typosquat.IsLikelyTypo {
		score += 25
		methods := strings.Join(r.Typosquat.Techniques, ", ")
		factors = append(factors, fmt.Sprintf("possible typosquat detected (techniques: %s)", methods))
	}

	// Vulnerable/malicious packages: +30 per package, capped at 50
	if len(r.VulnerablePackages) > 0 {
		vpScore := min(len(r.VulnerablePackages)*30, 50)
		score += vpScore
		factors = append(factors, fmt.Sprintf("known-malicious packages detected (%d)", len(r.VulnerablePackages)))
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score, factors
}
