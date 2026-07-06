/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"strings"
)

// loadCert loads certificate data from teardown.
func loadCert(dir string, report *Report) {
	var raw struct {
		Certificates []struct {
			Subject   string `json:"subject"`
			Issuer    string `json:"issuer"`
			NotBefore string `json:"not_before"`
			NotAfter  string `json:"not_after"`
			Expired   bool   `json:"is_expired"`
			SelfSign  bool   `json:"is_self_signed"`
			FP        struct {
				SHA256 string `json:"sha256"`
			} `json:"fingerprint"`
		} `json:"certificates"`
	}

	if err := loadJSON(dir, "apk_cert.json", &raw); err != nil {
		return
	}

	if len(raw.Certificates) == 0 {
		return
	}

	c := raw.Certificates[0]
	report.Certificate = &CertSummary{
		Subject:    c.Subject,
		Issuer:     c.Issuer,
		NotBefore:  c.NotBefore,
		NotAfter:   c.NotAfter,
		SHA256:     c.FP.SHA256,
		SelfSigned: c.SelfSign,
		Expired:    c.Expired,
	}
}

// loadManifest loads manifest analysis data.
func loadManifest(dir string, report *Report) {
	var raw struct {
		Package     string `json:"package"`
		VersionName string `json:"version_name"`
		VersionCode int    `json:"version_code"`
		UsesSdk     struct {
			MinSdkVersion    int `json:"min_sdk_version"`
			TargetSdkVersion int `json:"target_sdk_version"`
		} `json:"uses_sdk"`
		Permissions []struct {
			Name string `json:"name"`
		} `json:"permissions"`
		Application struct {
			Debuggable         *bool `json:"debuggable"`
			AllowBackup        *bool `json:"allow_backup"`
			UsesCleartextTraff *bool `json:"uses_cleartext_traffic"`
		} `json:"application"`
		Components []struct {
			Exported *bool `json:"exported"`
		} `json:"components"`
	}

	if err := loadJSON(dir, "manifest_info.json", &raw); err != nil {
		return
	}

	report.PackageName = raw.Package
	report.Version = raw.VersionName

	dangerousPerms := []string{
		"android.permission.CAMERA",
		"android.permission.RECORD_AUDIO",
		"android.permission.READ_CONTACTS",
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.ACCESS_COARSE_LOCATION",
		"android.permission.READ_PHONE_STATE",
		"android.permission.SEND_SMS",
		"android.permission.READ_SMS",
		"android.permission.READ_CALL_LOG",
		"android.permission.READ_EXTERNAL_STORAGE",
		"android.permission.WRITE_EXTERNAL_STORAGE",
		"android.permission.GET_ACCOUNTS",
		"android.permission.BODY_SENSORS",
		"android.permission.READ_CALENDAR",
		"android.permission.PROCESS_OUTGOING_CALLS",
	}
	dangerousSet := map[string]bool{}
	for _, p := range dangerousPerms {
		dangerousSet[p] = true
	}

	var allPerms, dangerFound []string
	for _, p := range raw.Permissions {
		allPerms = append(allPerms, p.Name)
		if dangerousSet[p.Name] {
			dangerFound = append(dangerFound, p.Name)
		}
	}

	debuggable := false
	if raw.Application.Debuggable != nil {
		debuggable = *raw.Application.Debuggable
	}

	allowBackup := false
	if raw.Application.AllowBackup != nil {
		allowBackup = *raw.Application.AllowBackup
	}

	cleartext := false
	if raw.Application.UsesCleartextTraff != nil {
		cleartext = *raw.Application.UsesCleartextTraff
	}

	exported := 0
	for _, c := range raw.Components {
		if c.Exported != nil && *c.Exported {
			exported++
		}
	}

	report.Manifest = &ManifestSummary{
		Package:       raw.Package,
		VersionName:   raw.VersionName,
		VersionCode:   raw.VersionCode,
		MinSDK:        raw.UsesSdk.MinSdkVersion,
		TargetSDK:     raw.UsesSdk.TargetSdkVersion,
		Permissions:   allPerms,
		DangerousPerm: dangerFound,
		Debuggable:    debuggable,
		AllowBackup:   allowBackup,
		CleartextOK:   cleartext,
		ExportedComps: exported,
	}
}

// loadNetwork loads network analysis data.
func loadNetwork(dir string, report *Report) {
	var raw struct {
		Endpoints []struct {
			URL    string `json:"url"`
			Host   string `json:"host"`
			Path   string `json:"path"`
			Scheme string `json:"scheme"`
		} `json:"endpoints"`
		CertPinning *struct {
			HasPinning bool `json:"has_pinning"`
		} `json:"cert_pinning"`
	}

	if err := loadJSON(dir, "network_analysis.json", &raw); err != nil {
		return
	}

	summary := &NetworkSummary{
		TotalEndpoints: len(raw.Endpoints),
		Domains:        []string{},
		APIEndpoints:   []APIEndpoint{},
	}

	if raw.CertPinning != nil {
		summary.HasCertPinning = raw.CertPinning.HasPinning
	}

	domainSet := map[string]bool{}
	for _, ep := range raw.Endpoints {
		apiEP := APIEndpoint{
			URL:    ep.URL,
			Host:   ep.Host,
			Path:   ep.Path,
			Scheme: ep.Scheme,
		}

		if ep.Scheme == "http" {
			summary.HasCleartext = true
		}

		if ep.Host != "" {
			domainSet[ep.Host] = true
		}

		if isAPIEndpoint(apiEP) {
			apiEP.Category = classifyEndpoint(apiEP)
			// Infer method from path patterns
			apiEP.Method = inferMethod(ep.Path)
			summary.APIEndpoints = append(summary.APIEndpoints, apiEP)
		}
	}

	for d := range domainSet {
		summary.Domains = append(summary.Domains, d)
	}

	report.Network = summary
}

// inferMethod guesses HTTP method from path patterns.
func inferMethod(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/create") || strings.Contains(lower, "/register") ||
		strings.Contains(lower, "/upload") || strings.Contains(lower, "/submit") ||
		strings.Contains(lower, "/login") || strings.Contains(lower, "/token") ||
		strings.Contains(lower, "/auth"):
		return "POST"
	case strings.Contains(lower, "/update") || strings.Contains(lower, "/edit"):
		return "PUT"
	case strings.Contains(lower, "/delete") || strings.Contains(lower, "/remove"):
		return "DELETE"
	default:
		return "GET"
	}
}

// loadSecrets loads secret scan data.
func loadSecrets(dir string, report *Report) {
	var raw struct {
		TotalFindings  int `json:"total_findings"`
		HighConfidence int `json:"high_confidence"`
		MedConfidence  int `json:"medium_confidence"`
		Findings       []struct {
			Type       string `json:"type"`
			Value      string `json:"value"`
			File       string `json:"file"`
			Confidence string `json:"confidence"`
		} `json:"findings"`
	}

	if err := loadJSON(dir, "secret_scan.json", &raw); err != nil {
		return
	}

	cats := map[string]int{}
	var top []SecretFinding
	for _, f := range raw.Findings {
		cats[f.Type]++
		if f.Confidence == "high" && len(top) < 50 {
			top = append(top, SecretFinding{
				Type:       f.Type,
				Value:      f.Value,
				File:       f.File,
				Confidence: f.Confidence,
			})
		}
	}

	report.Secrets = &SecretsSummary{
		TotalFindings:  raw.TotalFindings,
		HighConfidence: raw.HighConfidence,
		Categories:     cats,
		TopFindings:    top,
	}
}

// loadTelemetry loads telemetry/SDK data.
func loadTelemetry(dir string, report *Report) {
	var raw struct {
		SDKs []struct {
			Name       string `json:"name"`
			Category   string `json:"category"`
			Confidence int    `json:"confidence"`
		} `json:"sdks"`
		StealthFeatures []struct {
			Type        string `json:"type"`
			Component   string `json:"component"`
			Description string `json:"description"`
			Risk        string `json:"risk"`
		} `json:"stealth_features"`
	}

	if err := loadJSON(dir, "telemetry_detection.json", &raw); err != nil {
		return
	}

	cats := map[string]int{}
	var sdks []SDKInfo
	for _, s := range raw.SDKs {
		sdks = append(sdks, SDKInfo{
			Name:       s.Name,
			Category:   s.Category,
			Confidence: s.Confidence,
		})
		cats[s.Category]++
	}

	var stealth []StealthFeature
	for _, sf := range raw.StealthFeatures {
		stealth = append(stealth, StealthFeature{
			Type:        sf.Type,
			Component:   sf.Component,
			Description: sf.Description,
			Risk:        sf.Risk,
		})
	}

	report.Telemetry = &TelemetrySummary{
		SDKCount:        len(sdks),
		SDKs:            sdks,
		StealthFeatures: stealth,
		Categories:      cats,
	}
}

// loadMetadata loads size and app info from metadata.json.
func loadMetadata(dir string, report *Report) {
	var raw struct {
		Size     int64  `json:"size"`
		FileName string `json:"file_name"`
	}

	if err := loadJSON(dir, "metadata.json", &raw); err != nil {
		return
	}

	report.Size = raw.Size
	if report.AppName == "" {
		report.AppName = raw.FileName
	}
}

// generateFindings produces forensic findings from the report data.
func generateFindings(report *Report) []Finding {
	var findings []Finding

	if report.Manifest != nil {
		if report.Manifest.Debuggable {
			findings = append(findings, Finding{
				Category:    "configuration",
				Title:       "Debuggable application",
				Description: "android:debuggable=true allows attaching a debugger to the running process",
				Severity:    "high",
			})
		}
		if report.Manifest.CleartextOK {
			findings = append(findings, Finding{
				Category:    "network",
				Title:       "Cleartext traffic allowed",
				Description: "usesCleartextTraffic=true enables unencrypted HTTP communication",
				Severity:    "medium",
			})
		}
		if report.Manifest.AllowBackup {
			findings = append(findings, Finding{
				Category:    "configuration",
				Title:       "Backup enabled",
				Description: "allowBackup=true may expose app data via adb backup",
				Severity:    "low",
			})
		}
		if len(report.Manifest.DangerousPerm) > 5 {
			findings = append(findings, Finding{
				Category:    "permissions",
				Title:       "Excessive dangerous permissions",
				Description: strings.Join(report.Manifest.DangerousPerm, ", "),
				Severity:    "medium",
			})
		}
		if report.Manifest.ExportedComps > 10 {
			findings = append(findings, Finding{
				Category:    "attack_surface",
				Title:       "Many exported components",
				Description: strings.Repeat("", 0) + "Large attack surface with many exported activities/services/receivers",
				Severity:    "medium",
				Evidence:    strings.Repeat("", 0) + string(rune('0'+report.Manifest.ExportedComps)) + " exported components",
			})
		}
	}

	if report.Network != nil {
		if report.Network.HasCleartext {
			findings = append(findings, Finding{
				Category:    "network",
				Title:       "HTTP endpoints detected",
				Description: "Application communicates over unencrypted HTTP",
				Severity:    "medium",
			})
		}
		if !report.Network.HasCertPinning {
			findings = append(findings, Finding{
				Category:    "network",
				Title:       "No certificate pinning",
				Description: "Application does not implement SSL certificate pinning",
				Severity:    "low",
			})
		}
	}

	if report.Secrets != nil && report.Secrets.HighConfidence > 0 {
		findings = append(findings, Finding{
			Category:    "secrets",
			Title:       "Hardcoded secrets detected",
			Description: "High-confidence API keys, tokens, or credentials found in binary",
			Severity:    "high",
		})
	}

	if report.Telemetry != nil {
		for _, sf := range report.Telemetry.StealthFeatures {
			findings = append(findings, Finding{
				Category:    "stealth",
				Title:       sf.Type,
				Description: sf.Description,
				Severity:    sf.Risk,
				Evidence:    sf.Component,
			})
		}
	}

	if report.Certificate != nil && report.Certificate.Expired {
		findings = append(findings, Finding{
			Category:    "certificate",
			Title:       "Expired signing certificate",
			Description: "APK signing certificate has expired",
			Severity:    "medium",
		})
	}

	return findings
}
