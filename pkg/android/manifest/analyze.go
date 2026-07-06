/*
Copyright (c) 2026 Security Research
*/
package manifest

import "strings"

// Analysis holds the security analysis results derived from a parsed Manifest.
type Analysis struct {
	SecurityScore     int               `json:"security_score"` // 0-100 (higher = more risk)
	RiskLevel         string            `json:"risk_level"`     // "low", "medium", "high", "critical"
	PermissionSummary PermissionSummary `json:"permission_summary"`
	ComponentRisks    []ComponentRisk   `json:"component_risks,omitempty"`
	DeepLinks         []DeepLink        `json:"deep_links,omitempty"`
	SecurityIssues    []SecurityIssue   `json:"security_issues"`
}

// PermissionSummary aggregates permission statistics and groups.
type PermissionSummary struct {
	Total     int                 `json:"total"`
	Dangerous int                 `json:"dangerous"`
	Signature int                 `json:"signature"`
	Normal    int                 `json:"normal"`
	Unknown   int                 `json:"unknown"`
	Groups    map[string][]string `json:"groups,omitempty"` // group name -> permission names
}

// ComponentRisk identifies an exported component with potential security issues.
type ComponentRisk struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Risk           string `json:"risk"` // "high", "medium", "low"
	Reason         string `json:"reason"`
	ImplicitExport bool   `json:"implicit_export,omitempty"`
}

// DeepLink represents a deep link URI pattern found in an intent filter.
type DeepLink struct {
	URI       string `json:"uri"`
	Component string `json:"component"`
	Guarded   bool   `json:"guarded"` // has permission requirement
}

// SecurityIssue represents a specific finding from manifest analysis.
type SecurityIssue struct {
	Severity    string `json:"severity"` // "critical", "high", "medium", "low", "info"
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Analyze performs security analysis on a parsed Manifest and returns findings.
func Analyze(m *Manifest) *Analysis {
	a := &Analysis{}

	a.PermissionSummary = analyzePermissions(m.Permissions)
	a.ComponentRisks = analyzeComponents(m)
	a.DeepLinks = extractDeepLinks(m)
	a.SecurityIssues = findSecurityIssues(m, a)
	a.SecurityScore = calculateScore(m, a)
	a.RiskLevel = scoreToLevel(a.SecurityScore)

	return a
}

func analyzePermissions(perms []Permission) PermissionSummary {
	s := PermissionSummary{
		Total:  len(perms),
		Groups: make(map[string][]string),
	}

	for _, p := range perms {
		switch p.RiskLevel {
		case "dangerous":
			s.Dangerous++
		case "signature":
			s.Signature++
		case "normal":
			s.Normal++
		default:
			s.Unknown++
		}

		if group := permissionGroup(p.Name); group != "" {
			s.Groups[group] = append(s.Groups[group], p.Name)
		}
	}

	return s
}

func analyzeComponents(m *Manifest) []ComponentRisk {
	var risks []ComponentRisk

	for _, c := range m.Components {
		exported := false
		implicit := false

		if c.Exported != nil {
			exported = *c.Exported
		} else if len(c.IntentFilters) > 0 && m.TargetSDK < 31 {
			// Before API 31, components with intent-filters are implicitly exported
			exported = true
			implicit = true
		}

		if !exported {
			continue
		}

		risk := "low"
		reason := "exported component"

		if c.Permission == "" {
			risk = "high"
			reason = "exported without permission guard"
			if implicit {
				reason = "implicitly exported (has intent-filter, targetSdk < 31) without permission guard"
			}
		} else {
			risk = "medium"
			reason = "exported with permission: " + c.Permission
		}

		if c.Type == ComponentProvider && c.Permission == "" {
			risk = "high"
			reason = "content provider exported without permission — data exposure risk"
		}

		risks = append(risks, ComponentRisk{
			Name:           c.Name,
			Type:           string(c.Type),
			Risk:           risk,
			Reason:         reason,
			ImplicitExport: implicit,
		})
	}

	return risks
}

func extractDeepLinks(m *Manifest) []DeepLink {
	var links []DeepLink

	for _, c := range m.Components {
		for _, f := range c.IntentFilters {
			for _, d := range f.Data {
				if d.Scheme == "" {
					continue
				}

				uri := d.Scheme + "://"
				if d.Host != "" {
					uri += d.Host
				}
				if d.Path != "" {
					uri += d.Path
				}

				links = append(links, DeepLink{
					URI:       uri,
					Component: c.Name,
					Guarded:   c.Permission != "",
				})
			}
		}
	}

	return links
}

func findSecurityIssues(m *Manifest, a *Analysis) []SecurityIssue {
	var issues []SecurityIssue

	// Security flags
	if m.Security.Debuggable {
		issues = append(issues, SecurityIssue{
			Severity:    "critical",
			Title:       "Application is debuggable",
			Description: "android:debuggable=true allows attaching a debugger and inspecting runtime state",
		})
	}

	if m.Security.AllowBackup {
		issues = append(issues, SecurityIssue{
			Severity:    "medium",
			Title:       "Backup is enabled",
			Description: "android:allowBackup=true allows data extraction via adb backup",
		})
	}

	if m.Security.UsesCleartextTraffic {
		issues = append(issues, SecurityIssue{
			Severity:    "high",
			Title:       "Cleartext traffic allowed",
			Description: "android:usesCleartextTraffic=true permits unencrypted HTTP connections",
		})
	}

	if !m.Security.NetworkSecurityConfig {
		issues = append(issues, SecurityIssue{
			Severity:    "info",
			Title:       "No network security config",
			Description: "No custom networkSecurityConfig defined; using platform defaults",
		})
	}

	// SDK version checks
	if m.TargetSDK > 0 && m.TargetSDK < 28 {
		issues = append(issues, SecurityIssue{
			Severity:    "high",
			Title:       "Low target SDK",
			Description: "targetSdkVersion < 28 misses important security defaults (cleartext blocked, etc.)",
		})
	}

	if m.MinSDK > 0 && m.MinSDK < 21 {
		issues = append(issues, SecurityIssue{
			Severity:    "medium",
			Title:       "Very low minimum SDK",
			Description: "minSdkVersion < 21 supports devices without full TLS 1.2 and ART runtime",
		})
	}

	// Permission findings
	if a.PermissionSummary.Dangerous > 5 {
		issues = append(issues, SecurityIssue{
			Severity:    "medium",
			Title:       "Many dangerous permissions",
			Description: strings.Join([]string{"App requests", itoa(a.PermissionSummary.Dangerous), "dangerous permissions"}, " "),
		})
	}

	// Unguarded exported components
	highRiskComponents := 0
	for _, cr := range a.ComponentRisks {
		if cr.Risk == "high" {
			highRiskComponents++
		}
	}
	if highRiskComponents > 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "high",
			Title:       "Unguarded exported components",
			Description: strings.Join([]string{itoa(highRiskComponents), "exported components without permission guards"}, " "),
		})
	}

	// Unguarded deep links
	unguardedLinks := 0
	for _, dl := range a.DeepLinks {
		if !dl.Guarded {
			unguardedLinks++
		}
	}
	if unguardedLinks > 0 {
		issues = append(issues, SecurityIssue{
			Severity:    "medium",
			Title:       "Unguarded deep links",
			Description: strings.Join([]string{itoa(unguardedLinks), "deep link URIs without permission protection"}, " "),
		})
	}

	return issues
}

func calculateScore(m *Manifest, a *Analysis) int {
	score := 0

	// Security flags (up to 35 points)
	if m.Security.Debuggable {
		score += 25
	}
	if m.Security.UsesCleartextTraffic {
		score += 10
	}

	// Permissions (up to 20 points)
	score += min(a.PermissionSummary.Dangerous*2, 20)

	// Component risks (up to 25 points)
	for _, cr := range a.ComponentRisks {
		switch cr.Risk {
		case "high":
			score += 5
		case "medium":
			score += 2
		}
	}
	score = min(score, 80) // cap component contribution

	// SDK version (up to 10 points)
	if m.TargetSDK > 0 && m.TargetSDK < 28 {
		score += 10
	} else if m.TargetSDK > 0 && m.TargetSDK < 31 {
		score += 5
	}

	// Deep links (up to 10 points)
	for _, dl := range a.DeepLinks {
		if !dl.Guarded {
			score += 3
		}
	}

	return min(score, 100)
}

func scoreToLevel(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 45:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}

// permissionGroup returns the Android permission group for a permission name.
func permissionGroup(name string) string {
	groups := map[string]string{
		"BODY_SENSORS": "sensors", "BODY_SENSORS_BACKGROUND": "sensors",
		"READ_CALENDAR": "calendar", "WRITE_CALENDAR": "calendar",
		"READ_CALL_LOG": "call_log", "WRITE_CALL_LOG": "call_log", "PROCESS_OUTGOING_CALLS": "call_log",
		"CAMERA":        "camera",
		"READ_CONTACTS": "contacts", "WRITE_CONTACTS": "contacts", "GET_ACCOUNTS": "contacts",
		"ACCESS_FINE_LOCATION": "location", "ACCESS_COARSE_LOCATION": "location", "ACCESS_BACKGROUND_LOCATION": "location",
		"RECORD_AUDIO":     "microphone",
		"READ_PHONE_STATE": "phone", "READ_PHONE_NUMBERS": "phone", "CALL_PHONE": "phone",
		"ANSWER_PHONE_CALLS": "phone", "ADD_VOICEMAIL": "phone", "USE_SIP": "phone",
		"SEND_SMS": "sms", "RECEIVE_SMS": "sms", "READ_SMS": "sms",
		"RECEIVE_WAP_PUSH": "sms", "RECEIVE_MMS": "sms",
		"READ_EXTERNAL_STORAGE": "storage", "WRITE_EXTERNAL_STORAGE": "storage",
		"MANAGE_EXTERNAL_STORAGE": "storage", "ACCESS_MEDIA_LOCATION": "storage",
		"READ_MEDIA_IMAGES": "storage", "READ_MEDIA_VIDEO": "storage", "READ_MEDIA_AUDIO": "storage",
		"BLUETOOTH_CONNECT": "nearby", "BLUETOOTH_SCAN": "nearby",
		"BLUETOOTH_ADVERTISE": "nearby", "NEARBY_WIFI_DEVICES": "nearby",
		"POST_NOTIFICATIONS":   "notifications",
		"ACTIVITY_RECOGNITION": "activity_recognition",
	}

	// Extract the short name from android.permission.XXX
	short := name
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		short = name[idx+1:]
	}

	return groups[short]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
