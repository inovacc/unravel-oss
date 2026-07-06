/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"fmt"
	"sort"
	"strings"
)

// renderMarkdown produces a markdown forensic report for a single app.
func renderMarkdown(r *Report) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Forensic Report: %s\n\n", r.AppID))
	sb.WriteString(fmt.Sprintf("**Package:** `%s`\n", r.PackageName))
	sb.WriteString(fmt.Sprintf("**Version:** %s\n", r.Version))
	sb.WriteString(fmt.Sprintf("**Size:** %s\n", formatSize(r.Size)))
	sb.WriteString(fmt.Sprintf("**Risk Score:** %d/100 (%s)\n\n", r.RiskScore, strings.ToUpper(r.RiskLevel)))

	// Certificate
	if r.Certificate != nil {
		sb.WriteString("## Certificate\n\n")
		sb.WriteString(fmt.Sprintf("| Field | Value |\n|-------|-------|\n"))
		sb.WriteString(fmt.Sprintf("| Subject | %s |\n", r.Certificate.Subject))
		sb.WriteString(fmt.Sprintf("| Issuer | %s |\n", r.Certificate.Issuer))
		sb.WriteString(fmt.Sprintf("| Valid | %s → %s |\n", r.Certificate.NotBefore, r.Certificate.NotAfter))
		sb.WriteString(fmt.Sprintf("| SHA-256 | `%s` |\n", r.Certificate.SHA256))
		sb.WriteString(fmt.Sprintf("| Self-Signed | %v |\n", r.Certificate.SelfSigned))
		sb.WriteString(fmt.Sprintf("| Expired | %v |\n\n", r.Certificate.Expired))
	}

	// Manifest
	if r.Manifest != nil {
		sb.WriteString("## Manifest\n\n")
		sb.WriteString(fmt.Sprintf("- **Min SDK:** %d | **Target SDK:** %d\n", r.Manifest.MinSDK, r.Manifest.TargetSDK))
		sb.WriteString(fmt.Sprintf("- **Debuggable:** %v | **Allow Backup:** %v | **Cleartext:** %v\n", r.Manifest.Debuggable, r.Manifest.AllowBackup, r.Manifest.CleartextOK))
		sb.WriteString(fmt.Sprintf("- **Permissions:** %d total, %d dangerous\n", len(r.Manifest.Permissions), len(r.Manifest.DangerousPerm)))
		sb.WriteString(fmt.Sprintf("- **Exported Components:** %d\n\n", r.Manifest.ExportedComps))

		if len(r.Manifest.DangerousPerm) > 0 {
			sb.WriteString("### Dangerous Permissions\n\n")
			for _, p := range r.Manifest.DangerousPerm {
				sb.WriteString(fmt.Sprintf("- `%s`\n", p))
			}
			sb.WriteString("\n")
		}
	}

	// Network
	if r.Network != nil {
		sb.WriteString("## Network Communication\n\n")
		sb.WriteString(fmt.Sprintf("- **Total Endpoints:** %d\n", r.Network.TotalEndpoints))
		sb.WriteString(fmt.Sprintf("- **API Endpoints:** %d\n", len(r.Network.APIEndpoints)))
		sb.WriteString(fmt.Sprintf("- **Unique Domains:** %d\n", len(r.Network.Domains)))
		sb.WriteString(fmt.Sprintf("- **Certificate Pinning:** %v\n", r.Network.HasCertPinning))
		sb.WriteString(fmt.Sprintf("- **Cleartext HTTP:** %v\n\n", r.Network.HasCleartext))

		if len(r.Network.APIEndpoints) > 0 {
			sb.WriteString("### API Endpoints\n\n")
			sb.WriteString("| Category | Method | Host | Path |\n")
			sb.WriteString("|----------|--------|------|------|\n")

			shown := 0
			for _, ep := range r.Network.APIEndpoints {
				if shown >= 50 {
					sb.WriteString(fmt.Sprintf("| ... | ... | ... | +%d more |\n", len(r.Network.APIEndpoints)-50))
					break
				}
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", ep.Category, ep.Method, ep.Host, truncate(ep.Path, 60)))
				shown++
			}
			sb.WriteString("\n")
		}
	}

	// Secrets
	if r.Secrets != nil && r.Secrets.TotalFindings > 0 {
		sb.WriteString("## Secrets\n\n")
		sb.WriteString(fmt.Sprintf("- **Total:** %d findings\n", r.Secrets.TotalFindings))
		sb.WriteString(fmt.Sprintf("- **High Confidence:** %d\n\n", r.Secrets.HighConfidence))

		if len(r.Secrets.Categories) > 0 {
			sb.WriteString("| Type | Count |\n|------|-------|\n")
			for t, c := range r.Secrets.Categories {
				sb.WriteString(fmt.Sprintf("| %s | %d |\n", t, c))
			}
			sb.WriteString("\n")
		}
	}

	// Telemetry & SDKs
	if r.Telemetry != nil {
		sb.WriteString("## Telemetry & SDKs\n\n")
		sb.WriteString(fmt.Sprintf("- **SDKs Detected:** %d\n\n", r.Telemetry.SDKCount))

		if len(r.Telemetry.SDKs) > 0 {
			sb.WriteString("| SDK | Category | Confidence |\n")
			sb.WriteString("|-----|----------|------------|\n")
			for _, sdk := range r.Telemetry.SDKs {
				sb.WriteString(fmt.Sprintf("| %s | %s | %d%% |\n", sdk.Name, sdk.Category, sdk.Confidence))
			}
			sb.WriteString("\n")
		}

		if len(r.Telemetry.StealthFeatures) > 0 {
			sb.WriteString("### Stealth Features\n\n")
			for _, sf := range r.Telemetry.StealthFeatures {
				sb.WriteString(fmt.Sprintf("- **[%s]** %s — %s\n", strings.ToUpper(sf.Risk), sf.Type, sf.Description))
			}
			sb.WriteString("\n")
		}
	}

	// Findings
	if len(r.Findings) > 0 {
		sb.WriteString("## Findings\n\n")
		sb.WriteString("| Severity | Category | Title |\n")
		sb.WriteString("|----------|----------|-------|\n")
		for _, f := range r.Findings {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", strings.ToUpper(f.Severity), f.Category, f.Title))
		}
		sb.WriteString("\n")
	}

	// Curl scripts summary
	if len(r.CurlScripts) > 0 {
		sb.WriteString("## API Replay Scripts (curl)\n\n")
		sb.WriteString(fmt.Sprintf("Generated **%d** curl scripts for API communication replay.\n\n", len(r.CurlScripts)))
		sb.WriteString("See `curl/` directory for executable scripts by category:\n\n")

		cats := map[string]int{}
		for _, cs := range r.CurlScripts {
			cats[cs.Category]++
		}
		for cat, count := range cats {
			sb.WriteString(fmt.Sprintf("- `curl/%s.sh` — %d endpoints\n", cat, count))
		}
		sb.WriteString(fmt.Sprintf("- `curl/replay-all.sh` — all %d endpoints\n", len(r.CurlScripts)))
	}

	return sb.String()
}

// renderBatchSummary produces the batch summary markdown.
func renderBatchSummary(batch *BatchReport) string {
	var sb strings.Builder

	sb.WriteString("# Forensic Summary Report\n\n")
	sb.WriteString(fmt.Sprintf("**Total Apps Analyzed:** %d\n\n", batch.TotalApps))

	// Risk distribution
	riskDist := map[string]int{}
	for _, app := range batch.Apps {
		riskDist[app.RiskLevel]++
	}

	sb.WriteString("## Risk Distribution\n\n")
	sb.WriteString("| Level | Count |\n|-------|-------|\n")
	for _, level := range []string{"critical", "high", "medium", "low"} {
		if count, ok := riskDist[level]; ok {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(level), count))
		}
	}
	sb.WriteString("\n")

	// Top 20 riskiest apps
	sb.WriteString("## Top 20 Riskiest Apps\n\n")
	sb.WriteString("| # | App | Score | Level | Secrets | Endpoints | SDKs |\n")
	sb.WriteString("|---|-----|-------|-------|---------|-----------|------|\n")
	for i, app := range batch.TopRisks {
		secrets := 0
		if app.Secrets != nil {
			secrets = app.Secrets.HighConfidence
		}
		endpoints := 0
		if app.Network != nil {
			endpoints = len(app.Network.APIEndpoints)
		}
		sdks := 0
		if app.Telemetry != nil {
			sdks = app.Telemetry.SDKCount
		}
		sb.WriteString(fmt.Sprintf("| %d | %s | %d | %s | %d | %d | %d |\n",
			i+1, app.AppID, app.RiskScore, strings.ToUpper(app.RiskLevel), secrets, endpoints, sdks))
	}
	sb.WriteString("\n")

	// Most common domains
	sb.WriteString("## Most Contacted Domains\n\n")
	sb.WriteString("| Domain | Apps |\n|--------|------|\n")
	type domCount struct {
		domain string
		count  int
	}
	var doms []domCount
	for d, apps := range batch.DomainIndex {
		doms = append(doms, domCount{d, len(apps)})
	}
	sort.Slice(doms, func(i, j int) bool { return doms[i].count > doms[j].count })
	shown := 0
	for _, dc := range doms {
		if shown >= 30 {
			break
		}
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", dc.domain, dc.count))
		shown++
	}
	sb.WriteString("\n")

	// Most common SDKs
	sb.WriteString("## Most Common SDKs\n\n")
	sb.WriteString("| SDK | Apps |\n|-----|------|\n")
	type sdkCount struct {
		sdk   string
		count int
	}
	var sdkCounts []sdkCount
	for s, apps := range batch.SDKIndex {
		sdkCounts = append(sdkCounts, sdkCount{s, len(apps)})
	}
	sort.Slice(sdkCounts, func(i, j int) bool { return sdkCounts[i].count > sdkCounts[j].count })
	shown = 0
	for _, sc := range sdkCounts {
		if shown >= 20 {
			break
		}
		sb.WriteString(fmt.Sprintf("| %s | %d |\n", sc.sdk, sc.count))
		shown++
	}

	return sb.String()
}

// renderDomainIndex produces a domain → apps index.
func renderDomainIndex(batch *BatchReport) string {
	var sb strings.Builder
	sb.WriteString("# Domain Index\n\n")
	sb.WriteString("Which apps communicate with which domains.\n\n")

	type entry struct {
		domain string
		apps   []string
	}
	var entries []entry
	for d, apps := range batch.DomainIndex {
		entries = append(entries, entry{d, apps})
	}
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].apps) > len(entries[j].apps) })

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("## %s (%d apps)\n\n", e.domain, len(e.apps)))
		for _, app := range e.apps {
			sb.WriteString(fmt.Sprintf("- %s\n", app))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderSDKIndex produces an SDK → apps index.
func renderSDKIndex(batch *BatchReport) string {
	var sb strings.Builder
	sb.WriteString("# SDK Index\n\n")
	sb.WriteString("Which apps include which tracking/analytics SDKs.\n\n")

	type entry struct {
		sdk  string
		apps []string
	}
	var entries []entry
	for s, apps := range batch.SDKIndex {
		entries = append(entries, entry{s, apps})
	}
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].apps) > len(entries[j].apps) })

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("## %s (%d apps)\n\n", e.sdk, len(e.apps)))
		for _, app := range e.apps {
			sb.WriteString(fmt.Sprintf("- %s\n", app))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
