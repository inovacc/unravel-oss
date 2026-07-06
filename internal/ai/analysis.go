/*
Copyright (c) 2026 Security Research
*/
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AnalysisResult holds the AI-generated deep analysis of an Android app.
type AnalysisResult struct {
	Manifest         string        `json:"manifest"`
	CodeArchitecture string        `json:"code_architecture"`
	SecurityFindings string        `json:"security_findings"`
	NetworkSurface   string        `json:"network_surface"`
	SecretsExposed   string        `json:"secrets_exposed"`
	Obfuscation      string        `json:"obfuscation"`
	RiskAssessment   string        `json:"risk_assessment"`
	Usage            *Usage        `json:"usage,omitempty"`
	Duration         time.Duration `json:"duration"`
}

// AnalyzeAndroid sends the dissect results to Claude for deep AI-powered analysis.
// The systemPrompt is the extraction checklist (from GenerateAIPrompt).
// The dataSummary is a structured summary of the actual analysis data.
func AnalyzeAndroid(ctx context.Context, client *Client, systemPrompt, dataSummary string) (*AnalysisResult, error) {
	start := time.Now()

	resp, err := client.Analyze(ctx, systemPrompt, dataSummary)
	if err != nil {
		return nil, fmt.Errorf("AI analysis: %w", err)
	}

	result := parseAnalysisResponse(resp.Content)
	result.Usage = &resp.Usage
	result.Duration = time.Since(start)

	return result, nil
}

// AnalyzeAndroidStream runs AI analysis with streaming progress updates.
// The cb callback is invoked with each text chunk as it arrives from the API.
func AnalyzeAndroidStream(ctx context.Context, client *Client, systemPrompt, dataSummary string, cb StreamCallback) (*AnalysisResult, error) {
	start := time.Now()

	resp, err := client.AnalyzeStream(ctx, systemPrompt, dataSummary, cb)
	if err != nil {
		return nil, fmt.Errorf("AI analysis: %w", err)
	}

	result := parseAnalysisResponse(resp.Content)
	result.Usage = &Usage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}
	result.Duration = time.Since(start)

	return result, nil
}

// BuildDataSummary constructs a compact text summary of the dissect analysis
// results to send as user content alongside the AI system prompt.
// It takes the JSON-serialized DissectResult to avoid circular imports.
func BuildDataSummary(dissectJSON []byte) string {
	var sb strings.Builder

	sb.WriteString("# Android APK Analysis Data\n\n")
	sb.WriteString("Below is the complete structured analysis data collected by unravel.\n")
	sb.WriteString("Use this data alongside the system prompt instructions to produce\n")
	sb.WriteString("an exhaustive, detailed analysis of every resource in this APK.\n\n")
	sb.WriteString("```json\n")
	sb.Write(dissectJSON)
	sb.WriteString("\n```\n")

	return sb.String()
}

// MarshalDissectForAI serializes the dissect result to compact JSON
// suitable for sending to the AI. It strips large fields to keep
// the payload within API limits (~4MB target).
func MarshalDissectForAI(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return data, nil
	}

	// Remove fields not needed for AI analysis
	delete(m, "ai_prompt")
	delete(m, "analyses")
	delete(m, "beautified_js")

	// Trim DEX analysis: remove full string pools and keep only summaries + findings
	if dex, ok := m["dex_analysis"].(map[string]any); ok {
		if files, ok := dex["dex_files"].([]any); ok {
			for _, f := range files {
				if df, ok := f.(map[string]any); ok {
					delete(df, "strings") // full string pool is huge
					delete(df, "types")   // full type list
					delete(df, "fields")  // full field list
					// Keep classes (names only) and methods (for API analysis)
					trimSlice(df, "classes", 500)
					trimSlice(df, "methods", 500)
				}
			}
		}
		// Keep high-entropy strings and risk findings (already small)
		trimSlice(dex, "high_entropy_strings", 100)
	}

	// Trim network analysis: keep domains and pinning, limit endpoints
	if net, ok := m["network_analysis"].(map[string]any); ok {
		trimSlice(net, "endpoints", 200)
		trimSlice(net, "domains", 100)
	}

	// Trim secrets: limit findings
	if secrets, ok := m["secrets"].(map[string]any); ok {
		trimSlice(secrets, "findings", 200)
	}

	// Trim resource analysis: limit assets list
	if res, ok := m["resource_analysis"].(map[string]any); ok {
		trimSlice(res, "assets", 100)
		if sp, ok := res["string_pool"].(map[string]any); ok {
			trimSlice(sp, "sample_strings", 20)
		}
	}

	return json.Marshal(m)
}

// trimSlice truncates a JSON array field to maxLen entries.
func trimSlice(m map[string]any, key string, maxLen int) {
	if arr, ok := m[key].([]any); ok && len(arr) > maxLen {
		m[key] = arr[:maxLen]
	}
}

// sectionKeywords maps keyword substrings (lowercase) to their target field pointer.
// The lookup iterates this slice in order, so more-specific keys should come first.
func sectionKeywords(r *AnalysisResult) []struct {
	keyword string
	field   *string
} {
	return []struct {
		keyword string
		field   *string
	}{
		{"manifest", &r.Manifest},
		{"architecture", &r.CodeArchitecture},
		{"code", &r.CodeArchitecture},
		{"security", &r.SecurityFindings},
		{"network", &r.NetworkSurface},
		{"api", &r.NetworkSurface},
		{"credential", &r.SecretsExposed},
		{"secret", &r.SecretsExposed},
		{"key", &r.SecretsExposed},
		{"obfuscat", &r.Obfuscation},
		{"protect", &r.Obfuscation},
		{"risk", &r.RiskAssessment},
	}
}

// matchSection returns the result field pointer for a header string, or nil if
// no keyword matches. The header should already be lowercased.
func matchSection(header string, keywords []struct {
	keyword string
	field   *string
}) *string {
	for _, kw := range keywords {
		if strings.Contains(header, kw.keyword) {
			return kw.field
		}
	}
	return nil
}

// stripBullet removes a leading bullet marker ("- " or "* ") from a line.
func stripBullet(line string) string {
	if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
		return line[2:]
	}
	return line
}

// parseXMLSections extracts content from XML-like tags (case-insensitive).
// It returns a map from lowercased tag name to accumulated content, and
// reports whether any tags were found.
func parseXMLSections(response string, keywords []struct {
	keyword string
	field   *string
}) (found bool) {
	// Walk through every "<tag>" opener.
	remaining := response
	for {
		openStart := strings.Index(remaining, "<")
		if openStart == -1 {
			break
		}
		openEnd := strings.Index(remaining[openStart:], ">")
		if openEnd == -1 {
			break
		}
		tag := remaining[openStart+1 : openStart+openEnd]

		// Skip closing tags and tags with spaces (attributes / HTML).
		if strings.HasPrefix(tag, "/") || strings.ContainsAny(tag, " \t") {
			remaining = remaining[openStart+openEnd+1:]
			continue
		}

		closeTag := "</" + tag + ">"
		closeIdx := strings.Index(remaining, closeTag)
		if closeIdx == -1 {
			remaining = remaining[openStart+openEnd+1:]
			continue
		}

		content := strings.TrimSpace(remaining[openStart+openEnd+1 : closeIdx])
		remaining = remaining[closeIdx+len(closeTag):]

		tagLower := strings.ToLower(tag)
		field := matchSection(tagLower, keywords)
		if field == nil {
			continue
		}

		// Strip bullets from each content line.
		lines := strings.Split(content, "\n")
		for i, l := range lines {
			lines[i] = stripBullet(l)
		}
		content = strings.TrimSpace(strings.Join(lines, "\n"))

		if *field == "" {
			*field = content
		} else {
			*field += "\n\n" + content
		}
		found = true
	}
	return found
}

// isMarkdownHeader reports whether line is a markdown section header
// (# / ## / ###) or a numbered section header ("1. Title" or "**1. Title**").
// It returns the lowercased header text (without the prefix).
func isMarkdownHeader(line string) (header string, ok bool) {
	// Markdown ATX headers: # / ## / ###
	for _, prefix := range []string{"### ", "## ", "# "} {
		if strings.HasPrefix(line, prefix) {
			return strings.ToLower(strings.TrimSpace(line[len(prefix):])), true
		}
	}

	// Numbered sections: "1. Title" or "**1. Title**"
	trimmed := strings.TrimPrefix(line, "**")
	trimmed = strings.TrimSuffix(trimmed, "**")
	trimmed = strings.TrimSpace(trimmed)

	// Check for "N. " prefix where N is one or more digits.
	i := 0
	for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
		i++
	}
	if i > 0 && strings.HasPrefix(trimmed[i:], ". ") {
		return strings.ToLower(strings.TrimSpace(trimmed[i+2:])), true
	}

	return "", false
}

// parseMarkdownSections populates result fields from markdown-formatted text.
func parseMarkdownSections(response string, keywords []struct {
	keyword string
	field   *string
}) bool {
	lines := strings.Split(response, "\n")

	var (
		currentField *string
		sectionLines []string
		found        bool
	)

	flush := func() {
		if currentField == nil || len(sectionLines) == 0 {
			sectionLines = nil
			return
		}
		content := strings.TrimSpace(strings.Join(sectionLines, "\n"))
		if content == "" {
			sectionLines = nil
			return
		}
		if *currentField == "" {
			*currentField = content
		} else {
			*currentField += "\n\n" + content
		}
		sectionLines = nil
	}

	for _, line := range lines {
		if header, ok := isMarkdownHeader(line); ok {
			flush()
			currentField = matchSection(header, keywords)
			if currentField != nil {
				found = true
			}
			continue
		}

		if currentField != nil {
			sectionLines = append(sectionLines, stripBullet(line))
		}
	}
	flush()

	return found
}

// parseAnalysisResponse extracts structured sections from the AI response.
// XML tags take priority over markdown headers when both are present.
func parseAnalysisResponse(response string) *AnalysisResult {
	result := &AnalysisResult{}
	keywords := sectionKeywords(result)

	// Try XML-style tags first; they take priority.
	if parseXMLSections(response, keywords) {
		return result
	}

	// Fall back to markdown / numbered-section parsing.
	if parseMarkdownSections(response, keywords) {
		return result
	}

	// No recognisable structure — put the whole response in SecurityFindings.
	result.SecurityFindings = response
	return result
}
