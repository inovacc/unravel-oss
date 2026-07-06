/*
Copyright (c) 2026 Security Research
*/
package enrich

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

// Header marker comment used to identify a script that has already received
// an enrichment header. Re-runs idempotently strip and replace the header.
const enrichHeaderMarker = "/** [unravel-enriched header]"
const enrichHeaderEnd = "[unravel-enriched header end] */"

// hookAttachRE matches `Interceptor.attach(<id>...)` blocks. The captured
// group 1 is the hook id token (best-effort symbol — matches the leading
// identifier passed to attach). When the leading argument isn't a bare
// identifier we fall back to a positional id.
var hookAttachRE = regexp.MustCompile(`Interceptor\.attach\s*\(\s*([A-Za-z_$][\w$.]*)`)

// renderArtifacts produces the rewritten script body and the criteria.json
// payload from the original script + AI response. Returns (script, criteria,
// err).
func renderArtifacts(originalScript string, resp EnrichResponse, scriptBaseName string) (string, frida.CriteriaFile, error) {
	stripped := stripExistingHeader(originalScript)
	header := buildHeader(resp.HeaderSummary)
	withHooks, err := injectPerHookComments(stripped, resp.Hooks)
	if err != nil {
		return "", frida.CriteriaFile{}, err
	}
	final := header + withHooks
	criteria := frida.CriteriaFile{
		SchemaVersion: 1,
		Script:        scriptBaseName,
		Hooks:         buildHookCriteria(resp.Hooks),
	}
	return final, criteria, nil
}

func stripExistingHeader(src string) string {
	idx := strings.Index(src, enrichHeaderMarker)
	if idx < 0 {
		return src
	}
	end := strings.Index(src, enrichHeaderEnd)
	if end < 0 || end < idx {
		return src
	}
	return src[end+len(enrichHeaderEnd):]
}

func buildHeader(summary string) string {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		summary = "Frida script (header summary unavailable)."
	}
	var b strings.Builder
	b.WriteString(enrichHeaderMarker)
	b.WriteString("\n * ")
	for _, line := range splitLines(summary, 100) {
		b.WriteString(line)
		b.WriteString("\n * ")
	}
	b.WriteString("\n " + enrichHeaderEnd + "\n")
	return b.String()
}

// injectPerHookComments walks the script and prepends a JSDoc block above
// each `Interceptor.attach(...)` call that matches a hook id from resp.
func injectPerHookComments(src string, hooks []HookEnrichment) (string, error) {
	if len(hooks) == 0 {
		return src, nil
	}
	byID := map[string]HookEnrichment{}
	for _, h := range hooks {
		byID[h.ID] = h
	}
	matches := hookAttachRE.FindAllStringSubmatchIndex(src, -1)
	if len(matches) == 0 {
		return src, nil
	}
	var out strings.Builder
	cursor := 0
	posIdx := 0
	for _, m := range matches {
		matchStart := m[0]
		idStart, idEnd := m[2], m[3]
		hookToken := src[idStart:idEnd]
		var enrich HookEnrichment
		var ok bool
		enrich, ok = byID[hookToken]
		if !ok {
			fallbackKey := fmt.Sprintf("hook_%d", posIdx)
			enrich, ok = byID[fallbackKey]
		}
		posIdx++
		if !ok {
			continue
		}
		out.WriteString(src[cursor:matchStart])
		out.WriteString(buildJSDoc(enrich))
		cursor = matchStart
	}
	out.WriteString(src[cursor:])
	return out.String(), nil
}

func buildJSDoc(h HookEnrichment) string {
	var b strings.Builder
	b.WriteString("/**\n")
	b.WriteString(" * Hook: ")
	b.WriteString(h.ID)
	b.WriteString("\n")
	if h.Summary != "" {
		b.WriteString(" * What:  ")
		b.WriteString(stripJSDocBreakers(h.Summary))
		b.WriteString("\n")
	}
	if h.WhyItMatters != "" {
		b.WriteString(" * Why:   ")
		b.WriteString(stripJSDocBreakers(h.WhyItMatters))
		b.WriteString("\n")
	}
	if h.WatchFor != "" {
		b.WriteString(" * Watch: ")
		b.WriteString(stripJSDocBreakers(h.WatchFor))
		b.WriteString("\n")
	}
	b.WriteString(" */\n")
	return b.String()
}

// stripJSDocBreakers removes the `*/` sequence so injected prose can never
// terminate the surrounding JSDoc block. Mitigates T-09-06 at the rendering
// boundary (parse-check is the second line of defence).
func stripJSDocBreakers(s string) string {
	s = strings.ReplaceAll(s, "*/", "* /")
	// Also flatten control characters that would break JSDoc structure.
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func splitLines(s string, width int) []string {
	if width <= 0 {
		width = 80
	}
	var out []string
	for len(s) > width {
		cut := width
		if idx := strings.LastIndex(s[:width], " "); idx > 0 {
			cut = idx
		}
		out = append(out, s[:cut])
		s = strings.TrimSpace(s[cut:])
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

func buildHookCriteria(hooks []HookEnrichment) []frida.HookCriteria {
	out := make([]frida.HookCriteria, 0, len(hooks))
	for _, h := range hooks {
		hc := frida.HookCriteria{
			ID:          h.ID,
			Description: h.Summary,
		}
		for _, a := range h.Expected.Args {
			hc.Criteria = append(hc.Criteria, frida.Criterion{
				Op:      a.Op,
				Target:  fmt.Sprintf("args[%d]", a.Index),
				Value:   a.Value,
				Pattern: a.Pattern,
				Min:     a.Min,
				Max:     a.Max,
			})
		}
		if h.Expected.Return != nil {
			r := h.Expected.Return
			hc.Criteria = append(hc.Criteria, frida.Criterion{
				Op:      r.Op,
				Target:  "return",
				Value:   r.Value,
				Pattern: r.Pattern,
				Min:     r.Min,
				Max:     r.Max,
			})
		}
		if h.Expected.CallCount != nil {
			hc.Criteria = append(hc.Criteria, frida.Criterion{
				Op:     "frequency-count",
				Target: h.ID,
				Min:    h.Expected.CallCount.Min,
				Max:    h.Expected.CallCount.Max,
			})
		}
		for _, vc := range h.Expected.ValueConstraints {
			hc.Criteria = append(hc.Criteria, frida.Criterion{
				Op:      vc.Op,
				Target:  vc.Target,
				Value:   vc.Value,
				Pattern: vc.Pattern,
				Min:     vc.Min,
				Max:     vc.Max,
			})
		}
		out = append(out, hc)
	}
	return out
}

// writeArtifacts atomically writes the enriched script and criteria.json
// using knowledge.WriteFileAtomic / knowledge.WriteJSONAtomic (D-22).
// Reference: "github.com/inovacc/unravel-oss/pkg/knowledge/atomic" — see import above.
func writeArtifacts(scriptAbs, scriptBody string, criteria frida.CriteriaFile) error {
	if err := knowledge.WriteFileAtomic(scriptAbs, []byte(scriptBody), 0o644); err != nil {
		return fmt.Errorf("write script: %w", err)
	}
	if err := knowledge.WriteJSONAtomic(criteriaSiblingPath(scriptAbs), criteria); err != nil {
		return fmt.Errorf("write criteria: %w", err)
	}
	return nil
}
