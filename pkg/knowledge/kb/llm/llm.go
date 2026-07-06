// Package llm routes prompt → text completions exclusively through the
// MCP sampling seam.
//
// Call is usable only from inside an MCP server session whose host
// supports sampling (Claude Code, Cursor, etc). Naked CLI invocations
// have no resolver wired and will return ErrNoSamplingClient rather
// than fan out subprocesses.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoSamplingClient is returned by Call when no sampling resolver is
// wired or the wired resolver returns nil. Callers can use errors.Is to
// distinguish "no host" from "host transport error" if they want to
// downgrade to a soft-fail.
var ErrNoSamplingClient = errors.New("llm: no MCP sampling client wired (this binary must run as an MCP server child of a host that supports sampling)")

// samplingResolver is the package-level seam for MCP sampling. Set by
// production wiring (llm_sampling_wire.go) or overridden in tests.
// A nil resolver causes Call to return ErrNoSamplingClient.
var samplingResolver func() SamplingClient

// Call routes the prompt through the wired MCP sampling client and
// returns the host's completion text. The model parameter is silently
// ignored — the host picks the model from its own session context. The
// timeout is applied to the request ctx so a stalled host can be
// abandoned without leaking goroutines.
//
// Errors:
//   - ErrNoSamplingClient: no sampling host is wired (run as MCP child)
//   - any other error: surfaced from the sampling adapter
func Call(ctx context.Context, _ string, prompt string, timeout time.Duration) (string, error) {
	if samplingResolver == nil {
		return "", ErrNoSamplingClient
	}
	sc := samplingResolver()
	if sc == nil {
		return "", ErrNoSamplingClient
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := sc.Summarize(cctx, prompt)
	if err != nil {
		return "", fmt.Errorf("sampling: %w", err)
	}
	return string(body), nil
}

// ParseJSON extracts the first balanced top-level {...} block from raw and
// unmarshals it into v. Strips ```json fences and any leading prose.
func ParseJSON(raw string, v any) error {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "```") {
		if i := strings.Index(s, "\n"); i > 0 {
			s = s[i+1:]
		}
		if j := strings.LastIndex(s, "```"); j > 0 {
			s = s[:j]
		}
	}
	start := strings.Index(s, "{")
	if start < 0 {
		return fmt.Errorf("no JSON object found in response")
	}
	depth := 0
	end := -1
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if c == '\\' && inStr {
			esc = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
	}
	if end < 0 {
		return fmt.Errorf("unbalanced braces")
	}
	if err := json.Unmarshal([]byte(s[start:end]), v); err != nil {
		return fmt.Errorf("unmarshal: %w (json=%s)", err, s[start:end])
	}
	return nil
}

// ExtractFirstJSONArray returns the first balanced [...] block found in s,
// or s itself unchanged if no such block exists.
func ExtractFirstJSONArray(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "["); i >= 0 {
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return s[i : j+1]
				}
			}
		}
	}
	return s
}
