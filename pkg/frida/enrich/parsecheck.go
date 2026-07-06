// Copyright (c) 2026 Security Research
//
// Phase 9 D-19 / T-09-06: regex-only structural-preservation guard for the
// enriched Frida script. Catches the three breakage modes that comment
// injection can introduce:
//
//  1. unclosed block comments (rendered comment lacks closing token).
//  2. orphan close-comment (a stray close-comment outside any open block).
//  3. broken JSDoc string escapes (a backslash followed by EOF inside a
//     JSDoc literal — handled by checking we never end mid-escape).
//
// If real fixtures show false positives, escalate to a goja parse per the
// research doc.
package enrich

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	errUnclosedBlock      = errors.New("parse-check: unclosed /* */ block")
	errOrphanCloseComment = errors.New("parse-check: orphan */ outside any block")
	errBrokenEscape       = errors.New("parse-check: broken string escape near EOF")
)

// blockOpenRE counts /* opens (not preceded by `*` to ignore mid-block stars).
var blockOpenRE = regexp.MustCompile(`/\*`)
var blockCloseRE = regexp.MustCompile(`\*/`)

// parseCheck enforces the three rules above. Operates on the rendered
// script body. Returns nil when the script passes. Wrapped errors carry
// enough context for the orchestrator's caller to surface a useful message.
func parseCheck(s string) error {
	if err := checkBlockComments(s); err != nil {
		return err
	}
	if err := checkBrokenEscapes(s); err != nil {
		return err
	}
	return nil
}

// checkBlockComments walks the body once and confirms that every /* is
// followed by a matching */ before the next /* opens. An orphan */ outside
// any open block is also rejected (mode 2 from the file header).
func checkBlockComments(s string) error {
	opens := blockOpenRE.FindAllStringIndex(s, -1)
	closes := blockCloseRE.FindAllStringIndex(s, -1)
	if len(opens) != len(closes) {
		if len(opens) > len(closes) {
			return fmt.Errorf("%w (opens=%d closes=%d)", errUnclosedBlock, len(opens), len(closes))
		}
		return fmt.Errorf("%w (opens=%d closes=%d)", errOrphanCloseComment, len(opens), len(closes))
	}
	// Pair them in order: open[i] must precede close[i], and close[i] must
	// precede open[i+1].
	for i := range opens {
		if opens[i][0] >= closes[i][0] {
			return fmt.Errorf("%w (orphan close at %d)", errOrphanCloseComment, closes[i][0])
		}
		if i+1 < len(opens) && closes[i][0] >= opens[i+1][0] {
			return fmt.Errorf("%w (nested open before close)", errUnclosedBlock)
		}
	}
	return nil
}

// checkBrokenEscapes detects the trailing-backslash-before-EOF case.
// Conservative: we look for an odd-count run of `\` immediately before
// either EOF or a newline that itself ends the file.
func checkBrokenEscapes(s string) error {
	trimmed := strings.TrimRight(s, " \t\r\n")
	if trimmed == "" {
		return nil
	}
	// Count trailing backslashes.
	count := 0
	for i := len(trimmed) - 1; i >= 0 && trimmed[i] == '\\'; i-- {
		count++
	}
	if count%2 == 1 {
		return errBrokenEscape
	}
	return nil
}
