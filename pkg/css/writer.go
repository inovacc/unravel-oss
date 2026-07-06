// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// WriteCSS writes beautified CSS to a writer with consistent formatting.
// Uses 2-space indentation, blank lines between top-level rules,
// and proper nesting for @media and @keyframes.
func WriteCSS(rules []Rule, w io.Writer) error {
	if len(rules) == 0 {
		return nil
	}

	for i, r := range rules {
		if i > 0 {
			if _, err := fmt.Fprint(w, "\n"); err != nil {
				return err
			}
		}
		if err := writeRule(w, r, 0); err != nil {
			return err
		}
	}
	return nil
}

// FormatRule formats a single Rule to a beautified CSS string.
func FormatRule(r Rule) string {
	var b strings.Builder
	_ = writeRule(&b, r, 0)
	return b.String()
}

// WriteCSSToFile writes beautified CSS to a file.
func WriteCSSToFile(rules []Rule, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := WriteCSS(rules, f); err != nil {
		return fmt.Errorf("write css to %s: %w", path, err)
	}
	return nil
}

// writeRule writes a single rule at the given indentation level.
func writeRule(w io.Writer, r Rule, indent int) error {
	prefix := strings.Repeat("  ", indent)

	// At-rule with children (@media, @keyframes, etc.)
	if r.AtRule != "" && len(r.Children) > 0 {
		if _, err := fmt.Fprintf(w, "%s%s {\n", prefix, r.AtRule); err != nil {
			return err
		}
		for i, child := range r.Children {
			if i > 0 {
				if _, err := fmt.Fprint(w, "\n"); err != nil {
					return err
				}
			}
			if err := writeRule(w, child, indent+1); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s}\n", prefix); err != nil {
			return err
		}
		return nil
	}

	// At-rule without children (@import, @charset, etc.)
	if r.AtRule != "" && len(r.Children) == 0 && len(r.Declarations) == 0 {
		raw := r.Raw
		if raw != "" {
			if _, err := fmt.Fprintf(w, "%s%s %s;\n", prefix, r.AtRule, raw); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "%s%s;\n", prefix, r.AtRule); err != nil {
				return err
			}
		}
		return nil
	}

	// Regular ruleset
	selector := r.Selector
	if r.AtRule != "" && selector == "" {
		selector = r.AtRule
	}

	if _, err := fmt.Fprintf(w, "%s%s {\n", prefix, selector); err != nil {
		return err
	}

	declPrefix := prefix + "  "
	for _, d := range r.Declarations {
		val := d.Value
		if d.Important {
			val += " !important"
		}
		if _, err := fmt.Fprintf(w, "%s%s: %s;\n", declPrefix, d.Property, val); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "%s}\n", prefix); err != nil {
		return err
	}

	return nil
}
