/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseViewports parses a comma-separated viewport list ("1920x1080,1280x720")
// into []Viewport. Empty input returns nil so the caller defaults to the
// natural viewport.
func ParseViewports(s string) ([]Viewport, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []Viewport
	for part := range strings.SplitSeq(s, ",") {
		p := strings.TrimSpace(strings.ToLower(part))
		if p == "" {
			continue
		}
		var sep string
		switch {
		case strings.Contains(p, "×"):
			sep = "×"
		default:
			sep = "x"
		}
		wh := strings.SplitN(p, sep, 2)
		if len(wh) != 2 {
			return nil, fmt.Errorf("invalid viewport %q (want WxH)", part)
		}
		w, err := strconv.Atoi(strings.TrimSpace(wh[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid viewport width %q: %w", part, err)
		}
		h, err := strconv.Atoi(strings.TrimSpace(wh[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid viewport height %q: %w", part, err)
		}
		if w <= 0 || h <= 0 {
			return nil, fmt.Errorf("viewport %q must have positive dimensions", part)
		}
		out = append(out, Viewport{W: w, H: h, Scale: 1.0})
	}
	return out, nil
}
