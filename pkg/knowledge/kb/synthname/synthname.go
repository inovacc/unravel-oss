// Package synthname deterministically derives a human-readable module name
// from a minified module body, for Teams `teams_module_<N>` placeholder rows
// that lost their symbolic name upstream. Pure-Go, no AI. Same body in →
// same name out.
package synthname

import (
	"regexp"
	"strings"
)

var (
	// AMD/Haste registration: __d("Name",[…  /  define('Name',[…
	reDefine = regexp.MustCompile(`(?:__d|define)\(\s*["']([A-Za-z_$][\w.$-]{1,79})["']`)
	// exported function/class identifier
	reExport = regexp.MustCompile(`export\s+(?:default\s+)?(?:async\s+)?(?:function|class)\s+([A-Za-z_$][\w$]{1,79})`)
	// top-level class/function declaration
	reDecl = regexp.MustCompile(`(?:^|[;{\s])(?:class|function)\s+([A-Za-z_$][\w$]{2,79})`)
	// fallback: a meaningful quoted string/route constant (>=4 chars, has a letter)
	reConst = regexp.MustCompile(`["']([A-Za-z][\w./-]{3,79})["']`)
)

// Derive returns a sanitized human-readable name and true when the body
// carries a confident signal, or ("", false) when it does not. The priority
// ladder (first non-empty wins) is: AMD/define registered name → exported
// identifier → top-level class/function declaration → meaningful constant.
func Derive(body string) (string, bool) {
	if strings.TrimSpace(body) == "" {
		return "", false
	}
	for _, re := range []*regexp.Regexp{reDefine, reExport, reDecl, reConst} {
		if m := re.FindStringSubmatch(body); m != nil {
			if n := sanitize(m[1]); n != "" {
				return n, true
			}
		}
	}
	return "", false
}

// sanitize strips control characters, collapses to a bounded safe token, and
// rejects empty/too-short results.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80]
	}
	if len(s) < 3 {
		return ""
	}
	return s
}
