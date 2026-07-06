/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"fmt"
	"regexp"
	"strconv"
)

// Webpack regexes — re-declared here (not imported from
// pkg/knowledge/kb/scanner) to keep import direction one-way.
// Kept verbatim shape with the scanner version so kb-scanner promotion
// stays in sync.
var (
	reWebpackChunkMap = regexp.MustCompile(`\{((?:\d+:["'][A-Za-z0-9_./~\-]{2,80}["'][,}])+)`)
	reWebpackChunkKV  = regexp.MustCompile(`(\d+):["']([A-Za-z0-9_./~\-]{2,80})["']`)
	reWebpackExport   = regexp.MustCompile(`__webpack_require__\.d\([a-zA-Z_$][a-zA-Z0-9_$]*,["']([A-Za-z_$][A-Za-z0-9_$]{1,60})["']`)
	reWebpackDExport  = regexp.MustCompile(`\b[a-zA-Z_$][a-zA-Z0-9_$]?\.d\([a-zA-Z_$][a-zA-Z0-9_$]*\s*,\s*\{\s*([A-Za-z_$][A-Za-z0-9_$]{2,60})\s*:`)
	reCJSExport       = regexp.MustCompile(`\b(?:t|e|exports|module\.exports)\.([A-Z][A-Za-z0-9_$]{2,60})\s*=`)
	reDefineProp      = regexp.MustCompile(`Object\.defineProperty\([a-zA-Z_$][a-zA-Z0-9_$]*\s*,\s*["']([A-Z][A-Za-z0-9_$]{2,60})["']`)

	// Webpack fingerprints.
	// Accepts self / this / globalThis as the host (real-world bundles vary by target —
	// `self.` for web-workers, `this.` for main-window, `globalThis.` for spec-strict builds).
	reWebpackChunkPush = regexp.MustCompile(`\(\s*(?:self|this|globalThis)\.webpackChunk[A-Za-z0-9_$]*\s*=\s*(?:self|this|globalThis)\.webpackChunk[A-Za-z0-9_$]*\s*\|\|\s*\[\]\s*\)\s*\.push\s*\(`)
	reWebpackRequire   = regexp.MustCompile(`__webpack_require__`)
	// Module key inside the table object: `<digits>:` or `"<digits>":`
	reWebpackModuleKey = regexp.MustCompile(`(?:^|[\{,\s])(\d{1,9})\s*:\s*(?:function|\(\s*[A-Za-z_$,\s]*\)\s*=>)`)
	// Recovers ID -> exported-name through __webpack_require__.d call
	reWebpackDPair = regexp.MustCompile(`__webpack_require__\.d\([a-zA-Z_$][\w$]*\s*,\s*\{\s*([A-Za-z_$][\w$]{1,60})\s*:`)
)

// WebpackRecogniser implements Recogniser for webpack output.
type WebpackRecogniser struct{}

// Name returns the kind identifier.
func (WebpackRecogniser) Name() Kind { return KindWebpack }

// Match scans src for webpack fingerprints and carves module proposals.
// Returns (set, true) iff a webpack fingerprint matched.
func (WebpackRecogniser) Match(src []byte) (set ModuleSet, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			set = ModuleSet{
				Kind:     KindWebpack,
				Evidence: []string{fmt.Sprintf("panic: %v", r)},
			}
			matched = true
		}
	}()

	hasChunk := reWebpackChunkPush.Match(src)
	hasReq := reWebpackRequire.Match(src)
	if !hasChunk && !hasReq {
		return ModuleSet{Kind: KindUnknown}, false
	}

	set.Kind = KindWebpack
	if hasChunk {
		set.Evidence = append(set.Evidence, "webpackChunk push")
	}
	if hasReq {
		set.Evidence = append(set.Evidence, "__webpack_require__")
	}
	matched = true

	// Locate every module-id key candidate. To keep this simple and
	// bounded, we scan all matches of reWebpackModuleKey, then for each
	// hit perform a brace-balanced extraction of the function body.
	keyMatches := reWebpackModuleKey.FindAllSubmatchIndex(src, -1)
	for _, m := range keyMatches {
		// m[0]:m[1] is whole match, m[2]:m[3] is the digit ID group.
		id := string(src[m[2]:m[3]])
		// Find the `{` that opens the module body. Scan forward from
		// m[1] for the next '{'.
		openIdx := indexNextOpenBrace(src, m[1])
		if openIdx < 0 {
			continue
		}
		closeIdx := matchBalancedBrace(src, openIdx)
		if closeIdx < 0 {
			continue
		}
		// Extend End to include trailing `,` if present, but cap at src.
		end := min(closeIdx+1, len(src))
		// Module starts at the digit-key (the m[2] index).
		set.Modules = append(set.Modules, ModuleProposal{
			Start:    m[2],
			End:      end,
			ModuleID: id,
			Source:   "pattern",
		})
	}

	// Pass: name recovery via __webpack_require__.d
	for _, dm := range reWebpackDPair.FindAllSubmatch(src, -1) {
		if len(dm) < 2 {
			continue
		}
		name := string(dm[1])
		// Heuristic: attach to the last unnamed module that contains
		// this name as an identifier. If exactly one match, attach.
		attachIfUnambiguous(&set.Modules, name, src)
	}

	// Sort + dedupe overlapping (keep widest).
	set.Modules = sortAndDedupe(set.Modules)
	return set, true
}

// indexNextOpenBrace returns the index of the next `{` byte at or after
// pos, or -1 if none. Naive scan; safe for bounded scans.
func indexNextOpenBrace(src []byte, pos int) int {
	for i := pos; i < len(src); i++ {
		c := src[i]
		switch c {
		case '{':
			return i
		case '\n', '\r', ' ', '\t', ',':
			continue
		default:
			// Permit a few characters between key colon and body
			// (whitespace handled above; allow `function`/`(`).
			if c == 'f' || c == '(' || c == 'a' /* async */ {
				continue
			}
			// Fall through: still scan onwards since braces may appear
			// after parens in arrow-form modules.
		}
	}
	return -1
}

// matchBalancedBrace returns the index of the matching `}` for the `{`
// at openIdx, or -1 on imbalance. State machine skips braces inside
// strings, template literals, single-line `//` comments and `/* */`
// block comments. Depth-capped at 1024 (matches chunk pkg).
func matchBalancedBrace(src []byte, openIdx int) int {
	if openIdx < 0 || openIdx >= len(src) || src[openIdx] != '{' {
		return -1
	}
	const maxDepth = 1024
	depth := 0
	i := openIdx
	n := len(src)
	mode := mCode
	for i < n {
		c := src[i]
		switch mode {
		case mCode:
			switch c {
			case '{':
				depth++
				if depth > maxDepth {
					return -1
				}
			case '}':
				depth--
				if depth == 0 {
					return i
				}
			case '"':
				mode = mDQ
			case '\'':
				mode = mSQ
			case '`':
				mode = mTpl
			case '/':
				if i+1 < n {
					switch src[i+1] {
					case '/':
						mode = mLine
						i++
					case '*':
						mode = mBlock
						i++
					}
				}
			}
		case mDQ:
			if c == '\\' && i+1 < n {
				i++
			} else if c == '"' {
				mode = mCode
			}
		case mSQ:
			if c == '\\' && i+1 < n {
				i++
			} else if c == '\'' {
				mode = mCode
			}
		case mTpl:
			if c == '\\' && i+1 < n {
				i++
			} else if c == '`' {
				mode = mCode
			}
		case mLine:
			if c == '\n' {
				mode = mCode
			}
		case mBlock:
			if c == '*' && i+1 < n && src[i+1] == '/' {
				mode = mCode
				i++
			}
		}
		i++
	}
	return -1
}

type braceMode int

const (
	mCode braceMode = iota
	mDQ
	mSQ
	mTpl
	mLine
	mBlock
)

// attachIfUnambiguous attaches name to a single module whose body
// contains the identifier `name` (and that module currently has no
// CandidateName). Skips if 0 or >1 modules match.
func attachIfUnambiguous(mods *[]ModuleProposal, name string, src []byte) {
	if name == "" {
		return
	}
	idents := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	hits := -1
	count := 0
	for i, m := range *mods {
		if m.CandidateName != "" {
			continue
		}
		if m.Start < 0 || m.End > len(src) || m.Start >= m.End {
			continue
		}
		if idents.Match(src[m.Start:m.End]) {
			count++
			hits = i
			if count > 1 {
				return
			}
		}
	}
	if count == 1 && hits >= 0 {
		(*mods)[hits].CandidateName = name
	}
}

// sortAndDedupe sorts proposals by Start ascending and drops any later
// proposal that starts inside an earlier proposal's [Start, End) range.
func sortAndDedupe(in []ModuleProposal) []ModuleProposal {
	if len(in) <= 1 {
		return in
	}
	// simple O(n^2) sort — small N
	sorted := make([]ModuleProposal, len(in))
	copy(sorted, in)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Start < sorted[i].Start {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	out := make([]ModuleProposal, 0, len(sorted))
	prevEnd := -1
	for _, p := range sorted {
		if p.Start < prevEnd {
			continue
		}
		out = append(out, p)
		if p.End > prevEnd {
			prevEnd = p.End
		}
	}
	return out
}

// helper for ID parsing (kept exported in case future code needs it).
var _ = strconv.Atoi
