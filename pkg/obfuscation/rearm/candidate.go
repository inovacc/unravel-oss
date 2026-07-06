/*
Copyright (c) 2026 Security Research
*/
package rearm

import (
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/garble"
)

// CollectCandidates is pure-Go: it only reads signals already populated by the
// dissect analyzers. Nil/empty input ⇒ nil (honest-empty).
func CollectCandidates(r *dissect.DissectResult) []Candidate {
	if r == nil {
		return nil
	}
	opt := DefaultOptions()
	var out []Candidate

	if c, ok := jsCandidate(r, opt); ok {
		out = append(out, c)
	}

	if gd := r.GarbleDetect; gd != nil && garbleObfuscated(gd) {
		s := garbleSummary(r)
		out = append(out, Candidate{
			Lang: "go", ModuleRef: "go-binary", Source: s, Size: len(s),
			HeuristicHint: "garble", Signal: 90,
		})
	}

	out = append(out, collectDotNet(r, opt)...)
	out = append(out, collectJava(r, opt)...)
	return out
}

// sidecarMinifiedFloor: a combined CDP-sidecar JS bundle this large is
// minified/concatenated by definition (WhatsApp/Teams ship a single huge
// minified bundle), so it qualifies for rearm even when an upstream
// ObfuscationScore was not computed (0/low).
const sidecarMinifiedFloor = 200_000

// sidecarMinifiedSignal is the floor signal applied to a large sidecar
// bundle so it ranks as obfuscation-worthy.
const sidecarMinifiedSignal = 70

// jsCandidate builds the single JS rearm candidate. Primary source is
// r.BeautifiedJS; the WebView2-UWP fallback is r.RecoveredJSSource (the
// bounded CDP-sidecar copy stashed by dissect.applyCDPSourceSidecar — the
// seam that keeps rearm free of pkg/capture/webview2). Honest-empty: no
// JSAnalysis, or no usable source ⇒ no candidate.
func jsCandidate(r *dissect.DissectResult, opt Options) (Candidate, bool) {
	ja := r.JSAnalysis
	if ja == nil {
		return Candidate{}, false
	}

	src := r.BeautifiedJS
	signal := ja.ObfuscationScore
	scoreOK := ja.ObfuscationScore >= opt.JSObfMin

	if src == "" {
		// Fallback: bounded CDP-sidecar source (WebView2-UWP). A large
		// minified bundle qualifies even without an upstream score.
		rjs := r.RecoveredJSSource
		if rjs == "" {
			return Candidate{}, false
		}
		src = rjs
		if len(rjs) > sidecarMinifiedFloor {
			scoreOK = true
			if signal < sidecarMinifiedSignal {
				signal = sidecarMinifiedSignal
			}
		}
	}

	if !scoreOK || src == "" {
		return Candidate{}, false
	}
	if len(src) > opt.Bounds.MaxModuleBytes {
		src = src[:opt.Bounds.MaxModuleBytes]
	}
	return Candidate{
		Lang: "js", ModuleRef: nonEmpty(ja.File, "javascript"),
		Source: src, Size: len(src),
		HeuristicHint: "minified/obfuscated-js", Signal: signal,
	}, true
}

func nonEmpty(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

// garbleObfuscated returns the real garble obfuscation indicator
// (DetectionResult.IsGarbled), nil-safe.
func garbleObfuscated(gd *garble.DetectionResult) bool {
	if gd == nil {
		return false
	}
	return gd.IsGarbled
}

const garbleSummaryCap = 16384

// garbleSummary builds a concise deterministic string from the populated
// garble symbol/string signals, bounded to 16384 bytes.
func garbleSummary(r *dissect.DissectResult) string {
	var b strings.Builder
	if sym := r.GarbleSymbols; sym != nil {
		b.WriteString("symbols.obfuscated_count=")
		b.WriteString(itoa(sym.ObfuscatedCount))
		b.WriteByte('\n')
		ss := append([]string(nil), sym.TopObfuscated...)
		sort.Strings(ss)
		for _, s := range ss {
			b.WriteString("sym:")
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	if st := r.GarbleStrings; st != nil {
		b.WriteString("strings.high_entropy_count=")
		b.WriteString(itoa(st.HighEntropyCount))
		b.WriteByte('\n')
		samples := make([]string, 0, len(st.Strings))
		for _, es := range st.Strings {
			samples = append(samples, es.Value)
		}
		sort.Strings(samples)
		for _, s := range samples {
			b.WriteString("str:")
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	out := b.String()
	if len(out) > garbleSummaryCap {
		out = out[:garbleSummaryCap]
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// unreadableRatio returns the fraction of identifiers that look
// obfuscated (single/short tokens or no vowels), pure-Go heuristic.
func unreadableRatio(names []string) float64 {
	total := 0
	bad := 0
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		total++
		if isUnreadableIdent(n) {
			bad++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(bad) / float64(total)
}

func isUnreadableIdent(s string) bool {
	// Strip a common file extension / dotted segment to the last token.
	if i := strings.LastIndexByte(s, '.'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	if len(s) <= 2 {
		return true
	}
	hasVowel := false
	for _, c := range strings.ToLower(s) {
		if c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' {
			hasVowel = true
			break
		}
	}
	return !hasVowel
}

// collectDotNet returns a candidate only when DotNetDecompile is non-nil and
// the assembly names show an unreadable-identifier ratio >= 0.5.
func collectDotNet(r *dissect.DissectResult, opt Options) []Candidate {
	d := r.DotNetDecompile
	if d == nil || len(d.Assemblies) == 0 {
		return nil
	}
	names := make([]string, 0, len(d.Assemblies))
	for _, a := range d.Assemblies {
		names = append(names, a.Name)
	}
	ratio := unreadableRatio(names)
	if ratio < 0.5 {
		return nil
	}
	sort.Strings(names)
	src := strings.Join(names, "\n")
	if len(src) > opt.Bounds.MaxModuleBytes {
		src = src[:opt.Bounds.MaxModuleBytes]
	}
	if src == "" {
		return nil
	}
	return []Candidate{{
		Lang: "dotnet", ModuleRef: nonEmpty(names[0], "dotnet-assembly"),
		Source: src, Size: len(src),
		HeuristicHint: "confuserex", Signal: int(ratio * 100),
	}}
}

// collectJava is honest-empty: DissectResult exposes no Java decompile/beautify
// field today, so there is no usable signal to read. Returns nil.
func collectJava(_ *dissect.DissectResult, _ Options) []Candidate {
	return nil
}
