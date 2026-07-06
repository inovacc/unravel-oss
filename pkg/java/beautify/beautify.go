/*
Copyright (c) 2026 Security Research
*/
package beautify

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/internal/ai/prompts"
	recon "github.com/inovacc/unravel-oss/internal/ai/reconstruct/chunk"
)

// Beautifier abstracts the AI delegation surface. Implementations
// receive the rendered prompt + chunk body and return a beautified
// chunk. Tests use a fakeBeautifier; production wraps pkg/ai.
type Beautifier interface {
	Beautify(ctx context.Context, prompt, input string) (string, error)
}

// FileBeautifyReport summarises one BeautifyFile call.
type FileBeautifyReport struct {
	Beautified bool   `json:"beautified"`
	Reason     string `json:"reason,omitempty"`
	ChunkCount int    `json:"chunk_count"`
	RawSize    int    `json:"raw_size"`
	OutSize    int    `json:"out_size"`
}

// Sentinel markers wrapping the untrusted decompiled-input region in
// the AI prompt. Mitigates prompt-injection attempts in source comments
// (T-06-04) by giving the model a literal boundary it has been told to
// treat as untrusted data.
const (
	SentinelBegin = "<BEGIN_JAVA_SOURCE>"
	SentinelEnd   = "<END_JAVA_SOURCE>"
)

// Reason codes used by the structural-preservation guard (D-23).
const (
	ReasonMemberCountMismatch     = "member_count_mismatch"
	ReasonAnnotationCountMismatch = "annotation_count_mismatch"
	ReasonMethodSignatureMismatch = "method_signature_mismatch"
	ReasonAIError                 = "ai_error"
)

// Member matcher: type declarations + method/constructor declarations +
// field declarations. Greedy enough to count, not perfect.
var reMember = regexp.MustCompile(
	`(?m)^\s*(?:@[A-Za-z_]\w*(?:\([^)]*\))?\s*)*` +
		`(?:public|private|protected|static|final|abstract|synchronized|native|default|sealed|non-sealed|strictfp|volatile|transient|\s)+` +
		`(?:class|interface|enum|record|@interface|void|[A-Za-z_][\w<>?,\s\.\[\]]*)\s+` +
		`[A-Za-z_]\w*\s*[\(\;\=\{]`,
)

// reAnnot counts annotation occurrences `@Foo` and `@Foo(...)`.
var reAnnot = regexp.MustCompile(`@[A-Za-z_][\w.]*(?:\([^)]*\))?`)

// reMethodSig captures `name(paramTypes...)` to detect signature drift.
// We capture the method name plus the comma-collapsed param-type list.
var reMethodSig = regexp.MustCompile(
	`(?m)^\s*(?:@[A-Za-z_]\w*(?:\([^)]*\))?\s*)*` +
		`(?:public|private|protected|static|final|abstract|synchronized|native|default|\s)+` +
		`\s*\S+\s+([A-Za-z_]\w*)\s*\(([^)]*)\)`,
)

// countMembers approximates the member declaration count of src.
func countMembers(src string) int {
	return len(reMember.FindAllStringIndex(src, -1))
}

// countAnnotations approximates the annotation occurrence count of src.
// Excludes `@interface` declarations from being mis-counted as
// annotation-uses by removing the leading `@` only when followed by
// `interface`.
func countAnnotations(src string) int {
	matches := reAnnot.FindAllString(src, -1)
	n := 0
	for _, m := range matches {
		if strings.HasPrefix(m, "@interface") {
			continue
		}
		n++
	}
	return n
}

// methodSignatures returns a sorted slice of "name(paramTypes)" strings
// for every method/constructor declaration. Param types are collapsed by
// removing parameter names: each token after the type is dropped.
func methodSignatures(src string) []string {
	out := []string{}
	for _, m := range reMethodSig.FindAllStringSubmatch(src, -1) {
		name := m[1]
		params := strings.TrimSpace(m[2])
		out = append(out, name+"("+collapseParamTypes(params)+")")
	}
	return out
}

// collapseParamTypes takes "Foo a, Bar<X> b" → "Foo,Bar<X>".
func collapseParamTypes(params string) string {
	if params == "" {
		return ""
	}
	parts := splitTopLevelCommas(params)
	types := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Strip leading annotations.
		for strings.HasPrefix(p, "@") {
			sp := strings.IndexAny(p, " \t")
			if sp < 0 {
				break
			}
			p = strings.TrimSpace(p[sp:])
		}
		// Type is everything up to the LAST whitespace-separated token
		// (which is the parameter name).
		if last := strings.LastIndexAny(p, " \t"); last >= 0 {
			p = strings.TrimSpace(p[:last])
		}
		types = append(types, p)
	}
	return strings.Join(types, ",")
}

// splitTopLevelCommas splits s on commas not inside `<>` `()` `[]`.
func splitTopLevelCommas(s string) []string {
	out := []string{}
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// verifyStructure compares member count, annotation count, and method
// signatures between raw and beautified. Returns ("", true) on match;
// otherwise returns a reason code and false. This is the
// structural-preservation guard mitigating T-06-04 hallucinated edits
// (D-23).
func verifyStructure(raw, beautified string) (string, bool) {
	if countMembers(raw) != countMembers(beautified) {
		return ReasonMemberCountMismatch, false
	}
	if countAnnotations(raw) != countAnnotations(beautified) {
		return ReasonAnnotationCountMismatch, false
	}
	rawSigs := methodSignatures(raw)
	beautSigs := methodSignatures(beautified)
	if len(rawSigs) != len(beautSigs) {
		return ReasonMethodSignatureMismatch, false
	}
	// Compare as multisets — order may shift across reflows, but content
	// must be preserved.
	rawCount := map[string]int{}
	for _, s := range rawSigs {
		rawCount[s]++
	}
	for _, s := range beautSigs {
		rawCount[s]--
		if rawCount[s] < 0 {
			return ReasonMethodSignatureMismatch, false
		}
	}
	for _, v := range rawCount {
		if v != 0 {
			return ReasonMethodSignatureMismatch, false
		}
	}
	return "", true
}

// renderPrompt assembles the full prompt by substituting `{input}` in
// the embedded java.md body with the chunk body wrapped in the
// untrusted-input sentinels.
func renderPrompt(promptBody, chunkBody string) string {
	wrapped := SentinelBegin + "\n" + chunkBody + "\n" + SentinelEnd
	if strings.Contains(promptBody, "{input}") {
		return strings.Replace(promptBody, "{input}", wrapped, 1)
	}
	return promptBody + "\n\n" + wrapped
}

// BeautifyFile runs the chunker (LangJava) + per-chunk Beautifier +
// structural guard. On guard failure it returns the RAW bytes plus a
// report with Beautified=false and the reason — never the hallucinated
// AI output.
func BeautifyFile(ctx context.Context, b Beautifier, src []byte) (out []byte, report *FileBeautifyReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("BeautifyFile panic: %v", r)
			out = src
			report = &FileBeautifyReport{
				Beautified: false,
				Reason:     fmt.Sprintf("panic: %v", r),
				RawSize:    len(src),
				OutSize:    len(src),
			}
		}
	}()

	if b == nil {
		return src, &FileBeautifyReport{
			Beautified: false,
			Reason:     "nil beautifier",
			RawSize:    len(src),
			OutSize:    len(src),
		}, fmt.Errorf("BeautifyFile: nil Beautifier")
	}

	chunks, _ := recon.Chunk(src, recon.LangJava, recon.Options{})
	report = &FileBeautifyReport{ChunkCount: len(chunks), RawSize: len(src)}

	promptBody := prompts.JavaPrompt()

	var buf strings.Builder
	for _, ch := range chunks {
		rendered := renderPrompt(promptBody, ch.Body)
		bt, berr := b.Beautify(ctx, rendered, ch.Body)
		if berr != nil {
			report.Beautified = false
			report.Reason = ReasonAIError + ": " + berr.Error()
			report.OutSize = len(src)
			return src, report, nil
		}
		buf.WriteString(bt)
	}
	beautified := buf.String()

	if reason, ok := verifyStructure(string(src), beautified); !ok {
		report.Beautified = false
		report.Reason = reason
		report.OutSize = len(src)
		return src, report, nil
	}

	report.Beautified = true
	report.OutSize = len(beautified)
	return []byte(beautified), report, nil
}
