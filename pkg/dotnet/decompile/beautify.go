/*
Copyright (c) 2026 Security Research
*/
package decompile

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
// chunk. Tests use a fakeBeautifier; production wraps pkg/ai/.
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

// Sentinel markers wrapping the untrusted decompiled input region in
// the AI prompt. Mitigates prompt-injection attempts in source comments
// (T-05-04) by giving the model a literal boundary it has been told to
// treat as untrusted data.
const (
	SentinelBegin = "<<<UNRAVEL_DECOMPILED_INPUT_BEGIN>>>"
	SentinelEnd   = "<<<UNRAVEL_DECOMPILED_INPUT_END>>>"
)

// Reason codes used by the structural-preservation guard.
const (
	ReasonMemberCountMismatch    = "member_count_mismatch"
	ReasonAttributeCountMismatch = "attribute_count_mismatch"
	ReasonAIError                = "ai_error"
)

// reMember roughly counts member declarations: methods/properties/ctors,
// nested types, and field declarations. We only need member-count
// preservation, not perfect identification.
var reMember = regexp.MustCompile(
	`(?m)^\s*(?:\[[^\]]*\]\s*)*` +
		`(?:public|private|protected|internal|static|readonly|const|virtual|override|abstract|sealed|async|extern|unsafe|new|partial|\s)+` +
		`\s*(?:class|struct|interface|record|enum|void|[A-Za-z_][\w<>?,\s.\[\]]*)\s+` +
		`[A-Za-z_]\w*\s*[\(\;\=\{]`,
)

// reAttr counts attribute occurrences `[Foo(...)]`.
var reAttr = regexp.MustCompile(`\[[A-Za-z_][\w.]*(?:\([^\)]*\))?\s*[,\]]`)

// countMembers approximates the member declaration count of src.
func countMembers(src string) int {
	return len(reMember.FindAllStringIndex(src, -1))
}

// countAttributes approximates the attribute occurrence count of src.
func countAttributes(src string) int {
	return len(reAttr.FindAllStringIndex(src, -1))
}

// verifyMembers compares member + attribute counts in raw vs beautified
// and returns ("", true) if both match. Mismatch returns a reason code
// and false. This is the structural-preservation guard mitigating
// T-05-04 hallucinated edits and Pitfall #3.
func verifyMembers(raw, beautified string) (string, bool) {
	rawM := countMembers(raw)
	beautM := countMembers(beautified)
	if rawM != beautM {
		return ReasonMemberCountMismatch, false
	}
	rawA := countAttributes(raw)
	beautA := countAttributes(beautified)
	if rawA != beautA {
		return ReasonAttributeCountMismatch, false
	}
	return "", true
}

// renderPrompt assembles the full prompt by substituting `{input}` in
// the embedded csharp.md body with the chunk body wrapped in the
// untrusted-input sentinels.
func renderPrompt(promptBody, chunkBody string) string {
	wrapped := SentinelBegin + "\n" + chunkBody + "\n" + SentinelEnd
	if strings.Contains(promptBody, "{input}") {
		return strings.Replace(promptBody, "{input}", wrapped, 1)
	}
	return promptBody + "\n\n" + wrapped
}

// BeautifyFile runs the chunker + per-chunk Beautifier + structural
// guard. On guard failure it returns the RAW bytes plus a report with
// Beautified=false and the reason — never the hallucinated AI output.
//
// Returns (bytes, report, err); err is non-nil only for hard failures
// (panic, nil Beautifier). Per-chunk AI errors are recorded in report
// and the function falls back to raw cleanly.
func BeautifyFile(ctx context.Context, b Beautifier, src []byte) (out []byte, report *FileBeautifyReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("BeautifyFile panic: %v", r)
			out = src
			report = &FileBeautifyReport{Beautified: false, Reason: fmt.Sprintf("panic: %v", r), RawSize: len(src), OutSize: len(src)}
		}
	}()

	if b == nil {
		return src, &FileBeautifyReport{Beautified: false, Reason: "nil beautifier", RawSize: len(src), OutSize: len(src)}, fmt.Errorf("BeautifyFile: nil Beautifier")
	}

	chunks, _ := recon.Chunk(src, recon.LangCSharp, recon.Options{})
	report = &FileBeautifyReport{ChunkCount: len(chunks), RawSize: len(src)}

	promptBody := prompts.CSharpPrompt()

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

	// Structural guard.
	if reason, ok := verifyMembers(string(src), beautified); !ok {
		report.Beautified = false
		report.Reason = reason
		report.OutSize = len(src)
		return src, report, nil
	}

	report.Beautified = true
	report.OutSize = len(beautified)
	return []byte(beautified), report, nil
}
