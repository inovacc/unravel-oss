/*
Copyright (c) 2026 Security Research
*/
package jsdeob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/internal/ai/prompts"
	recon "github.com/inovacc/unravel-oss/internal/ai/reconstruct/chunk"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"
)

// Beautifier abstracts the AI delegation surface. Implementations
// receive the rendered prompt + chunk body and return a beautified
// chunk. Tests use a fakeBeautifier; production wraps pkg/ai. Same
// shape as 06-01 for swap-in compatibility.
type Beautifier interface {
	Beautify(ctx context.Context, prompt, input string) (string, error)
}

// BeautifyAIOptions configures BeautifyAI.
type BeautifyAIOptions struct {
	AIEnabled bool
	Model     string
	OutputDir string
	InputPath string
}

// BeautifyAIReport summarises one BeautifyAI call.
type BeautifyAIReport struct {
	Beautified        bool                      `json:"beautified"`
	Reason            string                    `json:"reason,omitempty"`
	FrameworkDetected []framework.FrameworkInfo `json:"framework_detected,omitempty"`
	ChunkCount        int                       `json:"chunk_count"`
	RawSize           int                       `json:"raw_size"`
	OutSize           int                       `json:"out_size"`
}

// Sentinel markers wrapping the untrusted JS-input region in the prompt
// (T-06-04). The AI prompt instructs the model to treat everything
// between these literals as DATA, not instructions.
const (
	JSSentinelBegin = "<BEGIN_JS_SOURCE>"
	JSSentinelEnd   = "<END_JS_SOURCE>"
)

// Reason codes for the structural-preservation guard (D-23).
const (
	ReasonExportCountMismatch       = "export_count_mismatch"
	ReasonIdentifierCountMismatch   = "identifier_count_mismatch"
	ReasonCommentBlockCountMismatch = "comment_block_count_mismatch"
	ReasonLicenseHeaderMoved        = "license_header_moved"
	ReasonAIError                   = "ai_error"
)

// reTopLevelExport captures top-level exports.
//   - `export` keyword (default, named, const, let, var, function, class, async, `{...}`)
//   - `module.exports.x = ...` and `module.exports = ...`
//   - `exports.x = ...`
//   - `Object.defineProperty(exports, "X", ...)`
var reTopLevelExport = regexp.MustCompile(
	`(?m)^(?:` +
		`\s*export\s+(?:default\s+|const\s+|let\s+|var\s+|function\s*\*?\s+|class\s+|async\s+function|\{)` +
		`|\s*module\.exports(?:\.\w+)?\s*=` +
		`|\s*exports\.\w+\s*=` +
		`|\s*Object\.defineProperty\s*\(\s*exports\s*,` +
		`)`,
)

// reTopLevelDecl matches top-level identifier declarations: var/let/
// const/function/class. Loose-matched at line start (post-whitespace).
var reTopLevelDecl = regexp.MustCompile(
	`(?m)^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?(?:var|let|const|function\s*\*?|class)\s+([A-Za-z_$][\w$]*)`,
)

// reCommentBlock matches `/* ... */` and `/** ... */` comment blocks
// (single-pass, not nested). License-style `/*! ... */` and
// `/** @license ... */` are subsets — counted by reLicenseBlock.
var reCommentBlock = regexp.MustCompile(`(?s)/\*[\s\S]*?\*/`)

// reLicenseBlock matches the canonical license-header forms.
var reLicenseBlock = regexp.MustCompile(`(?s)/\*[!*][\s\S]*?\*/`)

// countTopLevelExports approximates the top-level export count.
func countTopLevelExports(src string) int {
	return len(reTopLevelExport.FindAllStringIndex(src, -1))
}

// countIdentifierDecls approximates the top-level identifier-declaration
// count.
func countIdentifierDecls(src string) int {
	return len(reTopLevelDecl.FindAllStringIndex(src, -1))
}

// countCommentBlocks counts `/* ... */` blocks.
func countCommentBlocks(src string) int {
	return len(reCommentBlock.FindAllStringIndex(src, -1))
}

// licenseHeaderHash returns the sha256 of the concatenation of every
// license-style comment block (`/*! ... */`, `/** @license ... */`),
// normalised by trimming surrounding whitespace. If the AI relocates,
// alters, or drops a license header the hash will diverge.
func licenseHeaderHash(src string) string {
	matches := reLicenseBlock.FindAllString(src, -1)
	// Filter to license-y blocks (start with `/*!` OR contain @license).
	keep := make([]string, 0, len(matches))
	for _, m := range matches {
		trimmed := strings.TrimSpace(m)
		if strings.HasPrefix(trimmed, "/*!") || strings.Contains(trimmed, "@license") {
			keep = append(keep, trimmed)
		}
	}
	sort.Strings(keep)
	h := sha256.Sum256([]byte(strings.Join(keep, "\n")))
	return hex.EncodeToString(h[:])
}

// licenseHeaderInOrderHash returns the hash of license-header BLOCKS in
// their source order (not sorted). Detects a move-by-relocation: the
// content is the same but the relative order changed.
func licenseHeaderInOrderHash(src string) string {
	matches := reLicenseBlock.FindAllString(src, -1)
	keep := make([]string, 0, len(matches))
	for _, m := range matches {
		trimmed := strings.TrimSpace(m)
		if strings.HasPrefix(trimmed, "/*!") || strings.Contains(trimmed, "@license") {
			keep = append(keep, trimmed)
		}
	}
	h := sha256.Sum256([]byte(strings.Join(keep, "\n")))
	return hex.EncodeToString(h[:])
}

// verifyJSStructure is the JS variant of the Phase 5 structural-
// preservation guard (D-23). It compares 4 structural invariants:
//  1. top-level export count
//  2. top-level identifier-declaration count
//  3. comment-block count
//  4. license-header content (hash, content-stable AND order-stable)
//
// Returns ("", true) on match; otherwise (reason, false).
func verifyJSStructure(raw, beautified string) (string, bool) {
	if countTopLevelExports(raw) != countTopLevelExports(beautified) {
		return ReasonExportCountMismatch, false
	}
	if countIdentifierDecls(raw) != countIdentifierDecls(beautified) {
		return ReasonIdentifierCountMismatch, false
	}
	if countCommentBlocks(raw) != countCommentBlocks(beautified) {
		return ReasonCommentBlockCountMismatch, false
	}
	if licenseHeaderHash(raw) != licenseHeaderHash(beautified) {
		return ReasonLicenseHeaderMoved, false
	}
	if licenseHeaderInOrderHash(raw) != licenseHeaderInOrderHash(beautified) {
		return ReasonLicenseHeaderMoved, false
	}
	return "", true
}

// renderJSPrompt assembles the full prompt body by substituting
// `{framework_json}` and `{input}`. Wraps chunkBody in JS sentinels at
// call-time (T-06-04).
func renderJSPrompt(promptBody, chunkBody string, primary *framework.FrameworkInfo) string {
	var fwJSON string
	if primary == nil {
		fwJSON = "null"
	} else {
		b, err := json.Marshal(primary)
		if err != nil {
			fwJSON = "null"
		} else {
			fwJSON = string(b)
		}
	}
	body := strings.Replace(promptBody, "{framework_json}", fwJSON, 1)
	wrapped := JSSentinelBegin + "\n" + chunkBody + "\n" + JSSentinelEnd
	if strings.Contains(body, "{input}") {
		return strings.Replace(body, "{input}", wrapped, 1)
	}
	return body + "\n\n" + wrapped
}

// BeautifyAI runs the shared chunker (LangJavaScript) + per-chunk
// framework detection + per-chunk Beautifier delegation + JS structural
// guard. On guard failure it returns the RAW bytes plus a Report with
// Beautified=false + reason — never the hallucinated AI output.
func BeautifyAI(ctx context.Context, b Beautifier, src []byte, opts BeautifyAIOptions) (out []byte, report *BeautifyAIReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("BeautifyAI panic: %v", r)
			out = src
			report = &BeautifyAIReport{
				Beautified: false,
				Reason:     fmt.Sprintf("panic: %v", r),
				RawSize:    len(src),
				OutSize:    len(src),
			}
		}
	}()

	// Sanitise opts.InputPath / opts.OutputDir at IO boundaries (T-06-01).
	if opts.InputPath != "" {
		if _, serr := SanitizeOutPath("", opts.InputPath); serr != nil {
			return src, &BeautifyAIReport{
				Beautified: false,
				Reason:     "input_path_traversal: " + serr.Error(),
				RawSize:    len(src),
				OutSize:    len(src),
			}, fmt.Errorf("BeautifyAI: input path: %w", serr)
		}
	}
	if opts.OutputDir != "" {
		if _, serr := SanitizeOutPath("", opts.OutputDir); serr != nil {
			return src, &BeautifyAIReport{
				Beautified: false,
				Reason:     "output_path_traversal: " + serr.Error(),
				RawSize:    len(src),
				OutSize:    len(src),
			}, fmt.Errorf("BeautifyAI: output dir: %w", serr)
		}
	}

	if b == nil {
		return src, &BeautifyAIReport{
			Beautified: false,
			Reason:     "nil beautifier",
			RawSize:    len(src),
			OutSize:    len(src),
		}, fmt.Errorf("BeautifyAI: nil Beautifier")
	}

	// recon.Chunk (LangJavaScript) — D-09 50KB chunk fallback baked in.
	chunks, _ := recon.Chunk(src, recon.LangJavaScript, recon.Options{})
	report = &BeautifyAIReport{ChunkCount: len(chunks), RawSize: len(src)}

	promptBody := prompts.JavaScriptPrompt()

	// Per-chunk framework detection (D-08). Aggregate non-empty results
	// into report.FrameworkDetected for caller reference; per-chunk
	// primary feeds prompt.
	allFW := make([]framework.FrameworkInfo, 0, len(chunks))

	var buf strings.Builder
	for _, ch := range chunks {
		fwSlice := framework.Detect([]byte(ch.Body))
		var primary *framework.FrameworkInfo
		if len(fwSlice) > 0 {
			fw := fwSlice[0]
			primary = &fw
			allFW = append(allFW, fw)
		}

		rendered := renderJSPrompt(promptBody, ch.Body, primary)
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

	report.FrameworkDetected = allFW

	if reason, ok := verifyJSStructure(string(src), beautified); !ok {
		report.Beautified = false
		report.Reason = reason
		report.OutSize = len(src)
		return src, report, nil
	}

	report.Beautified = true
	report.OutSize = len(beautified)
	return []byte(beautified), report, nil
}
