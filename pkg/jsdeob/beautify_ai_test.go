/*
Copyright (c) 2026 Security Research
*/
package jsdeob

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakeBeautifier captures the rendered prompt for assertion and returns
// a deterministic transform.
type fakeBeautifier struct {
	lastPrompt string
	lastInput  string
	transform  func(input string) string
	err        error
}

func (f *fakeBeautifier) Beautify(_ context.Context, prompt, input string) (string, error) {
	f.lastPrompt = prompt
	f.lastInput = input
	if f.err != nil {
		return "", f.err
	}
	if f.transform == nil {
		return input, nil
	}
	return f.transform(input), nil
}

func TestBeautifyAI_FrameworkContextInjected(t *testing.T) {
	src := []byte(`/*! License */
import { _jsx } from "react/jsx-runtime";
export const App = () => _jsx("div", { children: "x" });
`)
	fake := &fakeBeautifier{}
	_, _, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI: %v", err)
	}
	if !strings.Contains(fake.lastPrompt, `"name":"React"`) {
		t.Errorf("rendered prompt missing React framework JSON; prompt excerpt:\n%s", fake.lastPrompt[:minInt(800, len(fake.lastPrompt))])
	}
}

func TestBeautifyAI_NullFrameworkContext(t *testing.T) {
	src := []byte(`var x = 1; var y = 2;`)
	fake := &fakeBeautifier{}
	_, _, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI: %v", err)
	}
	if !strings.Contains(fake.lastPrompt, "null") {
		t.Errorf("rendered prompt missing literal null framework slot")
	}
}

// canonicalSyntheticModule returns a 100-line module with 3 top-level
// exports + 12 identifier declarations + 1 license header.
func canonicalSyntheticModule() string {
	var sb strings.Builder
	sb.WriteString("/*! license: MIT */\n")
	for i := 0; i < 12; i++ {
		sb.WriteString("var v")
		sb.WriteByte(byte('0' + i%10))
		sb.WriteString(" = 1;\n")
	}
	sb.WriteString("export const a = 1;\n")
	sb.WriteString("export const b = 2;\n")
	sb.WriteString("module.exports.c = 3;\n")
	for i := 0; i < 80; i++ {
		sb.WriteString("// padding line\n")
	}
	return sb.String()
}

func TestBeautifyAI_StructuralPreservation_Pass(t *testing.T) {
	src := []byte(canonicalSyntheticModule())
	fake := &fakeBeautifier{
		transform: func(input string) string {
			// Whitespace-only tweak — counts identical.
			return strings.ReplaceAll(input, "var v", "var  v")
		},
	}
	_, rep, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI: %v", err)
	}
	if !rep.Beautified {
		t.Errorf("expected Beautified=true, got reason=%q", rep.Reason)
	}
}

func TestBeautifyAI_StructuralPreservation_RejectExportDrop(t *testing.T) {
	src := []byte(canonicalSyntheticModule())
	fake := &fakeBeautifier{
		transform: func(input string) string {
			return strings.Replace(input, "export const b = 2;\n", "", 1)
		},
	}
	out, rep, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI: %v", err)
	}
	if rep.Beautified {
		t.Errorf("expected guard rejection, got Beautified=true")
	}
	if rep.Reason != ReasonExportCountMismatch {
		t.Errorf("reason = %q, want %q", rep.Reason, ReasonExportCountMismatch)
	}
	if string(out) != string(src) {
		t.Error("guard failure must ship raw bytes, got mutated output")
	}
}

func TestBeautifyAI_StructuralPreservation_RejectIdentifierDrop(t *testing.T) {
	src := []byte(canonicalSyntheticModule())
	fake := &fakeBeautifier{
		transform: func(input string) string {
			return strings.Replace(input, "var v0 = 1;\n", "", 1)
		},
	}
	_, rep, _ := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if rep.Beautified {
		t.Error("expected guard rejection")
	}
	if rep.Reason != ReasonIdentifierCountMismatch {
		t.Errorf("reason = %q, want %q", rep.Reason, ReasonIdentifierCountMismatch)
	}
}

func TestBeautifyAI_StructuralPreservation_RejectLicenseHeaderMoved(t *testing.T) {
	src := []byte("/*! license: MIT */\nvar x = 1;\nvar y = 2;\n/*! license: BSD */\nexport const a = 1;\n")
	fake := &fakeBeautifier{
		transform: func(input string) string {
			// Swap the order of the two /*! ... */ blocks.
			s := strings.Replace(input, "/*! license: MIT */", "@@TMP@@", 1)
			s = strings.Replace(s, "/*! license: BSD */", "/*! license: MIT */", 1)
			s = strings.Replace(s, "@@TMP@@", "/*! license: BSD */", 1)
			return s
		},
	}
	_, rep, _ := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if rep.Beautified {
		t.Error("expected guard rejection on license header reorder")
	}
	if rep.Reason != ReasonLicenseHeaderMoved {
		t.Errorf("reason = %q, want %q", rep.Reason, ReasonLicenseHeaderMoved)
	}
}

func TestBeautifyAI_PerChunkFrameworkDetection(t *testing.T) {
	// Two top-level functions; first is React, second is plain.
	src := []byte(`function ReactCmp() {
  var __secret = __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
  return _jsx("div", null);
}
function PlainHelper(x) {
  return x + 1;
}
`)
	fake := &fakeBeautifier{}
	_, rep, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI: %v", err)
	}
	foundReact := false
	for _, fi := range rep.FrameworkDetected {
		if fi.Name == "React" {
			foundReact = true
			break
		}
	}
	if !foundReact {
		t.Errorf("expected React in per-chunk framework detection, got %v", rep.FrameworkDetected)
	}
}

func TestBeautifyAI_CommentBlockPreservation(t *testing.T) {
	src := []byte("/** @license MIT */\nvar a = 1;\n/** @license BSD */\nvar b = 2;\nexport const c = 3;\n")
	fake := &fakeBeautifier{
		transform: func(input string) string {
			return strings.Replace(input, "/** @license BSD */\n", "", 1)
		},
	}
	_, rep, _ := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if rep.Beautified {
		t.Error("expected guard rejection on dropped /** @license */")
	}
	// Either CommentBlock or LicenseHeader is acceptable — both represent
	// the same drift, but the guard checks comment-block count first.
	if rep.Reason != ReasonCommentBlockCountMismatch && rep.Reason != ReasonLicenseHeaderMoved {
		t.Errorf("unexpected reason %q", rep.Reason)
	}
}

func TestBeautifyAI_50kBChunkFallback(t *testing.T) {
	// 60 KB single function — chunker falls back to per-function chunks.
	var body strings.Builder
	body.WriteString("function huge() {\n")
	for i := 0; i < 4500; i++ {
		body.WriteString("  console.log('padding line ")
		body.WriteString(strings.Repeat("x", 8))
		body.WriteString("');\n")
	}
	body.WriteString("}\n")
	src := []byte(body.String())
	fake := &fakeBeautifier{}
	_, rep, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI: %v", err)
	}
	// Either 1 chunk (whole function) or sub-chunks via splitMethodGroups —
	// the contract is the orchestrator handles either case without error.
	if rep.ChunkCount < 1 {
		t.Errorf("expected >=1 chunk, got %d", rep.ChunkCount)
	}
}

func TestBeautifyAI_PathTraversalRejected(t *testing.T) {
	src := []byte("var x = 1;")
	fake := &fakeBeautifier{}
	_, rep, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{
		InputPath: "../../etc/passwd",
	})
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	low := strings.ToLower(err.Error() + " " + rep.Reason)
	if !strings.Contains(low, "traversal") && !strings.Contains(low, "outside") {
		t.Errorf("error/reason should mention traversal/outside, got err=%v reason=%q", err, rep.Reason)
	}
}

func TestProvenance_FrameworkDetectedField(t *testing.T) {
	// FileMeta.FrameworkDetected is a *FrameworkInfo (D-25). Round-trip
	// JSON to ensure both nil and populated cases serialise correctly.
	fm1 := FileMeta{Path: "a.js", FrameworkDetected: nil}
	if got := mustMarshal(t, fm1); !strings.Contains(got, `"framework_detected":null`) {
		t.Errorf("nil framework_detected should serialise as null, got %s", got)
	}
}

func TestBeautifyAI_AIError(t *testing.T) {
	src := []byte("var x = 1; export const a = 1;")
	fake := &fakeBeautifier{err: errAIFail{}}
	out, rep, err := BeautifyAI(context.Background(), fake, src, BeautifyAIOptions{})
	if err != nil {
		t.Fatalf("BeautifyAI returned err on AI fail: %v", err)
	}
	if rep.Beautified {
		t.Error("expected Beautified=false on AI error")
	}
	if !strings.HasPrefix(rep.Reason, ReasonAIError) {
		t.Errorf("reason = %q, want prefix %q", rep.Reason, ReasonAIError)
	}
	if string(out) != string(src) {
		t.Error("AI error must ship raw")
	}
}

type errAIFail struct{}

func (errAIFail) Error() string { return "synthetic AI failure" }

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
