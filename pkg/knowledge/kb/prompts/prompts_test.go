package prompts

import (
	"sort"
	"strings"
	"testing"
)

// expectedOps is the canonical set of prompts that must be embedded.
// Tests fail if a file is added or removed without updating this list,
// which forces the .md set and the Op constants to stay in sync.
var expectedOps = []string{
	OpArchDescribe,
	OpDepResolve,
	OpFactResolve,
	OpSecAudit,
	OpSymbolSummarize,
	OpTopicClassify,
}

func TestListReturnsAllExpectedOps(t *testing.T) {
	got := List()
	want := append([]string(nil), expectedOps...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("List length = %d, want %d (got=%v want=%v)", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("List[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGetEachPromptParses(t *testing.T) {
	for _, op := range expectedOps {
		t.Run(op, func(t *testing.T) {
			p, err := Get(op)
			if err != nil {
				t.Fatalf("Get(%q): %v", op, err)
			}
			if p.Op != op {
				t.Errorf("Op = %q, want %q", p.Op, op)
			}
			if p.Description == "" {
				t.Errorf("%s: description is empty", op)
			}
			if p.OutputFormat == "" {
				t.Errorf("%s: output_format is empty", op)
			}
			if p.Body == "" {
				t.Errorf("%s: body is empty", op)
			}
		})
	}
}

func TestGetUnknownOp(t *testing.T) {
	if _, err := Get("definitely_not_a_real_op"); err == nil {
		t.Error("expected error for unknown op")
	}
}

func TestFactResolveHasExpectedPlaceholders(t *testing.T) {
	p, err := Get(OpFactResolve)
	if err != nil {
		t.Fatal(err)
	}
	for _, ph := range []string{"{gap_prompt}", "{evidence_json}"} {
		if !strings.Contains(p.Body, ph) {
			t.Errorf("fact_resolve body missing %q", ph)
		}
	}
}

func TestRenderSubstitutes(t *testing.T) {
	p := &Prompt{Body: "Hello {name}, you are {role}."}
	got := p.Render(map[string]string{"name": "Ada", "role": "engineer"})
	if got != "Hello Ada, you are engineer." {
		t.Errorf("Render = %q", got)
	}
}

func TestRenderLeavesUnknownPlaceholders(t *testing.T) {
	p := &Prompt{Body: "Hello {name}, {unknown}"}
	got := p.Render(map[string]string{"name": "Ada"})
	if !strings.Contains(got, "{unknown}") {
		t.Errorf("expected {unknown} preserved, got %q", got)
	}
}

func TestParsePromptBodyOnly(t *testing.T) {
	raw := []byte("just a body, no frontmatter\n")
	p, err := parsePrompt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Op != "" {
		t.Errorf("Op = %q, expected empty", p.Op)
	}
	if !strings.Contains(p.Body, "just a body") {
		t.Errorf("Body = %q", p.Body)
	}
}

func TestParsePromptUnclosedFrontmatter(t *testing.T) {
	raw := []byte("---\nop: foo\nbody starts here without a closer\n")
	if _, err := parsePrompt(raw); err == nil {
		t.Error("expected error for unclosed frontmatter")
	}
}
