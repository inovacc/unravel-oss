/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"strings"
	"testing"
)

// fakeBeautifier returns a deterministic transformation of the input,
// optionally manipulated by a delta function.
type fakeBeautifier struct {
	transform func(input string) (string, error)
}

func (f *fakeBeautifier) Beautify(_ context.Context, _, input string) (string, error) {
	if f.transform == nil {
		return input, nil
	}
	return f.transform(input)
}

const sampleClassesForGuard = `namespace N
{
    [Serializable]
    public class A
    {
        [Obsolete]
        public int X;
        public int Y;
        public void M1() { }
        public void M2() { }
    }

    [Obsolete]
    public class B
    {
        public int Z;
        public void N1() { }
    }

    public class C
    {
        public int W;
        public void O1() { }
    }

    public class D
    {
        public int V;
        public void P1() { }
        public void P2() { }
    }
}
`

func TestBeautifyFile_PreservesMembers(t *testing.T) {
	src := []byte(sampleClassesForGuard)

	// 1. Identity transform — guard accepts.
	b1 := &fakeBeautifier{transform: func(in string) (string, error) {
		return in + "  ", nil // whitespace tweak only
	}}
	out, rep, err := BeautifyFile(context.Background(), b1, src)
	if err != nil {
		t.Fatalf("BeautifyFile (identity): %v", err)
	}
	if !rep.Beautified {
		t.Errorf("expected Beautified=true, got reason=%q", rep.Reason)
	}
	if len(out) == 0 {
		t.Error("empty output")
	}

	// 2. Drop a method — guard rejects with member_count_mismatch.
	b2 := &fakeBeautifier{transform: func(in string) (string, error) {
		out := strings.Replace(in, "public void M2() { }", "", 1)
		return out, nil
	}}
	out2, rep2, err := BeautifyFile(context.Background(), b2, src)
	if err != nil {
		t.Fatalf("BeautifyFile (drop): %v", err)
	}
	if rep2.Beautified {
		t.Error("expected Beautified=false after dropping member")
	}
	if rep2.Reason != ReasonMemberCountMismatch {
		t.Errorf("want reason=%q, got %q", ReasonMemberCountMismatch, rep2.Reason)
	}
	if string(out2) != string(src) {
		t.Error("expected fallback to RAW bytes on guard rejection")
	}
}

func TestBeautifyFile_PreservesAttributes(t *testing.T) {
	src := []byte(sampleClassesForGuard)
	b := &fakeBeautifier{transform: func(in string) (string, error) {
		// Drop one [Obsolete] attribute.
		out := strings.Replace(in, "[Obsolete]\n    public class B", "public class B", 1)
		return out, nil
	}}
	out, rep, err := BeautifyFile(context.Background(), b, src)
	if err != nil {
		t.Fatalf("BeautifyFile: %v", err)
	}
	if rep.Beautified {
		t.Errorf("expected Beautified=false after dropping attribute, got reason=%q", rep.Reason)
	}
	if rep.Reason != ReasonAttributeCountMismatch {
		// Member count may also trip; we accept either as a guard hit.
		if rep.Reason != ReasonMemberCountMismatch {
			t.Errorf("expected attribute or member mismatch, got %q", rep.Reason)
		}
	}
	if string(out) != string(src) {
		t.Error("expected fallback to raw bytes")
	}
}

func TestBeautifyFile_NilBeautifier(t *testing.T) {
	_, rep, err := BeautifyFile(context.Background(), nil, []byte("public class A { }"))
	if err == nil {
		t.Error("expected error on nil Beautifier")
	}
	if rep == nil || rep.Beautified {
		t.Errorf("unexpected report: %+v", rep)
	}
}

func TestRenderPrompt_WrapsWithSentinels(t *testing.T) {
	body := "Header text\n{input}\nFooter"
	rendered := renderPrompt(body, "public class X { }")
	if !strings.Contains(rendered, SentinelBegin) {
		t.Error("missing BEGIN sentinel")
	}
	if !strings.Contains(rendered, SentinelEnd) {
		t.Error("missing END sentinel")
	}
	if !strings.Contains(rendered, "public class X") {
		t.Error("input not wrapped")
	}
}
