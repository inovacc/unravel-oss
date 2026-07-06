package rearm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeBeautifier struct {
	resp                string
	err                 error
	gotPrompt, gotInput string
}

func (f *fakeBeautifier) Beautify(_ context.Context, p, in string) (string, error) {
	f.gotPrompt, f.gotInput = p, in
	return f.resp, f.err
}

func TestRearmOne_ParsesMechanismAndCode(t *testing.T) {
	fb := &fakeBeautifier{resp: "MECHANISM: terser|85\n```js\nfunction app(){ return 1; }\n```"}
	c := Candidate{Lang: "js", ModuleRef: "app.js", Source: "function a(){return 1}"}
	mech, conf, code, err := rearmOne(context.Background(), fb, c)
	if err != nil {
		t.Fatal(err)
	}
	if mech != "terser" || conf != 85 || !strings.Contains(code, "function app()") {
		t.Fatalf("parse failed: mech=%q conf=%d code=%q", mech, conf, code)
	}
	if !strings.Contains(fb.gotPrompt, "js") || fb.gotInput != c.Source {
		t.Fatalf("prompt/input not wired: %q", fb.gotPrompt)
	}
}

func TestRearmOne_ErrorPropagates(t *testing.T) {
	_, _, _, err := rearmOne(context.Background(), &fakeBeautifier{err: errors.New("unavailable")}, Candidate{Lang: "js", Source: "x"})
	if err == nil {
		t.Fatal("want error")
	}
}
