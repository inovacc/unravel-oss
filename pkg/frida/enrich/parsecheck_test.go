// Copyright (c) 2026 Security Research
package enrich

import (
	"errors"
	"testing"
)

func TestParseCheck_AcceptsBalancedScript(t *testing.T) {
	const ok = `Java.perform(function () {
  /* inline comment */
  Interceptor.attach(target, {});
});
`
	if err := parseCheck(ok); err != nil {
		t.Errorf("balanced script rejected: %v", err)
	}
}

func TestParseCheck_RejectsUnclosedBlock(t *testing.T) {
	const bad = `/* start of comment that never ends
Interceptor.attach(target, {});
`
	if err := parseCheck(bad); err == nil {
		t.Errorf("expected unclosed-block rejection")
	}
}

func TestParseCheck_RejectsOrphanCloseComment(t *testing.T) {
	// A close-comment with no preceding open is reported as imbalance.
	const bad = `Interceptor.attach(target, {}); */
`
	err := parseCheck(bad)
	if err == nil {
		t.Errorf("expected orphan-close rejection")
		return
	}
	if !errors.Is(err, errOrphanCloseComment) && !errors.Is(err, errUnclosedBlock) {
		t.Errorf("unexpected error class: %v", err)
	}
}

func TestParseCheck_RejectsBrokenEscapeAtEOF(t *testing.T) {
	const bad = `console.log("hi"); \`
	if err := parseCheck(bad); err == nil {
		t.Errorf("expected broken-escape rejection")
	}
}
