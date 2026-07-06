// Copyright (c) 2026 Security Research
package enrich

import (
	"strings"
	"testing"
)

func TestRenderPrompt_HasSentinelBoundaries(t *testing.T) {
	out := renderPrompt("script-body-here", "decompiled-body-here")
	if !strings.Contains(out, UserSourceBegin) || !strings.Contains(out, UserSourceEnd) {
		t.Fatalf("rendered prompt lacks sentinel boundaries:\n%s", out)
	}
	if !strings.Contains(out, "script-body-here") {
		t.Errorf("rendered prompt missing script body")
	}
	if !strings.Contains(out, "decompiled-body-here") {
		t.Errorf("rendered prompt missing decompiled body")
	}
}

func TestRenderPrompt_OmitsDecompiledWhenEmpty(t *testing.T) {
	// Empty decompiled bundle is allowed; the template still surrounds the
	// (empty) slot in sentinels — defence-in-depth, no special-case.
	out := renderPrompt("only-script", "")
	if !strings.Contains(out, "only-script") {
		t.Errorf("script slot missing")
	}
	if strings.Count(out, UserSourceBegin) < 2 {
		t.Errorf("expected at least two sentinel-bracketed regions, got: %s", out)
	}
}
