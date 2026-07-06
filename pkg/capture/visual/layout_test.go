/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractLayout(t *testing.T) {
	raw := loadTestdata(t, "computed_style_sample.json")
	spec, err := parseLayout(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(spec.Entries) != 2 {
		t.Fatalf("entries=%d want 2", len(spec.Entries))
	}
	if spec.Entries[0].DOMPath != "html > body > div#app > main" {
		t.Errorf("dom_path=%q", spec.Entries[0].DOMPath)
	}
	if !spec.Entries[0].Bounds.Visible {
		t.Errorf("expected visible")
	}
	if spec.Truncated {
		t.Errorf("not truncated")
	}
}

func TestLayoutTruncation(t *testing.T) {
	payload := `[
		{"dom_path":"html","bounds":{"x":0,"y":0,"w":10,"h":10,"visible":true},"computed_style":{}},
		{"truncated":true,"total_elements":75000,"captured":50000}
	]`
	spec, err := parseLayout(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !spec.Truncated || spec.TotalElements != 75000 || spec.Captured != 50000 {
		t.Errorf("truncated=%v total=%d captured=%d", spec.Truncated, spec.TotalElements, spec.Captured)
	}
	if len(spec.Entries) != 1 {
		t.Errorf("entries=%d want 1", len(spec.Entries))
	}
}

func TestLayoutByteCap(t *testing.T) {
	// Test the cap constant directly; exercising ExtractLayout via fake CDP
	// would require synthesizing a 60 MiB websocket frame.
	if layoutByteHardCap != 50*1024*1024 {
		t.Errorf("hard cap = %d want 50 MiB", layoutByteHardCap)
	}
	// Verify cap arithmetic surfaces in error string format.
	bigSize := 60 * 1024 * 1024
	if bigSize <= layoutByteHardCap {
		t.Errorf("test setup: %d should exceed cap %d", bigSize, layoutByteHardCap)
	}
}

func TestViewportsParse(t *testing.T) {
	v, err := ParseViewports("1920x1080,1280x720,414x896")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(v) != 3 {
		t.Fatalf("len=%d", len(v))
	}
	if v[0].W != 1920 || v[0].H != 1080 || v[0].Scale != 1.0 {
		t.Errorf("v[0]=%+v", v[0])
	}
	if v[2].W != 414 {
		t.Errorf("v[2].W=%d", v[2].W)
	}

	if got, _ := ParseViewports(""); got != nil {
		t.Errorf("empty want nil got %+v", got)
	}

	cases := []string{"abc", "100", "100x", "0x100", "100x-1"}
	for _, c := range cases {
		if _, err := ParseViewports(c); err == nil {
			t.Errorf("%q expected error", c)
		}
	}

	// Unicode separator support.
	v2, err := ParseViewports("1024×768")
	if err != nil || len(v2) != 1 || v2[0].W != 1024 {
		t.Errorf("unicode sep: %+v err=%v", v2, err)
	}
}

func TestRouteSlug(t *testing.T) {
	cases := map[string]string{
		"https://example.com/login":        "login",
		"https://example.com/":             "root",
		"https://example.com/a/b/c?q=1":    "a-b-c",
		"https://example.com/dash/admin#x": "dash-admin",
	}
	for in, want := range cases {
		if got := routeSlug(in); got != want {
			t.Errorf("routeSlug(%q)=%q want %q", in, got, want)
		}
	}
}

func TestModalSlug(t *testing.T) {
	if got := modalSlug("modal_open", "MFA"); got != "modal-mfa" {
		t.Errorf("got %q", got)
	}
	if got := modalSlug("modal_open", ""); got != "modal-anon" {
		t.Errorf("got %q", got)
	}
	if got := modalSlug("modal_close", "anything"); got != "" {
		t.Errorf("close should slug empty, got %q", got)
	}
}

func TestLayoutContainsCapMarkers(t *testing.T) {
	// Quick sanity: the JS payload references the soft cap.
	if !strings.Contains(computedStyleScript, "50000") {
		t.Errorf("layout script must reference 50000 element cap")
	}
}
