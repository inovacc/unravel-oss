/*
Copyright (c) 2026 Security Research
*/

package depth

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

type mockWebView2View struct {
	udf         int
	profiles    int
	cache       int
	preferences int
}

func (m mockWebView2View) UDFCovered() int         { return m.udf }
func (m mockWebView2View) ProfilesCovered() int    { return m.profiles }
func (m mockWebView2View) CacheCovered() int       { return m.cache }
func (m mockWebView2View) PreferencesCovered() int { return m.preferences }

func TestAuditWebView2_Empty(t *testing.T) {
	t.Run("nil_dissect_result", func(t *testing.T) {
		if got := AuditWebView2(nil, mockWebView2View{}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
	t.Run("nil_view", func(t *testing.T) {
		if got := AuditWebView2(&dissect.DissectResult{}, nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestAuditWebView2_AllZero(t *testing.T) {
	got := AuditWebView2(&dissect.DissectResult{}, mockWebView2View{})
	if len(got) != 4 {
		t.Fatalf("expected 4 dimensions, got %d", len(got))
	}
	for _, d := range got {
		if d.Total != 0 || d.Covered != 0 || d.Ratio != 0 {
			t.Errorf("dim %q: %+v want all zero", d.Name, d)
		}
		if !RatioOK(d) {
			t.Errorf("dim %q failed RatioOK", d.Name)
		}
	}
}

func TestAuditWebView2_PartialCoverage(t *testing.T) {
	dr := &dissect.DissectResult{
		WebView2Info: &webview2.Result{
			IsWebView2: true,
			UDFs: []webview2.UDFInfo{
				{Path: "C:\\Users\\u\\AppData\\Local\\App\\EBWebView", Source: "default", Exists: true},
				{Path: "C:\\fallback", Source: "localappdata", Exists: false},
			},
			Profiles: []webview2.ProfileInfo{
				{Name: "Default", Path: "Default"},
				{Name: "Profile 1", Path: "Profile 1"},
				{Name: "Profile 2", Path: "Profile 2"},
			},
			ProfileData: []any{
				struct{}{},
				struct{}{},
			},
		},
	}

	view := mockWebView2View{
		udf:         2,
		profiles:    3,
		cache:       1, // only 1 of 2 cache blocks propagated
		preferences: 2,
	}

	got := AuditWebView2(dr, view)
	if len(got) != 4 {
		t.Fatalf("expected 4 dimensions, got %d", len(got))
	}

	byName := map[string]Dimension{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if d := byName["webview2.udf"]; d.Total != 2 || d.Covered != 2 || d.Ratio != 1.0 {
		t.Errorf("webview2.udf: %+v want covered=2 total=2", d)
	}
	if d := byName["webview2.profiles"]; d.Total != 3 || d.Covered != 3 {
		t.Errorf("webview2.profiles: %+v want covered=3 total=3", d)
	}
	if d := byName["webview2.cache"]; d.Total != 2 || d.Covered != 1 || d.Ratio != 0.5 {
		t.Errorf("webview2.cache: %+v want covered=1 total=2 ratio=0.5", d)
	}
	if d := byName["webview2.preferences"]; d.Total != 2 || d.Covered != 2 {
		t.Errorf("webview2.preferences: %+v want covered=2 total=2", d)
	}
}

func TestAuditWebView2_DimensionOrderStable(t *testing.T) {
	canonical := []string{
		"webview2.udf",
		"webview2.profiles",
		"webview2.cache",
		"webview2.preferences",
	}
	got := AuditWebView2(&dissect.DissectResult{}, mockWebView2View{})
	if len(got) != len(canonical) {
		t.Fatalf("expected %d, got %d", len(canonical), len(got))
	}
	for i, want := range canonical {
		if got[i].Name != want {
			t.Errorf("position %d: got %q want %q", i, got[i].Name, want)
		}
	}
	for _, d := range got {
		if !RatioOK(d) {
			t.Errorf("dim %q failed RatioOK", d.Name)
		}
	}
}
