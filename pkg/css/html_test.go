/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHTMLExtractStyleBlocks(t *testing.T) {
	html := []byte(`<html><head><style>.a { color: red; }</style><style>.b { color: blue; }</style></head><body></body></html>`)
	styles, err := extractFromHTML(html, "test.html")
	if err != nil {
		t.Fatalf("extractFromHTML: %v", err)
	}
	if len(styles.StyleBlocks) != 2 {
		t.Errorf("expected 2 style blocks, got %d", len(styles.StyleBlocks))
	}
	if styles.StyleBlocks[0].Content != ".a { color: red; }" {
		t.Errorf("unexpected content: %q", styles.StyleBlocks[0].Content)
	}
	if styles.StyleBlocks[0].SourceFile != "test.html" {
		t.Errorf("expected source file test.html, got %q", styles.StyleBlocks[0].SourceFile)
	}
}

func TestHTMLExtractInlineStyles(t *testing.T) {
	html := []byte(`<html><body><div class="box" id="main" style="color: blue;">Hi</div><p style="margin: 10px;">Text</p></body></html>`)
	styles, err := extractFromHTML(html, "test.html")
	if err != nil {
		t.Fatalf("extractFromHTML: %v", err)
	}
	if len(styles.InlineStyles) != 2 {
		t.Errorf("expected 2 inline styles, got %d", len(styles.InlineStyles))
	}
	if styles.InlineStyles[0].Element != "div" {
		t.Errorf("expected element div, got %q", styles.InlineStyles[0].Element)
	}
	if styles.InlineStyles[0].Classes != "box" {
		t.Errorf("expected classes 'box', got %q", styles.InlineStyles[0].Classes)
	}
	if styles.InlineStyles[0].ID != "main" {
		t.Errorf("expected id 'main', got %q", styles.InlineStyles[0].ID)
	}
}

func TestHTMLExtractLinkedSheets(t *testing.T) {
	html := []byte(`<html><head><link rel="stylesheet" href="styles.css"><link rel="stylesheet" href="theme.css"></head><body></body></html>`)
	styles, err := extractFromHTML(html, "test.html")
	if err != nil {
		t.Fatalf("extractFromHTML: %v", err)
	}
	if len(styles.LinkedSheets) != 2 {
		t.Errorf("expected 2 linked sheets, got %d", len(styles.LinkedSheets))
	}
	if styles.LinkedSheets[0] != "styles.css" {
		t.Errorf("expected styles.css, got %q", styles.LinkedSheets[0])
	}
}

func TestHTMLStylesToStylesheets(t *testing.T) {
	styles := &HTMLStyles{
		StyleBlocks: []StyleBlock{
			{Content: ".a { color: red; }", Index: 0, SourceFile: "page.html"},
		},
		InlineStyles: []InlineStyle{
			{Style: "color: blue;", Element: "div", Classes: "box", ID: "main", SourceFile: "page.html"},
		},
	}
	sheets := htmlStylesToStylesheets(styles, "page.html")
	if len(sheets) != 2 {
		t.Errorf("expected 2 stylesheets, got %d", len(sheets))
	}
	found := false
	for _, s := range sheets {
		if s.Source == SourceHTMLStyle {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one stylesheet with source html-style")
	}
}

func TestHTMLFromTestdata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "page.html"))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	styles, err := extractFromHTML(data, "page.html")
	if err != nil {
		t.Fatalf("extractFromHTML: %v", err)
	}
	if len(styles.StyleBlocks) != 1 {
		t.Errorf("expected 1 style block, got %d", len(styles.StyleBlocks))
	}
	if len(styles.InlineStyles) != 2 {
		t.Errorf("expected 2 inline styles, got %d", len(styles.InlineStyles))
	}
	if len(styles.LinkedSheets) != 1 {
		t.Errorf("expected 1 linked sheet, got %d", len(styles.LinkedSheets))
	}
}
