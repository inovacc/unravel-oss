// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"testing"
)

func TestOrganizeByComponent_FilenameMatch(t *testing.T) {
	sheets := []Stylesheet{
		{Path: "button.css", Content: []byte(".btn { color: red; }")},
	}
	comps := OrganizeByComponent(sheets)
	found := false
	for _, c := range comps {
		if c.Name == "button" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'button' component from button.css, got: %+v", comps)
	}
}

func TestOrganizeByComponent_ModuleCSS(t *testing.T) {
	sheets := []Stylesheet{
		{Path: "modal.module.css", Content: []byte(".modal { display: none; }")},
	}
	comps := OrganizeByComponent(sheets)
	found := false
	for _, c := range comps {
		if c.Name == "modal" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'modal' component from modal.module.css, got: %+v", comps)
	}
}

func TestOrganizeByComponent_StyledJS(t *testing.T) {
	sheets := []Stylesheet{
		{Path: "Header.styled.js", Content: []byte("h1 { font-size: 24px; }")},
	}
	comps := OrganizeByComponent(sheets)
	found := false
	for _, c := range comps {
		if c.Name == "header" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'header' component from Header.styled.js, got: %+v", comps)
	}
}

func TestOrganizeByComponent_DirectoryContext(t *testing.T) {
	sheets := []Stylesheet{
		{Path: "components/Button/styles.css", Content: []byte(".btn { color: blue; }")},
	}
	comps := OrganizeByComponent(sheets)
	found := false
	for _, c := range comps {
		if c.Name == "button" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'button' component from components/Button/styles.css, got: %+v", comps)
	}
}

func TestOrganizeByComponent_SelectorFallback(t *testing.T) {
	sheets := []Stylesheet{
		{Path: "styles.css", Content: []byte(".btn { color: red; } .btn-primary { color: blue; } .btn-lg { padding: 10px; }")},
	}
	comps := OrganizeByComponent(sheets)
	found := false
	for _, c := range comps {
		if c.Name == "button" || c.Name == "btn" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'button' or 'btn' component via selector fallback, got: %+v", comps)
	}
}

func TestOrganizeByComponent_GlobalFallback(t *testing.T) {
	sheets := []Stylesheet{
		{Path: "styles.css", Content: []byte("body { margin: 0; } * { box-sizing: border-box; }")},
	}
	comps := OrganizeByComponent(sheets)
	found := false
	for _, c := range comps {
		if c.Name == "_global" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '_global' component for unmatched styles, got: %+v", comps)
	}
}
