// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteCSS_BasicRule(t *testing.T) {
	rules := []Rule{
		{Selector: ".btn", Declarations: []Declaration{
			{Property: "color", Value: "red"},
			{Property: "padding", Value: "8px"},
		}},
	}
	var buf bytes.Buffer
	if err := WriteCSS(rules, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, ".btn {") {
		t.Error("expected '.btn {' in output")
	}
	if !strings.Contains(out, "  color: red;") {
		t.Errorf("expected 2-space indented 'color: red;' in output, got:\n%s", out)
	}
}

func TestWriteCSS_MediaNested(t *testing.T) {
	rules := []Rule{
		{AtRule: "@media (max-width: 768px)", Children: []Rule{
			{Selector: ".btn", Declarations: []Declaration{
				{Property: "color", Value: "blue"},
			}},
		}},
	}
	var buf bytes.Buffer
	if err := WriteCSS(rules, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "@media (max-width: 768px) {") {
		t.Error("expected @media block")
	}
	if !strings.Contains(out, "  .btn {") {
		t.Errorf("expected nested .btn with 2-space indent, got:\n%s", out)
	}
	if !strings.Contains(out, "    color: blue;") {
		t.Errorf("expected 4-space nested declaration, got:\n%s", out)
	}
}

func TestWriteCSS_Keyframes(t *testing.T) {
	rules := []Rule{
		{AtRule: "@keyframes fade", Children: []Rule{
			{Selector: "0%", Declarations: []Declaration{
				{Property: "opacity", Value: "0"},
			}},
			{Selector: "100%", Declarations: []Declaration{
				{Property: "opacity", Value: "1"},
			}},
		}},
	}
	var buf bytes.Buffer
	if err := WriteCSS(rules, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "0% {") {
		t.Error("expected 0% keyframe step")
	}
	if !strings.Contains(out, "100% {") {
		t.Error("expected 100% keyframe step")
	}
}

func TestFormatRule(t *testing.T) {
	rule := Rule{
		Selector: ".card",
		Declarations: []Declaration{
			{Property: "margin", Value: "10px"},
			{Property: "padding", Value: "20px", Important: true},
		},
	}
	out := FormatRule(rule)
	if !strings.Contains(out, ".card {") {
		t.Error("expected '.card {' in output")
	}
	if !strings.Contains(out, "!important") {
		t.Error("expected !important in output")
	}
}

func TestWriteCSS_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSS([]Rule{}, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "" {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestWriteCSS_BlankLinesBetweenRules(t *testing.T) {
	rules := []Rule{
		{Selector: ".a", Declarations: []Declaration{{Property: "color", Value: "red"}}},
		{Selector: ".b", Declarations: []Declaration{{Property: "color", Value: "blue"}}},
	}
	var buf bytes.Buffer
	if err := WriteCSS(rules, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// Should have a blank line between rules
	if !strings.Contains(out, "}\n\n.b {") {
		t.Errorf("expected blank line between rules, got:\n%s", out)
	}
}
