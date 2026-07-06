package prompt

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

func TestSystemPrompt_ContainsKeyRules(t *testing.T) {
	b := New()
	p := b.SystemPrompt()

	checks := []string{
		"std::vector",
		"std::map",
		"error",
		"goroutine",
		"struct",
		"Go",
		"C++",
		"camelCase",
		"PascalCase",
	}

	for _, want := range checks {
		if !strings.Contains(p, want) {
			t.Errorf("SystemPrompt() missing %q", want)
		}
	}
}

func TestConvertRawPrompt(t *testing.T) {
	b := New()
	p := b.ConvertRawPrompt("hello.cpp", `#include <iostream>\nint main() { return 0; }`)

	if !strings.Contains(p, "hello.cpp") {
		t.Error("ConvertRawPrompt() missing filename")
	}

	if !strings.Contains(p, "#include") {
		t.Error("ConvertRawPrompt() missing source code")
	}

	if !strings.Contains(p, "C++") {
		t.Error("ConvertRawPrompt() missing C++ keyword")
	}
}

func TestConvertModulePrompt(t *testing.T) {
	b := New()

	module := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Imports: []*ir.Import{
			{Path: "fmt"},
		},
		Decls: []ir.Node{
			&ir.FuncDecl{Name: "Hello"},
		},
	}

	p, err := b.ConvertModulePrompt(module)
	if err != nil {
		t.Fatalf("ConvertModulePrompt() error = %v", err)
	}

	if !strings.Contains(p, "test.cpp") {
		t.Error("ConvertModulePrompt() missing filename")
	}

	if !strings.Contains(p, `"Hello"`) {
		t.Error("ConvertModulePrompt() missing function name in JSON")
	}
}

func TestDetectIncludes(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   []string
	}{
		{
			name:   "system include",
			source: "#include <iostream>",
			want:   []string{"iostream"},
		},
		{
			name:   "local include",
			source: `#include "myheader.h"`,
			want:   []string{"myheader.h"},
		},
		{
			name:   "multiple includes",
			source: "#include <iostream>\n#include <vector>\n#include <string>",
			want:   []string{"iostream", "vector", "string"},
		},
		{
			name:   "path includes",
			source: "#include <boost/asio.hpp>\n#include <opencv2/core.hpp>",
			want:   []string{"boost/asio.hpp", "opencv2/core.hpp"},
		},
		{
			name:   "no includes",
			source: "int main() { return 0; }",
			want:   nil,
		},
		{
			name:   "deduplicated includes",
			source: "#include <iostream>\n#include <iostream>",
			want:   []string{"iostream"},
		},
		{
			name:   "spaced include",
			source: "  #  include  <vector>",
			want:   []string{"vector"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectIncludes(tt.source)
			if len(got) != len(tt.want) {
				t.Fatalf("DetectIncludes() = %v, want %v", got, tt.want)
			}

			for i, g := range got {
				if g != tt.want[i] {
					t.Errorf("DetectIncludes()[%d] = %q, want %q", i, g, tt.want[i])
				}
			}
		})
	}
}

func TestMapIncludeToRule(t *testing.T) {
	tests := []struct {
		include string
		want    string
	}{
		{"vector", "stl"},
		{"iostream", "stl"},
		{"boost/asio.hpp", "asio"},
		{"opencv2/core.hpp", "opencv"},
		{"gtest/gtest.h", "googletest"},
		{"nlohmann/json.hpp", "json"},
		{"unknown.h", ""},
		{"Qt/QtCore", "qt"},
	}

	for _, tt := range tests {
		t.Run(tt.include, func(t *testing.T) {
			got := MapIncludeToRule(tt.include)
			if got != tt.want {
				t.Errorf("MapIncludeToRule(%q) = %q, want %q", tt.include, got, tt.want)
			}
		})
	}
}

func TestSystemPrompt_ContainsCppPatterns(t *testing.T) {
	b := New()
	p := b.SystemPrompt()

	checks := []string{
		"Constructor",
		"Destructor",
		"Close()",
		"defer",
		"template",
		"Namespaces",
		"std::thread",
		"goroutine",
		"sync.Mutex",
	}

	for _, want := range checks {
		if !strings.Contains(p, want) {
			t.Errorf("SystemPrompt() missing C++ pattern %q", want)
		}
	}
}

func TestSystemPrompt_ContainsWarnings(t *testing.T) {
	b := New()
	p := b.SystemPrompt()

	checks := []string{
		"WARNING",
		"Qt",
		"OpenGL",
		"Eigen",
		"NO direct Go equivalent",
	}

	for _, want := range checks {
		if !strings.Contains(p, want) {
			t.Errorf("SystemPrompt() missing warning %q", want)
		}
	}
}
