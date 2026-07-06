package reconstruct

import "testing"

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name    string
		content string
		ext     string
		want    Language
	}{
		{
			name:    "Java by content",
			content: "package com.example;\nimport java.util.*;",
			ext:     "",
			want:    LangJava,
		},
		{
			name:    "JavaScript by content",
			content: "const x = () => {}; export default x;",
			ext:     "",
			want:    LangJavaScript,
		},
		{
			name:    "CSharp by content",
			content: "using System;\nnamespace Foo {\npublic class Bar {}",
			ext:     "",
			want:    LangCSharp,
		},
		{
			name:    "Go by content",
			content: "package main\nfunc main() {\n\tfmt.Println(\"hello\")\n}",
			ext:     "",
			want:    LangGo,
		},
		{
			name:    "Python by content",
			content: "def foo():\n    pass\nimport os",
			ext:     "",
			want:    LangPython,
		},
		{
			name:    "Unknown content returns unknown",
			content: "just some random text without any language markers",
			ext:     "",
			want:    LangUnknown,
		},
		{
			name:    "Content overrides wrong extension",
			content: "package com.example;\nimport java.util.List;\npublic class Foo {}",
			ext:     ".py",
			want:    LangJava,
		},
		{
			name:    "Extension fallback when content ambiguous",
			content: "// just a comment",
			ext:     ".java",
			want:    LangJava,
		},
		{
			name:    "TypeScript detected with type annotations and exports",
			content: "import { Foo } from 'bar';\nconst x: string = 'hello';\ninterface Baz {\n  name: string;\n}",
			ext:     "",
			want:    LangTypeScript,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectLanguage(tt.content, tt.ext)
			if got != tt.want {
				t.Errorf("DetectLanguage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectLanguageFromPath(t *testing.T) {
	got := DetectLanguageFromPath("package main\nfunc main() {}", "cmd/app/main.go")
	if got != LangGo {
		t.Errorf("DetectLanguageFromPath() = %q, want %q", got, LangGo)
	}
}
