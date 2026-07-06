/* Copyright (c) 2026 Security Research */
package jsdeob

import (
	"testing"
)

func TestBeautify(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "empty string",
			code: "",
			want: "",
		},
		{
			name: "braces add newlines and indent",
			code: "if(x){a=1;}",
			want: "if(x){\n  a=1;\n\n}",
		},
		{
			name: "comma adds space",
			code: "a(1,2,3)",
			want: "a(1, 2, 3)",
		},
		{
			name: "string contents preserved",
			code: `var s="{test}"`,
			want: `var s="{test}"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Beautify(tt.code)
			if got != tt.want {
				t.Errorf("Beautify(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestDecodeHexString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "basic hex", input: `\x48\x65`, want: "He"},
		{name: "hello", input: `\x48\x65\x6c\x6c\x6f`, want: "Hello"},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeHexString(tt.input)
			if got != tt.want {
				t.Errorf("DecodeHexString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeUnicodeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "basic unicode", input: `\u0048\u0065`, want: "He"},
		{name: "hello", input: `\u0048\u0065\u006c\u006c\u006f`, want: "Hello"},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeUnicodeString(tt.input)
			if got != tt.want {
				t.Errorf("DecodeUnicodeString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeCharCodes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "He", input: "72, 101", want: "He"},
		{name: "Hello", input: "72, 101, 108, 108, 111", want: "Hello"},
		{name: "invalid returns empty", input: "abc", want: ""},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeCharCodes(tt.input)
			if got != tt.want {
				t.Errorf("DecodeCharCodes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnpackPacked(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
		contains  string
	}{
		{
			name:      "atob base64",
			code:      `atob("SGVsbG8=")`,
			wantCount: 1,
			contains:  "Hello",
		},
		{
			name:      "String.fromCharCode",
			code:      `String.fromCharCode(72, 101, 108, 108, 111)`,
			wantCount: 1,
			contains:  "Hello",
		},
		{
			name:      "no packed content",
			code:      `var x = 1;`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, count := UnpackPacked(tt.code)
			if count != tt.wantCount {
				t.Errorf("UnpackPacked() count = %d, want %d", count, tt.wantCount)
			}
			if tt.contains != "" && !containsStr(got, tt.contains) {
				t.Errorf("UnpackPacked() result %q does not contain %q", got, tt.contains)
			}
		})
	}
}

func TestDecodeStrings(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
		contains  string
	}{
		{
			name:      "hex string in quotes",
			code:      `"\x48\x65\x6c\x6c\x6f"`,
			wantCount: 1,
			contains:  "Hello",
		},
		{
			name:      "unicode string in quotes",
			code:      `"\u0048\u0065\u006c\u006c\u006f"`,
			wantCount: 1,
			contains:  "Hello",
		},
		{
			name:      "no encoded strings",
			code:      `"plain text"`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, count := DecodeStrings(tt.code)
			if count != tt.wantCount {
				t.Errorf("DecodeStrings() count = %d, want %d", count, tt.wantCount)
			}
			if tt.contains != "" && !containsStr(got, tt.contains) {
				t.Errorf("DecodeStrings() result %q does not contain %q", got, tt.contains)
			}
		})
	}
}

func TestExtractStrings(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{name: "double quoted", code: `var x = "hello world"`, want: 1},
		{name: "single quoted", code: `var x = 'hello world'`, want: 1},
		{name: "short strings excluded", code: `var x = "ab"`, want: 0},
		{name: "empty code", code: "", want: 0},
		{name: "dedup", code: `"hello" + "hello"`, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractStrings(tt.code)
			if len(got) != tt.want {
				t.Errorf("ExtractStrings() returned %d strings, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractURLs(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{name: "https url", code: `fetch("https://example.com/api")`, want: 1},
		{name: "http url", code: `var u = "http://test.com/path"`, want: 1},
		{name: "no urls", code: `var x = 1;`, want: 0},
		{name: "dedup", code: `"https://a.com" + "https://a.com"`, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractURLs(tt.code)
			if len(got) != tt.want {
				t.Errorf("ExtractURLs() returned %d urls, want %d", len(got), tt.want)
			}
		})
	}
}

func TestExtractFunctions(t *testing.T) {
	tests := []struct {
		name string
		code string
		want []string
	}{
		{
			name: "function declaration",
			code: `function hello() {}`,
			want: []string{"hello"},
		},
		{
			name: "arrow function",
			code: `const greet = () => {}`,
			want: []string{"greet"},
		},
		{
			name: "no functions",
			code: `var x = 1;`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFunctions(tt.code)
			if len(got) != len(tt.want) {
				t.Errorf("ExtractFunctions() returned %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAPICalls(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		// Each call-site URL `/api/...` also matches the standalone apiPaths regex,
		// so a single call-site emits 2 entries (e.g. "fetch: /api/data" + "path: /api/data").
		// This is intentional — apiPaths was added to capture API surfaces missed by call-site regexes.
		{name: "fetch call", code: `fetch("/api/data")`, want: 2},
		{name: "axios get", code: `axios.get("/api/data")`, want: 2},
		{name: "xhr open", code: `.open("GET", "/api/data")`, want: 2},
		{name: "no api calls", code: `var x = 1;`, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractAPICalls(tt.code)
			if len(got) != tt.want {
				t.Errorf("ExtractAPICalls() returned %d calls, want %d", len(got), tt.want)
			}
		})
	}
}

func TestSimplifyMath(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		want    string
		wantMin int
	}{
		{name: "addition", code: "1 + 2", want: "3", wantMin: 1},
		{name: "subtraction", code: "10 - 3", want: "7", wantMin: 1},
		{name: "multiplication", code: "2 * 3", want: "6", wantMin: 1},
		{name: "no math", code: "var x;", want: "var x;", wantMin: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, count := SimplifyMath(tt.code)
			if got != tt.want {
				t.Errorf("SimplifyMath(%q) = %q, want %q", tt.code, got, tt.want)
			}
			if count < tt.wantMin {
				t.Errorf("SimplifyMath() count = %d, want >= %d", count, tt.wantMin)
			}
		})
	}
}

func TestRenameVariables(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name:      "obfuscated variable",
			code:      `var _0x1234 = 1; _0x1234 + 2;`,
			wantCount: 1,
		},
		{
			name:      "no obfuscated variables",
			code:      `var x = 1;`,
			wantCount: 0,
		},
		{
			name:      "multiple obfuscated variables",
			code:      `var _0xabcd = 1; var _0x5678 = 2;`,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, count := RenameVariables(tt.code)
			if count != tt.wantCount {
				t.Errorf("RenameVariables() count = %d, want %d", count, tt.wantCount)
			}
			if tt.wantCount > 0 && containsStr(got, "_0x") {
				t.Errorf("RenameVariables() result still contains _0x patterns: %q", got)
			}
		})
	}
}

func TestDeobfuscate(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		opts           Options
		wantTransforms int
		wantContains   string
		wantURLs       int
		wantStrs       int
	}{
		{
			name:           "no options returns code unchanged",
			code:           `var x = 1;`,
			opts:           Options{},
			wantTransforms: 0,
		},
		{
			name:           "unpack only",
			code:           `atob("SGVsbG8=")`,
			opts:           Options{UnpackPacked: true},
			wantTransforms: 1,
			wantContains:   "Hello",
		},
		{
			name:           "decode strings only",
			code:           `"\x48\x65\x6c\x6c\x6f"`,
			opts:           Options{DecodeStrings: true},
			wantTransforms: 1,
			wantContains:   "Hello",
		},
		{
			name:           "simplify math only",
			code:           `var x = 2 + 3;`,
			opts:           Options{SimplifyMath: true},
			wantTransforms: 1,
			wantContains:   "5",
		},
		{
			name:           "rename vars only",
			code:           `var _0x1234 = 1; _0x1234 + 2;`,
			opts:           Options{RenameVars: true},
			wantTransforms: 1,
		},
		{
			name:           "beautify only",
			code:           `if(x){a=1;}`,
			opts:           Options{Beautify: true},
			wantTransforms: 1,
		},
		{
			name:     "extract strings and urls",
			code:     `var url = "https://example.com/api"; var name = "hello world";`,
			opts:     Options{ExtractStrings: true},
			wantURLs: 1,
			wantStrs: 2,
		},
		{
			name:         "all options combined",
			code:         `var _0xab = atob("SGVsbG8="); var y = 1 + 2;`,
			opts:         Options{UnpackPacked: true, DecodeStrings: true, SimplifyMath: true, RenameVars: true, Beautify: true, ExtractStrings: true},
			wantContains: "Hello",
		},
		{
			name:           "no transformations when nothing matches",
			code:           `var x = 1;`,
			opts:           Options{UnpackPacked: true, DecodeStrings: true, SimplifyMath: true, RenameVars: true},
			wantTransforms: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Deobfuscate(tt.code, tt.opts)
			if err != nil {
				t.Fatalf("Deobfuscate() error = %v", err)
			}
			if result == nil {
				t.Fatal("Deobfuscate() returned nil result")
			}
			if tt.wantTransforms > 0 && len(result.Transformations) < tt.wantTransforms {
				t.Errorf("got %d transformations, want >= %d", len(result.Transformations), tt.wantTransforms)
			}
			if tt.wantContains != "" && !stringContains(result.Code, tt.wantContains) {
				t.Errorf("result code %q does not contain %q", result.Code, tt.wantContains)
			}
			if tt.wantURLs > 0 && len(result.ExtractedURLs) < tt.wantURLs {
				t.Errorf("got %d URLs, want >= %d", len(result.ExtractedURLs), tt.wantURLs)
			}
			if tt.wantStrs > 0 && len(result.ExtractedStrs) < tt.wantStrs {
				t.Errorf("got %d strings, want >= %d", len(result.ExtractedStrs), tt.wantStrs)
			}
		})
	}
}

func TestDecodeStrings_ArrayLookup(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
		contains  string
	}{
		{
			name:      "array-based string lookup",
			code:      `var _0xabc = ["hello", "world"]; console.log(_0xabc[0]);`,
			wantCount: 1,
			contains:  `"hello"`,
		},
		{
			name:      "array lookup multiple indices",
			code:      `var _0xdef = ["foo", "bar", "baz"]; _0xdef[0] + _0xdef[2];`,
			wantCount: 2,
			contains:  `"foo"`,
		},
		{
			name:      "array lookup out of bounds unchanged",
			code:      `var _0xaaa = ["only"]; _0xaaa[5];`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, count := DecodeStrings(tt.code)
			if count != tt.wantCount {
				t.Errorf("DecodeStrings() count = %d, want %d", count, tt.wantCount)
			}
			if tt.contains != "" && !stringContains(got, tt.contains) {
				t.Errorf("DecodeStrings() = %q, want to contain %q", got, tt.contains)
			}
		})
	}
}

func TestIsInsideForLoop(t *testing.T) {
	tests := []struct {
		name string
		code string
		pos  int
		want bool
	}{
		{
			name: "semicolon inside for loop parens",
			code: "for(var i=0; i<10; i++){x++;}",
			pos:  11, // first ; in for(var i=0;
			want: true,
		},
		{
			name: "semicolon outside for loop",
			code: "for(var i=0; i<10; i++){x++;}",
			pos:  27, // ; after x++
			want: false,
		},
		{
			name: "no for loop at all",
			code: "var x = 1;",
			pos:  9,
			want: false,
		},
		{
			name: "semicolon in second part of for",
			code: "for(var i=0; i<10; i++){x++;}",
			pos:  17, // second ; in for
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInsideForLoop(tt.code, tt.pos)
			if got != tt.want {
				t.Errorf("isInsideForLoop(%q, %d) = %v, want %v", tt.code, tt.pos, got, tt.want)
			}
		})
	}
}

func TestBeautifyForLoop(t *testing.T) {
	code := "for(var i=0;i<10;i++){x++;}"
	got := Beautify(code)
	// Semicolons inside for loop parens should NOT get newlines
	if stringContains(got, "i=0;\n") {
		t.Errorf("Beautify() broke for loop: %q", got)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
