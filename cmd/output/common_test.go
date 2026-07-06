/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{name: "short string unchanged", s: "hello", maxLen: 10, want: "hello"},
		{name: "exact length unchanged", s: "hello", maxLen: 5, want: "hello"},
		{name: "truncate with ellipsis", s: "hello world", maxLen: 8, want: "hello..."},
		{name: "maxLen=3 no ellipsis", s: "hello", maxLen: 3, want: "hel"},
		{name: "maxLen=2 no ellipsis", s: "hello", maxLen: 2, want: "he"},
		{name: "maxLen=1 no ellipsis", s: "hello", maxLen: 1, want: "h"},
		{name: "empty string", s: "", maxLen: 5, want: ""},
		{name: "exactly maxLen-3 chars+ellipsis", s: "1234567890", maxLen: 7, want: "1234..."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Truncate(tc.s, tc.maxLen)
			if got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q; want %q", tc.s, tc.maxLen, got, tc.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{name: "zero bytes", bytes: 0, want: "0 bytes"},
		{name: "below KB", bytes: 512, want: "512 bytes"},
		{name: "exactly 1 KB", bytes: 1024, want: "1.0 KB"},
		{name: "2 KB", bytes: 2048, want: "2.0 KB"},
		{name: "below MB", bytes: 500 * 1024, want: "500.0 KB"},
		{name: "exactly 1 MB", bytes: 1024 * 1024, want: "1.0 MB"},
		{name: "1.5 MB", bytes: 1536 * 1024, want: "1.5 MB"},
		{name: "exactly 1 GB", bytes: 1024 * 1024 * 1024, want: "1.0 GB"},
		{name: "2.5 GB", bytes: int64(2.5 * 1024 * 1024 * 1024), want: "2.5 GB"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FormatSize(tc.bytes)
			if got != tc.want {
				t.Errorf("FormatSize(%d) = %q; want %q", tc.bytes, got, tc.want)
			}
		})
	}
}

func TestBoolYesNo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    bool
		want string
	}{
		{name: "true", b: true, want: "Yes"},
		{name: "false", b: false, want: "No"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := BoolYesNo(tc.b)
			if got != tc.want {
				t.Errorf("BoolYesNo(%v) = %q; want %q", tc.b, got, tc.want)
			}
		})
	}
}

func TestCountDigits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		n    int
		want int
	}{
		{name: "zero", n: 0, want: 1},
		{name: "single digit", n: 5, want: 1},
		{name: "two digits", n: 10, want: 2},
		{name: "three digits", n: 100, want: 3},
		{name: "nine digits", n: 123456789, want: 9},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := CountDigits(tc.n)
			if got != tc.want {
				t.Errorf("CountDigits(%d) = %d; want %d", tc.n, got, tc.want)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		s      string
		maxLen int
		want   []string
	}{
		{
			name:   "fits in one line",
			s:      "hello world",
			maxLen: 20,
			want:   []string{"hello world"},
		},
		{
			name:   "wraps at word boundary",
			s:      "hello world foo",
			maxLen: 11,
			// WrapText scans backwards from maxLen-1=10; first space found at idx=5 ("hello")
			// remaining = "world foo" (len 9 ≤ 11), so two lines.
			want: []string{"hello", "world foo"},
		},
		{
			name:   "no space to wrap on",
			s:      "helloworld",
			maxLen: 5,
			want:   []string{"hello", "world"},
		},
		{
			name:   "exact fit no wrap",
			s:      "hello",
			maxLen: 5,
			want:   []string{"hello"},
		},
		{
			name:   "multiple wraps",
			s:      "one two three four five",
			maxLen: 9,
			want:   []string{"one two", "three", "four five"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := WrapText(tc.s, tc.maxLen)
			if len(got) != len(tc.want) {
				t.Fatalf("WrapText(%q, %d) = %v (len=%d); want %v (len=%d)",
					tc.s, tc.maxLen, got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("WrapText line %d = %q; want %q", i, got[i], tc.want[i])
				}
			}
		})
	}

	// Verify that each line in any output is within maxLen
	t.Run("each line within maxLen", func(t *testing.T) {
		t.Parallel()
		input := strings.Repeat("word ", 50)
		lines := WrapText(input, 20)
		for i, l := range lines {
			if len(l) > 20 {
				t.Errorf("line %d length %d > 20: %q", i, len(l), l)
			}
		}
	})
}
