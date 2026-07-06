package goversions

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"go1.21.0", "go1.21.5", -1},
		{"go1.21.5", "go1.21.0", 1},
		{"go1.21.0", "go1.21.0", 0},
		{"1.20.3", "1.20.5", -1},
		{"go1", "go1.2", -1},
		{"go1.21rc1", "go1.21.0", -1},
		{"go1.21.0", "go1.21rc1", 1},
		{"go1.26.4", "go1.9", 1},
	}
	for _, tt := range tests {
		got := Compare(tt.a, tt.b)
		if sign(got) != tt.want {
			t.Errorf("Compare(%q,%q)=%d want sign %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
