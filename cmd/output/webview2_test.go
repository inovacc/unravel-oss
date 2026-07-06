/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"testing"
)

// ── orDash ────────────────────────────────────────────────────────────────────

func TestOrDash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "empty string", s: "", want: "-"},
		{name: "non-empty", s: "fixed", want: "fixed"},
		{name: "space", s: " ", want: " "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := orDash(tc.s)
			if got != tc.want {
				t.Errorf("orDash(%q) = %q; want %q", tc.s, got, tc.want)
			}
		})
	}
}

// ── orDashU ───────────────────────────────────────────────────────────────────

func TestOrDashU(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "empty string", s: "", want: "-"},
		{name: "non-empty", s: "Microsoft.App_1.0.0.0_x64", want: "Microsoft.App_1.0.0.0_x64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := orDashU(tc.s)
			if got != tc.want {
				t.Errorf("orDashU(%q) = %q; want %q", tc.s, got, tc.want)
			}
		})
	}
}
