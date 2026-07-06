/* Copyright (c) 2026 Security Research */
package manifest

import (
	"testing"
)

func TestExpandVariables(t *testing.T) {
	tests := []struct {
		name string
		s    string
		vars map[string]string
		want string
	}{
		{
			name: "single variable",
			s:    "hello ${NAME}",
			vars: map[string]string{"NAME": "world"},
			want: "hello world",
		},
		{
			name: "multiple variables",
			s:    "${GREETING} ${NAME}!",
			vars: map[string]string{"GREETING": "hi", "NAME": "alice"},
			want: "hi alice!",
		},
		{
			name: "no variables in string",
			s:    "no placeholders here",
			vars: map[string]string{"FOO": "bar"},
			want: "no placeholders here",
		},
		{
			name: "unmatched variable left as-is",
			s:    "hello ${MISSING}",
			vars: map[string]string{"OTHER": "val"},
			want: "hello ${MISSING}",
		},
		{
			name: "empty vars map",
			s:    "${FOO}",
			vars: map[string]string{},
			want: "${FOO}",
		},
		{
			name: "nil vars map",
			s:    "${FOO}",
			vars: nil,
			want: "${FOO}",
		},
		{
			name: "repeated variable",
			s:    "${X} and ${X}",
			vars: map[string]string{"X": "y"},
			want: "y and y",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExpandVariables(tt.s, tt.vars); got != tt.want {
				t.Errorf("ExpandVariables(%q, %v) = %q, want %q", tt.s, tt.vars, got, tt.want)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	m := Default()
	if m == nil {
		t.Fatal("Default() returned nil")
	}

	if m.Version == "" {
		t.Error("Default().Version should not be empty")
	}

	if m.Name == "" {
		t.Error("Default().Name should not be empty")
	}

	if len(m.Detection) == 0 {
		t.Error("Default().Detection should not be empty")
	}

	if m.Analysis == nil || len(m.Analysis) == 0 {
		t.Error("Default().Analysis should not be empty")
	}
}
