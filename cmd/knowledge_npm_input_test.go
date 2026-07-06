package cmd

import "testing"

func TestParseNPMInstallInput(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{input: "npm install -g @google/gemini-cli", want: "@google/gemini-cli", ok: true},
		{input: "npm i @openai/codex@1.2.3", want: "@openai/codex@1.2.3", ok: true},
		{input: "npm install --global --ignore-scripts express", want: "express", ok: true},
		{input: "npm view @openai/codex", ok: false},
		{input: "./package", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := parseNPMInstallInput(tt.input)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("parseNPMInstallInput(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.ok)
			}
		})
	}
}
