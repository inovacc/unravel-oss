/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import (
	"strings"
	"testing"
)

func TestRedact_Table(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string // substrings expected in output
		not  []string // substrings NOT expected
	}{
		{
			name: "windows path",
			in:   `read failed: C:\Users\alice\secret\token.txt missing`,
			want: []string{"<path>", "read failed"},
			not:  []string{`C:\Users\alice`, "secret\\token"},
		},
		{
			name: "posix path",
			in:   `open /home/bob/.config/api.key: no such file`,
			want: []string{"<path>"},
			not:  []string{"/home/bob/.config"},
		},
		{
			name: "postgres dsn",
			in:   `connect: postgres://user:p4ss@db.local:5432/unravel?sslmode=disable`,
			want: []string{"<dsn>"},
			not:  []string{"p4ss", "db.local"},
		},
		{
			name: "postgresql dsn",
			in:   `dial postgresql://u:secret@host/db failed`,
			want: []string{"<dsn>"},
			not:  []string{"secret", "host/db"},
		},
		{
			name: "anthropic key shape",
			in:   `auth failed sk-ant-abcDEF1234567890abcdef token rejected`,
			want: []string{"<anthropic-key>"},
			not:  []string{"sk-ant-abcDEF1234567890abcdef"},
		},
		{
			name: "api_key= pair",
			in:   `request: api_key=ZZZZZZZZ failed`,
			want: []string{"api_key=<redacted>"},
			not:  []string{"ZZZZZZZZ"},
		},
		{
			name: "token: pair case-insensitive",
			in:   `Authorization Token: deadbeefcafe`,
			want: []string{"<redacted>"},
			not:  []string{"deadbeefcafe"},
		},
		{
			name: "password=",
			in:   `db: password=hunter2 invalid`,
			want: []string{"<redacted>"},
			not:  []string{"hunter2"},
		},
		{
			name: "env var leakage",
			in:   "ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx\nnext line",
			want: []string{"<env>=<redacted>"},
			not:  []string{"sk-ant-xxxxxxxxxxxxxxxxxxxx"},
		},
		{
			name: "truncation at 4096",
			in:   strings.Repeat("a", 5000),
			want: []string{"…(truncated)"},
		},
		{
			name: "no secrets passes through",
			in:   "json parse: unexpected token at offset 42",
			want: []string{"json parse", "offset 42"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("Redact(%q): want substring %q, got %q", tc.in, w, got)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(got, n) {
					t.Errorf("Redact(%q): leaked %q in %q", tc.in, n, got)
				}
			}
		})
	}
}

func TestRedact_Idempotent(t *testing.T) {
	inputs := []string{
		`C:\Users\alice\file.txt and postgres://u:p@h/d`,
		`api_key=ABC password=XYZ token: 123`,
		strings.Repeat("z", 6000),
		"",
		"plain text no secrets",
	}
	for _, in := range inputs {
		once := Redact(in)
		twice := Redact(once)
		if once != twice {
			t.Errorf("non-idempotent for %q:\n once=%q\ntwice=%q", in, once, twice)
		}
	}
}

func TestRedact_TruncationLength(t *testing.T) {
	in := strings.Repeat("x", 10000)
	got := Redact(in)
	if len(got) > 4096+len("…(truncated)") {
		t.Errorf("output too long: %d", len(got))
	}
	if !strings.HasSuffix(got, "…(truncated)") {
		t.Errorf("missing truncated suffix: %q", got[len(got)-20:])
	}
}
