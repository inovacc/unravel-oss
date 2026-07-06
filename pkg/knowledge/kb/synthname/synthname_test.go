package synthname

import "testing"

func TestDerive(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{"amd_define", `__d("TeamsChatService",["a","b"],function(){})`, "TeamsChatService", true},
		{"define_quoted", `define('Foo.react',[],function(){return 1})`, "Foo.react", true},
		{"export_function", `"use strict";export function sendChatMessage(x){return x}`, "sendChatMessage", true},
		{"class_decl", `;class TeamsCallManager extends Base{constructor(){}}`, "TeamsCallManager", true},
		{"noise_only", `;(function(){var a=1;return a+2})();`, "", false},
		{"empty", ``, "", false},
		{"whitespace", "   \n\t ", "", false},
	}
	for _, c := range cases {
		got, ok := Derive(c.body)
		if got != c.want || ok != c.ok {
			t.Fatalf("%s: Derive()=%q,%v want %q,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestDeriveDeterministicAndSanitized(t *testing.T) {
	b := `__d("Repeat\nName",[],function(){})`
	a1, ok1 := Derive(b)
	a2, ok2 := Derive(b)
	if a1 != a2 || ok1 != ok2 {
		t.Fatalf("non-deterministic: %q/%v vs %q/%v", a1, ok1, a2, ok2)
	}
	if ok1 {
		for _, r := range a1 {
			if r == '\n' || r == '\r' || r == '\t' {
				t.Fatalf("unsanitized control char in %q", a1)
			}
		}
		if len(a1) > 80 {
			t.Fatalf("name not length-bounded: %d", len(a1))
		}
	}
	long := `class ` + string(make([]byte, 200)) + `X{}`
	_, _ = Derive(long) // must not panic
}
