package summaryview

import "testing"

func TestDisplayName(t *testing.T) {
	if got := DisplayName("teams_module_614040", "TeamsChatService"); got != "TeamsChatService" {
		t.Fatalf("placeholder + synthetic = %q", got)
	}
	if got := DisplayName("teams_module_42", ""); got != "teams_module_42" {
		t.Fatalf("placeholder + empty synthetic must return raw name = %q", got)
	}
	if got := DisplayName("WAWebSendMessage", "Ignored"); got != "WAWebSendMessage" {
		t.Fatalf("real name must never be overridden = %q", got)
	}
}

func TestPrefer(t *testing.T) {
	cases := map[string]bool{
		"does X": true,
		"":       false,
		"   ":    false,
		"\n\t":   false,
		"a":      true,
	}
	for in, want := range cases {
		if got := Prefer(in); got != want {
			t.Fatalf("Prefer(%q)=%v want %v", in, got, want)
		}
	}
}

func TestLine(t *testing.T) {
	if got := Line("Sends a message", "send", "msg,chat"); got != "[send] Sends a message {msg,chat}" {
		t.Fatalf("Line full = %q", got)
	}
	if got := Line("  Sends  ", "", ""); got != "Sends" {
		t.Fatalf("Line trim/no-role/no-tags = %q", got)
	}
	if got := Line("S", "role", ""); got != "[role] S" {
		t.Fatalf("Line role-only = %q", got)
	}
	if got := Line("S", "", "t1"); got != "S {t1}" {
		t.Fatalf("Line tags-only = %q", got)
	}
}
