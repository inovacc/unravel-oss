package topic

import "testing"

func TestDerive(t *testing.T) {
	cases := []struct{ role, tags, summary, deps, want string }{
		{"util", "sendMessage,chat", "Sends a chat message", "[]", "messaging"},
		{"network", "", "Encrypts the session key", "[]", "crypto"},
		{"ui", "react,render", "Renders the call window", "[]", "ui"},
		{"", "telemetry,metric", "logs analytics events", "[]", "telemetry"},
		{"storage", "", "caches blobs in indexeddb", "[]", "storage"},
		{"auth", "", "", "[]", "auth"},
		{"", "", "", "[]", "other"},
		{"weirdrole", "", "", "[]", "other"},
	}
	for _, c := range cases {
		if got := Derive(c.role, c.tags, c.summary, c.deps); got != c.want {
			t.Errorf("Derive(%q,%q,%q)=%q want %q", c.role, c.tags, c.summary, got, c.want)
		}
	}
	if Derive("util", "sendMessage", "x", "[]") != Derive("util", "sendMessage", "x", "[]") {
		t.Fatal("not deterministic")
	}
}
