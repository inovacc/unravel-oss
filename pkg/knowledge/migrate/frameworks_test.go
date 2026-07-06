/*
Copyright (c) 2026 Security Research
*/
package migrate

import (
	"sort"
	"testing"
)

func TestValidFrameworks(t *testing.T) {
	got := ValidFrameworks()
	want := []string{"angular", "flutter", "react", "react-native", "svelte", "vue", "winui3", "wpf"}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("ValidFrameworks length = %d want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ValidFrameworks[%d] = %q want %q", i, got[i], want[i])
		}
	}
	if !IsValid("react") {
		t.Errorf("IsValid(react) = false; want true")
	}
	if IsValid("ruby-on-rails") {
		t.Errorf("IsValid(ruby-on-rails) = true; want false")
	}
	if IsValid("React") {
		t.Errorf("IsValid(React) = true; want false (case sensitive)")
	}
}

func TestValidFrameworksReturnsCopy(t *testing.T) {
	a := ValidFrameworks()
	b := ValidFrameworks()
	a[0] = "tampered"
	if b[0] == "tampered" {
		t.Errorf("ValidFrameworks must return a fresh copy each call")
	}
}
