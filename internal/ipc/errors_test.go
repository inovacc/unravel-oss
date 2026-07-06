/*
Copyright (c) 2026 Security Research
*/
package ipc

import "testing"

func TestErrorBody_Codes_AllNonZeroAndUnique(t *testing.T) {
	codes := []int{
		CodeInvalidArg, CodeUnauthorized, CodeForbidden, CodeNotFound,
		CodeTimeout, CodeConflict, CodeInternal, CodeUpstream, CodeUnavailable,
	}
	seen := make(map[int]bool, len(codes))
	for _, c := range codes {
		if c == 0 {
			t.Errorf("code constant is 0; expected non-zero")
		}
		if seen[c] {
			t.Errorf("duplicate code value %d", c)
		}
		seen[c] = true
	}
}

func TestErrorBody_Error(t *testing.T) {
	e := &ErrorBody{Code: CodeNotFound, Message: "baseline missing"}
	got := e.Error()
	want := "ipc error 404: baseline missing"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
