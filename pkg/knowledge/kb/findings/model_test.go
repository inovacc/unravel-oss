package findings

import "testing"

func TestValidStance(t *testing.T) {
	good := []string{"affirm", "contradict", "augment", "uncertain"}
	for _, s := range good {
		if err := ValidStance(s); err != nil {
			t.Errorf("ValidStance(%q) unexpected error: %v", s, err)
		}
	}

	bad := []string{"", "AFFIRM", "unknown", "reject"}
	for _, s := range bad {
		if err := ValidStance(s); err == nil {
			t.Errorf("ValidStance(%q) expected error, got nil", s)
		}
	}
}

func TestValidStatus(t *testing.T) {
	good := []string{"open", "accepted", "rejected", "applied", "superseded"}
	for _, s := range good {
		if err := ValidStatus(s); err != nil {
			t.Errorf("ValidStatus(%q) unexpected error: %v", s, err)
		}
	}

	bad := []string{"", "Open", "pending", "done"}
	for _, s := range bad {
		if err := ValidStatus(s); err == nil {
			t.Errorf("ValidStatus(%q) expected error, got nil", s)
		}
	}
}

func TestStanceConstants(t *testing.T) {
	if string(StanceAffirm) != "affirm" {
		t.Errorf("StanceAffirm = %q", StanceAffirm)
	}
	if string(StanceContradict) != "contradict" {
		t.Errorf("StanceContradict = %q", StanceContradict)
	}
	if string(StanceAugment) != "augment" {
		t.Errorf("StanceAugment = %q", StanceAugment)
	}
	if string(StanceUncertain) != "uncertain" {
		t.Errorf("StanceUncertain = %q", StanceUncertain)
	}
}

func TestStatusConstants(t *testing.T) {
	if string(StatusOpen) != "open" {
		t.Errorf("StatusOpen = %q", StatusOpen)
	}
	if string(StatusAccepted) != "accepted" {
		t.Errorf("StatusAccepted = %q", StatusAccepted)
	}
	if string(StatusRejected) != "rejected" {
		t.Errorf("StatusRejected = %q", StatusRejected)
	}
	if string(StatusApplied) != "applied" {
		t.Errorf("StatusApplied = %q", StatusApplied)
	}
	if string(StatusSuperseded) != "superseded" {
		t.Errorf("StatusSuperseded = %q", StatusSuperseded)
	}
}

func TestScopeOrDefault(t *testing.T) {
	if got := scopeOrDefault(""); got != "module" {
		t.Errorf("scopeOrDefault(\"\") = %q, want \"module\"", got)
	}
	if got := scopeOrDefault("app"); got != "app" {
		t.Errorf("scopeOrDefault(\"app\") = %q, want \"app\"", got)
	}
}

func TestIterOrDefault(t *testing.T) {
	if got := iterOrDefault(0); got != 1 {
		t.Errorf("iterOrDefault(0) = %d, want 1", got)
	}
	if got := iterOrDefault(-5); got != 1 {
		t.Errorf("iterOrDefault(-5) = %d, want 1", got)
	}
	if got := iterOrDefault(3); got != 3 {
		t.Errorf("iterOrDefault(3) = %d, want 3", got)
	}
}

func TestStatusOrDefault(t *testing.T) {
	if got := statusOrDefault(""); got != "open" {
		t.Errorf("statusOrDefault(\"\") = %q, want \"open\"", got)
	}
	if got := statusOrDefault(StatusAccepted); got != "accepted" {
		t.Errorf("statusOrDefault(accepted) = %q", got)
	}
}

func TestClampLimit(t *testing.T) {
	if got := clampLimit(0); got != defaultLimit {
		t.Errorf("clampLimit(0) = %d, want %d", got, defaultLimit)
	}
	if got := clampLimit(-1); got != defaultLimit {
		t.Errorf("clampLimit(-1) = %d, want %d", got, defaultLimit)
	}
	if got := clampLimit(10); got != 10 {
		t.Errorf("clampLimit(10) = %d, want 10", got)
	}
	if got := clampLimit(600); got != defaultLimit {
		t.Errorf("clampLimit(600) = %d, want %d", got, defaultLimit)
	}
}

func TestNullHelpers(t *testing.T) {
	if ns := nullString(""); ns.Valid {
		t.Error("nullString(\"\") should be invalid")
	}
	if ns := nullString("x"); !ns.Valid || ns.String != "x" {
		t.Errorf("nullString(\"x\") = %+v", ns)
	}

	v := int64(42)
	if ni := nullInt64(&v); !ni.Valid || ni.Int64 != 42 {
		t.Errorf("nullInt64(&42) = %+v", ni)
	}
	if ni := nullInt64(nil); ni.Valid {
		t.Error("nullInt64(nil) should be invalid")
	}

	if nf := nullFloat64(0); nf.Valid {
		t.Error("nullFloat64(0) should be invalid")
	}
	if nf := nullFloat64(0.5); !nf.Valid || nf.Float64 != 0.5 {
		t.Errorf("nullFloat64(0.5) = %+v", nf)
	}
}
