//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// TestEnvArgValueOriginScoped is the CR-01 regression gate: the value
// written to the persistent HKCU hive must scope --remote-allow-origins to
// the exact loopback origin (http://127.0.0.1:PORT) and must NEVER contain
// the wildcard `*`. A leaked wildcard would let any web page (via
// DNS-rebinding to 127.0.0.1) drive CDP.
func TestEnvArgValueOriginScoped(t *testing.T) {
	const port = 9222
	v := envArgValue(port)
	want := fmt.Sprintf("--remote-allow-origins=http://127.0.0.1:%d", port)
	if !strings.Contains(v, want) {
		t.Fatalf("envArgValue(%d)=%q, want it to contain %q", port, v, want)
	}
	if strings.Contains(v, "--remote-allow-origins=*") {
		t.Fatalf("CR-01 regression: envArgValue(%d)=%q must NOT contain wildcard origin", port, v)
	}
	if !strings.Contains(v, fmt.Sprintf("--remote-debugging-port=%d", port)) {
		t.Fatalf("envArgValue(%d)=%q missing debug-port arg", port, v)
	}
}

// TestSelfHealRevertsLegacyWildcard is the CR-01 forward-compat gate: a
// value leaked by a pre-CR-01 binary (wildcard form) must still be
// recognized as unravel-tagged and reverted by self-heal when invoked
// standalone, so an old leak is repaired by a new binary.
func TestSelfHealRevertsLegacyWildcard(t *testing.T) {
	ctx := context.Background()
	legacy := "--remote-debugging-port=9222 --remote-allow-origins=*"
	if !isUnravelTaggedValue(legacy) {
		t.Fatalf("legacy wildcard value %q must still be recognized as unravel-tagged", legacy)
	}
	reg := &fakeRegistry{value: legacy, present: true}
	if err := selfHealWith(ctx, slog.Default(), reg, func() error { return nil }); err != nil {
		t.Fatalf("selfHealWith: %v", err)
	}
	if reg.present {
		t.Fatalf("expected legacy wildcard value reverted, got present=%v value=%q", reg.present, reg.value)
	}
	if reg.delHits != 1 {
		t.Fatalf("expected exactly 1 delete of legacy value, got %d", reg.delHits)
	}
}

// fakeRegistry is the test-local HKCU\Environment double implementing
// envRegistry, so the D-04 transactional revert and D-05 self-heal logic
// are exercised without touching the real user hive.
type fakeRegistry struct {
	value   string
	present bool
	setHits int
	delHits int
	getErr  error
	setErr  error
	delErr  error
}

func (r *fakeRegistry) Get() (string, bool, error) {
	if r.getErr != nil {
		return "", false, r.getErr
	}
	return r.value, r.present, nil
}

func (r *fakeRegistry) Set(v string) error {
	if r.setErr != nil {
		return r.setErr
	}
	r.value = v
	r.present = true
	r.setHits++
	return nil
}

func (r *fakeRegistry) Delete() error {
	if r.delErr != nil {
		return r.delErr
	}
	r.value = ""
	r.present = false
	r.delHits++
	return nil
}

// TestHKCURevert exercises D-04: snapshot prior HKCU state, Set the tagged
// value + broadcast, then CleanupHKCUEnv restores EXACTLY as found, on both
// the "absent prior" and "operator value prior" branches, and is idempotent
// on a double call.
func TestHKCURevert(t *testing.T) {
	ctx := context.Background()

	t.Run("absent_prior_reverts_to_absent", func(t *testing.T) {
		reg := &fakeRegistry{present: false}
		bcasts := 0
		h := newTestHost(slog.Default(), reg, func() error { bcasts++; return nil })

		if err := h.SetHKCUEnv(ctx, 9222); err != nil {
			t.Fatalf("SetHKCUEnv: %v", err)
		}
		if !reg.present || !isUnravelTaggedValue(reg.value) {
			t.Fatalf("expected tagged value set, got present=%v value=%q", reg.present, reg.value)
		}
		if err := h.CleanupHKCUEnv(ctx); err != nil {
			t.Fatalf("CleanupHKCUEnv: %v", err)
		}
		if reg.present {
			t.Fatalf("expected value deleted (prior absent), got present=%v value=%q", reg.present, reg.value)
		}
		if reg.delHits != 1 {
			t.Fatalf("expected exactly 1 delete, got %d", reg.delHits)
		}
		// Idempotent: second cleanup is a clean no-op.
		if err := h.CleanupHKCUEnv(ctx); err != nil {
			t.Fatalf("CleanupHKCUEnv (2nd): %v", err)
		}
		if reg.delHits != 1 {
			t.Fatalf("double-cleanup not idempotent: delHits=%d", reg.delHits)
		}
		if bcasts < 2 {
			t.Fatalf("expected >=2 broadcasts (set+cleanup), got %d", bcasts)
		}
	})

	t.Run("operator_prior_restored_exactly", func(t *testing.T) {
		const operatorVal = "--some-operator-flag"
		reg := &fakeRegistry{value: operatorVal, present: true}
		h := newTestHost(slog.Default(), reg, nil)

		if err := h.SetHKCUEnv(ctx, 9223); err != nil {
			t.Fatalf("SetHKCUEnv: %v", err)
		}
		if reg.value == operatorVal {
			t.Fatalf("expected operator value overwritten transiently")
		}
		if err := h.CleanupHKCUEnv(ctx); err != nil {
			t.Fatalf("CleanupHKCUEnv: %v", err)
		}
		if !reg.present || reg.value != operatorVal {
			t.Fatalf("expected operator value restored exactly, got present=%v value=%q", reg.present, reg.value)
		}
	})
}

// TestSelfHeal exercises D-05: a stale unravel-tagged value is reverted
// idempotently on start; an operator-set value is preserved; absent is a
// no-op; all idempotent on double-call.
func TestSelfHeal(t *testing.T) {
	ctx := context.Background()
	log := slog.Default()

	t.Run("stale_tagged_value_reverted", func(t *testing.T) {
		reg := &fakeRegistry{value: envArgValue(9222), present: true}
		bcasts := 0
		b := func() error { bcasts++; return nil }

		if err := selfHealWith(ctx, log, reg, b); err != nil {
			t.Fatalf("selfHealWith: %v", err)
		}
		if reg.present {
			t.Fatalf("expected stale value reverted, got present=%v value=%q", reg.present, reg.value)
		}
		if reg.delHits != 1 {
			t.Fatalf("expected exactly 1 delete, got %d", reg.delHits)
		}
		if bcasts != 1 {
			t.Fatalf("expected 1 broadcast, got %d", bcasts)
		}
		// Idempotent: second run is a clean no-op (value already gone).
		if err := selfHealWith(ctx, log, reg, b); err != nil {
			t.Fatalf("selfHealWith (2nd): %v", err)
		}
		if reg.delHits != 1 {
			t.Fatalf("double self-heal not idempotent: delHits=%d", reg.delHits)
		}
	})

	t.Run("operator_value_preserved", func(t *testing.T) {
		reg := &fakeRegistry{value: "--operator-only-flag", present: true}
		if err := selfHealWith(ctx, log, reg, nil); err != nil {
			t.Fatalf("selfHealWith: %v", err)
		}
		if !reg.present || reg.value != "--operator-only-flag" {
			t.Fatalf("operator value must be preserved, got present=%v value=%q", reg.present, reg.value)
		}
		if reg.delHits != 0 {
			t.Fatalf("operator value must not be deleted, delHits=%d", reg.delHits)
		}
	})

	t.Run("absent_is_noop", func(t *testing.T) {
		reg := &fakeRegistry{present: false}
		if err := selfHealWith(ctx, log, reg, nil); err != nil {
			t.Fatalf("selfHealWith: %v", err)
		}
		if reg.delHits != 0 || reg.setHits != 0 {
			t.Fatalf("absent must be a no-op, got delHits=%d setHits=%d", reg.delHits, reg.setHits)
		}
	})
}
