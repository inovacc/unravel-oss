/*
Copyright (c) 2026 Security Research
*/
package tauri

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestInjectActive_AlwaysUnsupported(t *testing.T) {
	_, err := InjectActive(context.Background(), "/path", inject.InjectOpts{
		Method:    inject.MethodCDP,
		Confirmed: true,
	})
	if !errors.Is(err, inject.ErrTauriUnsupported) {
		t.Fatalf("expected ErrTauriUnsupported, got %v", err)
	}
}

func TestInjectActive_RefusesEvenWithoutConsent(t *testing.T) {
	// Tauri stub does not gate on Confirmed — it returns Unsupported
	// regardless. Check the contract is stable.
	_, err := InjectActive(context.Background(), "/path", inject.InjectOpts{})
	if !errors.Is(err, inject.ErrTauriUnsupported) {
		t.Fatalf("expected ErrTauriUnsupported, got %v", err)
	}
}
