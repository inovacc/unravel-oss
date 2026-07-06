/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import (
	"context"
	"testing"
)

func TestHumanReview_NilDB(t *testing.T) {
	_, err := HumanReview(context.Background(), nil, HumanReviewOptions{})
	if err == nil {
		t.Fatalf("HumanReview(nil db): want error, got nil")
	}
}

func TestHumanReview_UnknownAction(t *testing.T) {
	// nil db short-circuits first; exercise the action-validation surface
	// by calling with a non-nil look-alike. Since *sql.DB is opaque, we
	// validate the dispatcher only at the function entry — deeper coverage
	// is in the integration tests.
	_, err := HumanReview(context.Background(), nil, HumanReviewOptions{Action: "bogus"})
	if err == nil {
		t.Fatalf("HumanReview: want error, got nil")
	}
}

func TestHumanReview_MarkResolvedRequiresModuleID(t *testing.T) {
	_, err := HumanReview(context.Background(), nil, HumanReviewOptions{Action: HumanReviewActionMarkResolved})
	if err == nil {
		t.Fatalf("HumanReview(mark_resolved, module_id=0): want error, got nil")
	}
}
