/*
Copyright (c) 2026 Security Research
*/

package eval_test

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/eval"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime"
)

func mkEntry(id, pred, human, status string) eval.CorpusEntryV2 {
	return eval.CorpusEntryV2{
		ID:             id,
		Name:           "n-" + id,
		Path:           "p/" + id,
		HumanLabel:     human,
		PredictedLabel: pred,
		Confidence:     0.9,
		ReviewStatus:   status,
	}
}

func TestPrecisionV2_Determinism(t *testing.T) {
	c := &eval.CorpusV2{
		SchemaVersion: 2,
		Entries: []eval.CorpusEntryV2{
			mkEntry("a", "auth", "auth", "accepted"),
			mkEntry("b", "crypto", "crypto", "accepted"),
			mkEntry("c", "ui", "auth", "edited"),
		},
	}
	first, err := eval.PrecisionV2(c)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for i := range 10 {
		r, err := eval.PrecisionV2(c)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if r != first {
			t.Errorf("run %d differs: %+v vs %+v", i, r, first)
		}
	}
}

func TestPrecisionV2_NilCorpus(t *testing.T) {
	if _, err := eval.PrecisionV2(nil); err == nil {
		t.Fatalf("expected error on nil")
	}
}

func TestPrecisionV2_AllPending(t *testing.T) {
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("a", "auth", "auth", "pending"),
		mkEntry("b", "crypto", "crypto", "pending"),
	}}
	_, err := eval.PrecisionV2(c)
	if err == nil || !strings.Contains(err.Error(), "no reviewed") {
		t.Fatalf("expected no-reviewed error, got %v", err)
	}
}

func TestPrecisionV2_AllAccepted_AllCorrect(t *testing.T) {
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("a", "auth", "auth", "accepted"),
		mkEntry("b", "crypto", "crypto", "accepted"),
	}}
	r, err := eval.PrecisionV2(c)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Precision != 1.0 {
		t.Errorf("precision: got %v want 1.0", r.Precision)
	}
}

func TestPrecisionV2_HalfRejected(t *testing.T) {
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("a", "auth", "auth", "accepted"),
		mkEntry("b", "auth", "auth", "rejected"),
	}}
	r, err := eval.PrecisionV2(c)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Reviewed != 2 {
		t.Errorf("Reviewed: got %d want 2", r.Reviewed)
	}
	if r.Rejected != 1 {
		t.Errorf("Rejected: got %d want 1", r.Rejected)
	}
	// 1 correct / 2 reviewed = 0.5
	if r.Precision != 0.5 {
		t.Errorf("Precision: got %v want 0.5", r.Precision)
	}
}

func TestPrecisionV2_UnknownReviewStatus(t *testing.T) {
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("xyz", "auth", "auth", "weird"),
	}}
	_, err := eval.PrecisionV2(c)
	if err == nil || !strings.Contains(err.Error(), "xyz") {
		t.Fatalf("expected error mentioning entry id, got %v", err)
	}
}

func TestPrecisionV2_EditedCorrectsClassifier(t *testing.T) {
	// edited entry where human_label==predicted_label counts toward correct.
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("a", "auth", "auth", "edited"),
	}}
	r, err := eval.PrecisionV2(c)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Edited != 1 || r.Precision != 1.0 {
		t.Errorf("got %+v", r)
	}
}

func TestPrecisionV2_80PercentBoundary(t *testing.T) {
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("a", "auth", "auth", "accepted"),
		mkEntry("b", "auth", "auth", "accepted"),
		mkEntry("c", "auth", "auth", "accepted"),
		mkEntry("d", "auth", "auth", "accepted"),
		mkEntry("e", "auth", "ui", "edited"), // wrong (predicted!=human)
	}}
	r, err := eval.PrecisionV2(c)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Precision != 0.8 {
		t.Errorf("Precision: got %v want 0.8", r.Precision)
	}
}

func TestPrecisionV2_BelowThreshold(t *testing.T) {
	c := &eval.CorpusV2{Entries: []eval.CorpusEntryV2{
		mkEntry("a", "auth", "auth", "accepted"),
		mkEntry("b", "auth", "auth", "accepted"),
		mkEntry("c", "auth", "auth", "accepted"),
		mkEntry("d", "auth", "ui", "edited"),
		mkEntry("e", "auth", "ui", "edited"),
	}}
	r, err := eval.PrecisionV2(c)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Precision != 0.6 {
		t.Errorf("Precision: got %v want 0.6", r.Precision)
	}
}
