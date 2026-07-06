/*
Copyright (c) 2026 Security Research
*/

package eval_test

import (
	"fmt"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/eval"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate rule registry
)

// TestCorpusPrecision_Gate is the merge gate per D-31-PRECISION-GATE.
// Failure prints precision/per-status counts so the regression is concrete.
//
// testdata/corpus.json is schema_version 2 (Pass-B relabeled).
// The v1 archive lives at testdata/corpus.v1.json.archive. This test calls
// RunCorpusV2 (the active gate) per D-40 atomic flip.
func TestCorpusPrecision_Gate(t *testing.T) {
	rep, err := eval.RunCorpusV2("testdata/corpus.json")
	if err != nil {
		t.Fatalf("RunCorpusV2: %v", err)
	}
	if rep.Precision < 0.80 {
		t.Errorf("precision gate failed: got %.4f, want >= 0.80\ntotal=%d reviewed=%d accepted=%d edited=%d rejected=%d pending=%d",
			rep.Precision, rep.Total, rep.Reviewed, rep.Accepted, rep.Edited, rep.Rejected, rep.Pending)
	}
	t.Logf("precision=%.4f total=%d reviewed=%d accepted=%d edited=%d rejected=%d pending=%d",
		rep.Precision, rep.Total, rep.Reviewed, rep.Accepted, rep.Edited, rep.Rejected, rep.Pending)
	_ = component.Buckets // keep import live for future per-bucket diagnostics
}

func TestCorpus_NoUnknownBuckets(t *testing.T) {
	// LoadCorpusV2 validates schema; PrecisionV2 errors on unknown review_status.
	if _, err := eval.RunCorpusV2("testdata/corpus.json"); err != nil {
		t.Fatalf("corpus invalid: %v", err)
	}
	_ = fmt.Sprint("")
}
