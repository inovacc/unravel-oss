package cmd

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/summaryview"
)

func TestKbSearchSummaryViewContract(t *testing.T) {
	if !summaryview.Prefer("x") || summaryview.Prefer(" ") {
		t.Fatal("summaryview.Prefer contract changed")
	}
	if got := summaryview.Line("s", "r", "t"); !strings.Contains(got, "s") {
		t.Fatalf("summaryview.Line contract changed: %q", got)
	}
}
