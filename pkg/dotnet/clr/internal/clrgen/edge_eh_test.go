/*
Copyright (c) 2026 Security Research
*/
package clrgen_test

import (
	"bytes"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/il"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/internal/clrgen"
)

func TestMultiSectionEH_AllClauses(t *testing.T) {
	b := clrgen.MultiSectionEH()
	img, err := clr.OpenReaderAt(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	body, err := il.ReadMethodBody(img.ReaderAt(), img.RVAToOffset, clrgen.EHMethodRVA, 0)
	if err != nil {
		t.Fatalf("ReadMethodBody: %v", err)
	}
	if len(body.EH) != clrgen.EHClauseCount {
		t.Fatalf("EH clause count = %d, want %d", len(body.EH), clrgen.EHClauseCount)
	}
	// Second clause's handler offset proves we followed the chained section.
	if body.EH[1].HandlerOffset != clrgen.EHSecondHandlerOffset {
		t.Fatalf("clause[1].HandlerOffset = %#x, want %#x", body.EH[1].HandlerOffset, clrgen.EHSecondHandlerOffset)
	}
}
