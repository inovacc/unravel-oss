/*
Copyright (c) 2026 Security Research
*/
package clrgen_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/internal/clrgen"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata"
)

func TestPtrIndirected_Rejected(t *testing.T) {
	b := clrgen.PtrIndirected()
	img, err := clr.OpenReaderAt(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _, err = metadata.Parse(img.Metadata())
	if !errors.Is(err, metadata.ErrIndirectionTablesUnsupported) {
		t.Fatalf("Parse on *Ptr fixture = %v, want ErrIndirectionTablesUnsupported", err)
	}
}
