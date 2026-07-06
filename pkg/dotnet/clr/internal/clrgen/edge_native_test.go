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

func TestNativeBody_FlaggedNotParsed(t *testing.T) {
	b := clrgen.NativeBody()
	img, err := clr.OpenReaderAt(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	body, err := il.ReadMethodBody(img.ReaderAt(), img.RVAToOffset, clrgen.NativeMethodRVA, clrgen.NativeImplFlags)
	if err != nil {
		t.Fatalf("ReadMethodBody: %v", err)
	}
	if !body.IsNative {
		t.Fatalf("native method: IsNative = false, want true")
	}
	if len(body.Code) != 0 {
		t.Fatalf("native method: Code len = %d, want 0 (no IL parse)", len(body.Code))
	}
}
