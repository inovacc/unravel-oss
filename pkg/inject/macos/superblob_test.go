/*
Copyright (c) 2026 Security Research
*/
package macos

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestParseSuperBlob_Hardened(t *testing.T) {
	t.Parallel()
	flags := uint32(FlagHardenedRuntime | FlagLibraryValidation)
	got, err := ParseSuperBlob(buildSuperBlob(flags))
	if err != nil {
		t.Fatalf("ParseSuperBlob: %v", err)
	}
	if !got.Has(FlagHardenedRuntime) || !got.Has(FlagLibraryValidation) {
		t.Errorf("flags=%#x missing expected bits", uint32(got))
	}
}

func TestParseSuperBlob_Bare(t *testing.T) {
	t.Parallel()
	got, err := ParseSuperBlob(buildSuperBlob(0))
	if err != nil {
		t.Fatalf("ParseSuperBlob: %v", err)
	}
	if got.Has(FlagHardenedRuntime) || got.Has(FlagLibraryValidation) {
		t.Errorf("expected zero flags, got %#x", uint32(got))
	}
	if blocks := SigningBlockStrings(got); len(blocks) != 0 {
		t.Errorf("SigningBlockStrings = %v, want empty", blocks)
	}
}

func TestParseSuperBlob_BadMagic(t *testing.T) {
	t.Parallel()
	bad := buildSuperBlob(0)
	bad[0] = 0xff // corrupt magic
	if _, err := ParseSuperBlob(bad); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSigningBlockStrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		flags uint32
		want  []string
	}{
		{"none", 0, nil},
		{"hardened", FlagHardenedRuntime, []string{"hardened-runtime"}},
		{"libval", FlagLibraryValidation, []string{"library-validation"}},
		{"both", FlagHardenedRuntime | FlagLibraryValidation, []string{"hardened-runtime", "library-validation"}},
	}
	for _, tc := range cases {
		got := SigningBlockStrings(SignatureFlags(tc.flags))
		if len(got) != len(tc.want) {
			t.Errorf("%s: got=%v want=%v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s[%d]: got=%q want=%q", tc.name, i, got[i], tc.want[i])
			}
		}
	}
}

func TestDowngradeConfidence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want inject.Confidence
	}{
		{inject.ConfidenceHigh, inject.ConfidenceMedium},
		{inject.ConfidenceMedium, inject.ConfidenceLow},
		{inject.ConfidenceLow, inject.ConfidenceLow},
	}
	for _, tc := range cases {
		if got := DowngradeConfidence(tc.in); got != tc.want {
			t.Errorf("DowngradeConfidence(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
