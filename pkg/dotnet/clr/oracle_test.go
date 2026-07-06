//go:build oracle

/*
Copyright (c) 2026 Security Research
*/
package clr_test

import (
	"os"
	"sort"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata"
)

// Env contract (set by task test:oracle / CI-local only):
//
//	UNRAVEL_ORACLE_ASMS  = comma-separated absolute paths to .dll oracles
//	                       (LinkedIn.dll, TrackingLib.dll, a System.* dll)
//	UNRAVEL_ORACLE_ILSPY = path to ilspycmd 8.2 (DOTNET_ROLL_FORWARD=Major)
func TestOracle_AssemblyRefParity(t *testing.T) {
	asms := oracleAssemblies(t)
	ilspy := requireILSpy(t)

	for _, path := range asms {
		t.Run(filepathBase(path), func(t *testing.T) {
			img, err := clr.Open(path)
			if err != nil {
				t.Fatalf("clr.Open(%s): %v", path, err)
			}
			tbls, _, err := metadata.Parse(img.Metadata())
			if err != nil {
				t.Fatalf("metadata.Parse: %v", err)
			}

			var got []string
			for _, r := range tbls.AssemblyRefs() {
				got = append(got, r.Name)
			}
			sort.Strings(got)

			want := ilspyAssemblyRefs(t, ilspy, path) // sorted
			if !equalStrings(got, want) {
				t.Fatalf("AssemblyRef set mismatch\n got=%v\nwant=%v", got, want)
			}
		})
	}
}

func oracleAssemblies(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("UNRAVEL_ORACLE_ASMS")
	if v == "" {
		t.Skip("UNRAVEL_ORACLE_ASMS unset — oracle tier skipped")
	}
	return splitComma(v)
}

func requireILSpy(t *testing.T) string {
	t.Helper()
	p := os.Getenv("UNRAVEL_ORACLE_ILSPY")
	if p == "" {
		t.Skip("UNRAVEL_ORACLE_ILSPY unset — oracle tier skipped")
	}
	return p
}
