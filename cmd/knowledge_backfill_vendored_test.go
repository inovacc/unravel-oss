/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"bytes"
	"reflect"
	"testing"
)

// TestClassifyVendored pins the decision logic of the backfill-vendored
// command: a row is newly marked iff the detector flags it AND it is not
// already marked. The detector is injected so this test is decoupled from
// the heuristics in kbscan.IsVendoredBody (those are covered by
// pkg/knowledge/kb/scanner/scanner_vendored_test.go).
func TestClassifyVendored(t *testing.T) {
	fake := func(_ string, b []byte) bool { return bytes.Contains(b, []byte("VENDOR")) }

	tests := []struct {
		name string
		rows []vendoredRow
		want []int64
	}{
		{
			name: "detected and unmarked are returned",
			rows: []vendoredRow{
				{id: 1, body: []byte("VENDOR lib")},
				{id: 2, body: []byte("app code")},
				{id: 4, body: []byte("more VENDOR here")},
			},
			want: []int64{1, 4},
		},
		{
			name: "already-marked rows are skipped even when detected",
			rows: []vendoredRow{
				{id: 3, alreadyVend: true, body: []byte("VENDOR")},
				{id: 5, body: []byte("VENDOR")},
			},
			want: []int64{5},
		},
		{
			name: "no candidates yields nil",
			rows: []vendoredRow{
				{id: 6, body: []byte("first party")},
				{id: 7, alreadyVend: true, body: []byte("VENDOR")},
			},
			want: nil,
		},
		{
			name: "empty input yields nil",
			rows: nil,
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyVendored(tc.rows, fake)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("classifyVendored() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyUnvendored pins the --reconcile correction set: ids currently
// marked vendored that the detector no longer flags.
func TestClassifyUnvendored(t *testing.T) {
	fake := func(_ string, b []byte) bool { return bytes.Contains(b, []byte("VENDOR")) }

	rows := []vendoredRow{
		{id: 1, alreadyVend: true, body: []byte("app code")},   // marked but not detected -> unmark
		{id: 2, alreadyVend: true, body: []byte("VENDOR lib")}, // marked and still detected -> keep
		{id: 3, alreadyVend: false, body: []byte("app code")},  // not marked -> ignore
		{id: 4, alreadyVend: true, body: []byte("plain")},      // marked but not detected -> unmark
	}
	got := classifyUnvendored(rows, fake)
	want := []int64{1, 4}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("classifyUnvendored() = %v, want %v", got, want)
	}
}
