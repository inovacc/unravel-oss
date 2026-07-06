/*
Copyright (c) 2026 Security Research
*/

package depth

import "testing"

func TestNewDimension(t *testing.T) {
	cases := []struct {
		name      string
		dimName   string
		covered   int
		total     int
		wantRatio float64
		wantName  string
	}{
		{name: "empty_zero_zero", dimName: "manifest", covered: 0, total: 0, wantRatio: 0, wantName: "manifest"},
		{name: "zero_covered_total_five", dimName: "dex_classes", covered: 0, total: 5, wantRatio: 0, wantName: "dex_classes"},
		{name: "partial_three_of_five", dimName: "permissions", covered: 3, total: 5, wantRatio: 0.6, wantName: "permissions"},
		{name: "full_five_of_five", dimName: "native_libs", covered: 5, total: 5, wantRatio: 1.0, wantName: "native_libs"},
		{name: "name_preserved_empty", dimName: "", covered: 1, total: 1, wantRatio: 1.0, wantName: ""},
		{name: "negative_clamped", dimName: "secrets", covered: -3, total: -1, wantRatio: 0, wantName: "secrets"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDimension(tt.dimName, tt.covered, tt.total)
			if d.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", d.Name, tt.wantName)
			}
			if d.Ratio != tt.wantRatio {
				t.Errorf("Ratio = %v, want %v", d.Ratio, tt.wantRatio)
			}
			if d.Covered < 0 || d.Total < 0 {
				t.Errorf("negative not clamped: covered=%d total=%d", d.Covered, d.Total)
			}
		})
	}
}

func TestRatioOK(t *testing.T) {
	cases := []struct {
		name    string
		covered int
		total   int
		want    bool
	}{
		{name: "absent_dimension_zero_zero", covered: 0, total: 0, want: true},
		{name: "loud_failure_total_five_covered_zero", covered: 0, total: 5, want: false},
		{name: "partial_one_of_five", covered: 1, total: 5, want: true},
		{name: "full_five_of_five", covered: 5, total: 5, want: true},
		{name: "programmer_error_zero_total_high_covered", covered: 999, total: 0, want: true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDimension("test", tt.covered, tt.total)
			if got := RatioOK(d); got != tt.want {
				t.Errorf("RatioOK(covered=%d, total=%d) = %v, want %v",
					tt.covered, tt.total, got, tt.want)
			}
		})
	}
}
