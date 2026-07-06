/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import "testing"

func TestSplitTokens90_10(t *testing.T) {
	cases := []struct {
		total           int64
		wantIn, wantOut int64
	}{
		{0, 0, 0},
		{100, 90, 10},
		{1000, 900, 100},
		{7, 6, 1}, // floor(0.9*7)=6 -> in=6, out=7-6=1
	}
	for _, c := range cases {
		in, out := SplitTokens90_10(c.total)
		if in+out != c.total {
			t.Errorf("SplitTokens90_10(%d): in+out=%d, must equal total", c.total, in+out)
		}
		if in != c.wantIn || out != c.wantOut {
			t.Errorf("SplitTokens90_10(%d) = (%d,%d), want (%d,%d)", c.total, in, out, c.wantIn, c.wantOut)
		}
	}
	// Exact 90/10 on a round number.
	in, out := SplitTokens90_10(1000)
	if in != 900 || out != 100 {
		t.Fatalf("SplitTokens90_10(1000) = (%d,%d), want (900,100)", in, out)
	}
	// Negative input is clamped to zero.
	if in, out := SplitTokens90_10(-5); in != 0 || out != 0 {
		t.Fatalf("SplitTokens90_10(-5) = (%d,%d), want (0,0)", in, out)
	}
}
