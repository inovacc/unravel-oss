/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import "testing"

func TestComputeCostMicroUSD(t *testing.T) {
	tests := []struct {
		name      string
		model     string
		inTokens  int64
		outTokens int64
		want      int64
	}{
		{"sonnet 1k in / 1k out", "sonnet", 1000, 1000, 18_000}, // 3M*1000/1M + 15M*1000/1M = 3000 + 15000 = 18000
		{"haiku 1k in / 1k out", "haiku", 1000, 1000, 4_800},    // 800k*1000/1M + 4M*1000/1M = 800 + 4000 = 4800
		{"opus 1k in / 1k out", "opus", 1000, 1000, 90_000},     // 15M*1000/1M + 75M*1000/1M = 15000 + 75000 = 90000
		{"unknown model returns 0", "claude-15", 1000, 1000, 0},
		{"zero tokens", "sonnet", 0, 0, 0},
		{"large counts don't overflow", "sonnet", 1_000_000, 1_000_000, 18_000_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeCostMicroUSD(tt.model, tt.inTokens, tt.outTokens)
			if got != tt.want {
				t.Errorf("computeCostMicroUSD(%q, %d, %d) = %d, want %d",
					tt.model, tt.inTokens, tt.outTokens, got, tt.want)
			}
		})
	}
}

func TestCostMicroUSD_KnownModel(t *testing.T) {
	// haiku = 800000 in / 4000000 out micro-USD per million tokens.
	// 1_000_000 in + 0 out => 800000 micro-USD.
	got := CostMicroUSD("haiku", 1_000_000, 0)
	if got != 800_000 {
		t.Fatalf("CostMicroUSD(haiku,1e6,0) = %d, want 800000", got)
	}
	// sonnet = 3000000 / 15000000. 1e6 in + 1e6 out => 18_000_000.
	if got := CostMicroUSD("sonnet", 1_000_000, 1_000_000); got != 18_000_000 {
		t.Fatalf("CostMicroUSD(sonnet,1e6,1e6) = %d, want 18000000", got)
	}
}

func TestCostMicroUSD_UnknownModelIsZero(t *testing.T) {
	if got := CostMicroUSD("gpt-9", 5_000_000, 5_000_000); got != 0 {
		t.Fatalf("unknown model cost = %d, want 0", got)
	}
}
