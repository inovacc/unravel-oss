/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import "log/slog"

// modelPriceMicroUSDPerMillionTokens maps a model alias to its (input, output)
// price in micro-USD per million tokens. Refresh manually as Anthropic
// publishes new prices.
//
// As of 2026-05: Sonnet 4.6 = $3 / $15, Haiku 4.5 = $0.80 / $4, Opus 4.7 = $15 / $75.
var modelPriceMicroUSDPerMillionTokens = map[string][2]int64{
	"sonnet": {3_000_000, 15_000_000},
	"haiku":  {800_000, 4_000_000},
	"opus":   {15_000_000, 75_000_000},
}

// computeCostMicroUSD returns the dollar cost of a sampling call in micro-USD.
// Unknown models log a slog.Warn (once per call — caller should de-dup) and
// return 0 rather than guess. Phase G drift metric mean_cost_micro_usd reads
// this via SUM(enrich_attempts.cost_micro_usd).
func computeCostMicroUSD(model string, inputTokens, outputTokens int64) int64 {
	prices, ok := modelPriceMicroUSDPerMillionTokens[model]
	if !ok {
		slog.Warn("unknown model price; cost recorded as 0", "model", model)
		return 0
	}
	return (inputTokens*prices[0] + outputTokens*prices[1]) / 1_000_000
}

// CostMicroUSD is the exported wrapper over computeCostMicroUSD. The
// subscription/plugin path (enrich.record_cost) prices a notional cost via
// this; the daemon path uses computeCostMicroUSD directly. Unknown models
// return 0 (logged once by computeCostMicroUSD).
func CostMicroUSD(model string, inputTokens, outputTokens int64) int64 {
	return computeCostMicroUSD(model, inputTokens, outputTokens)
}
