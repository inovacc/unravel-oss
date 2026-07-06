/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"context"
	"log/slog"
	"time"
)

// stageTimer starts a pipeline-stage timer and emits an always-on INFO
// "stage start" slog line. It returns a closure that, when invoked, emits a
// matching INFO "stage end" line carrying elapsed_ms plus any end fields.
//
// All output goes through the slog default logger, which the package
// configures to write to stderr only — stdout stays reserved for data
// output. Structured field keys are snake_case. No errors are produced
// (logging only); should any be added later, wrap with %w and use
// errors.Is/errors.As per repo conventions.
func stageTimer(stage, target string, fields ...any) func(end ...any) {
	start := time.Now()

	startAttrs := make([]any, 0, 4+len(fields))
	startAttrs = append(startAttrs, "stage", stage, "target", target)
	startAttrs = append(startAttrs, fields...)
	slog.Info("stage start", startAttrs...)

	return func(end ...any) {
		endAttrs := make([]any, 0, 6+len(end))
		endAttrs = append(endAttrs,
			"stage", stage,
			"target", target,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
		endAttrs = append(endAttrs, end...)
		slog.Info("stage end", endAttrs...)
	}
}

// debugEnabled reports whether the slog default logger would emit at DEBUG
// level, matching the --debug recorder semantics without changing any
// function signatures. Used to gate per-item DEBUG detail.
func debugEnabled(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	return slog.Default().Enabled(ctx, slog.LevelDebug)
}
