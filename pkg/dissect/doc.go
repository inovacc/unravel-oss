/*
Copyright (c) 2026 Security Research
*/

// Package dissect provides automated multi-analysis orchestration for the unravel toolkit.
//
// Given a file path, it detects the file type and automatically runs all applicable
// non-destructive analyses, producing an aggregated result. This enables a single-command
// deep analysis workflow: detect -> dispatch -> aggregate.
//
// Entry points:
//   - Run: detect file type and run all applicable analyses
//   - GenerateMarkdownReport: write a Markdown report from results
package dissect
