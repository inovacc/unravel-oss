/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"github.com/inovacc/unravel-oss/pkg/forensic"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

// init wires the dependency-enrichment CWE sink (pkg/knowledge.WriteEnrichedDeps)
// into pkg/forensic.RegisterCWE so Phase 10 forensic reports auto-pick up
// dep-derived CWEs (D-07). pkg/knowledge cannot import pkg/forensic
// directly because pkg/forensic.regression.go imports pkg/knowledge for
// Diff — installing the registrar here breaks the cycle.
func init() {
	knowledge.SetCWERegistrar(forensic.RegisterCWE)
}
