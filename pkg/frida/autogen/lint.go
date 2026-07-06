/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/jsdeob"
)

// lintJS validates generated JS via jsdeob.Lint. The returned error is
// wrapped with the seam id so the caller can identify which seam produced
// invalid output.
func lintJS(seamID string, js []byte) error {
	if err := jsdeob.Lint(string(js)); err != nil {
		return fmt.Errorf("autogen lint seam=%s: %w", seamID, err)
	}
	return nil
}
