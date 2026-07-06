/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/wasm"
)

func init() {
	RegisterAnalyzer(analyzeWASM, detect.TypeWASM)
}

func analyzeWASM(r *DissectResult, path string, _ Options) {
	r.runStep("wasm info", func(sr *debug.StepRecorder) error {
		res, err := wasm.Parse(path)
		if err != nil {
			return err
		}

		r.WASMInfo = res

		sr.RecordOutput(res)
		return nil
	})
}
