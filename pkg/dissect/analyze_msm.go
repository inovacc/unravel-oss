/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/msm"
)

func init() {
	RegisterAnalyzer(analyzeMSM, detect.TypeMSM)
}

// analyzeMSM parses a Windows Installer Merge Module (.msm), surfacing its
// merge-module metadata, component/file listing, driver payloads, and embedded
// cabinet streams. Non-fatal errors are recorded on the step (and thus on
// result.Errors) so the pipeline never blocks.
func analyzeMSM(r *DissectResult, path string, _ Options) {
	r.runStep("msm info", func(sr *debug.StepRecorder) error {
		res, err := msm.Info(path)
		if err != nil {
			return err
		}

		r.MSMInfo = res

		sr.RecordOutput(res)
		return nil
	})
}
