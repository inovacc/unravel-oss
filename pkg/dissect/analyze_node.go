/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/disasm"
	"github.com/inovacc/unravel-oss/pkg/nodeaddon"
)

func init() {
	RegisterAnalyzer(analyzeNodeAddon, detect.TypeNodeAddon)
}

func analyzeNodeAddon(r *DissectResult, path string, opts Options) {
	r.runStep("nodeaddon info", func(sr *debug.StepRecorder) error {
		res, err := nodeaddon.Analyze(path)
		if err != nil {
			return err
		}

		r.NodeAddonInfo = res

		sr.RecordOutput(res)
		return nil
	})

	r.runStep("cert info", func(sr *debug.StepRecorder) error {
		res, err := cert.ExtractCertificates(path)
		if err != nil {
			return err
		}

		r.CertInfo = res

		sr.RecordOutput(res)
		return nil
	})

	if opts.Disassemble {
		r.runStep("disassemble", func(sr *debug.StepRecorder) error {
			res, err := disasm.Disassemble(path, disasm.Options{})
			if err != nil {
				return err
			}

			r.Disassembly = res

			sr.RecordOutput(res)
			return nil
		})
	}
}
