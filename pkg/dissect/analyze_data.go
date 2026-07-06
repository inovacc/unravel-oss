/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/ios"
	"github.com/inovacc/unravel-oss/pkg/leveldb"
)

func init() {
	RegisterAnalyzer(analyzeLevelDB, detect.TypeLevelDB)
	RegisterAnalyzer(analyzeChromiumCache, detect.TypeChromiumCache)
	RegisterAnalyzer(analyzeIPA, detect.TypeIPA)
}

func analyzeLevelDB(r *DissectResult, path string, opts Options) {
	r.runStep("leveldb parse", func(sr *debug.StepRecorder) error {
		res, err := leveldb.ParseDirectory(path)
		if err != nil {
			return err
		}

		r.LevelDB = res

		sr.RecordOutput(res)
		return nil
	})
}

func analyzeChromiumCache(r *DissectResult, path string, opts Options) {
	r.runStep("cache parse", func(sr *debug.StepRecorder) error {
		res, err := cache.Parse(path, "")
		if err != nil {
			return err
		}

		r.Cache = res

		sr.RecordOutput(res)
		return nil
	})
}

func analyzeIPA(r *DissectResult, path string, opts Options) {
	r.runStep("ipa info", func(sr *debug.StepRecorder) error {
		info, err := ios.Info(path)
		if err != nil {
			return err
		}
		r.IPAInfo = info
		sr.RecordOutput(info)
		return nil
	})
	if opts.OutputDir != "" {
		r.runStep("ipa extract", func(sr *debug.StepRecorder) error {
			result, err := ios.Extract(path, filepath.Join(opts.OutputDir, "ipa"))
			if err != nil {
				return err
			}
			sr.RecordOutput(result)
			return nil
		})
	}
}
