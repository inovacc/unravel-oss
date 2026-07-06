/*
Copyright (c) 2026 Security Research
*/

package telemetry

import (
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/manifest"
)

func ScanAPK(dexResult *dex.ParseResult, m *manifest.Manifest) *ScanResult {
	sdks := DetectSDKs(dexResult)
	stealth := DetectStealth(m, dexResult)

	result := &ScanResult{
		SDKs:            sdks,
		StealthFeatures: stealth,
		TotalSDKs:       len(sdks),
		HasAnalytics:    false,
		HasAds:          false,
		HasStealth:      len(stealth) > 0,
	}

	for _, sdk := range sdks {
		switch sdk.Category {
		case CategoryAnalytics:
			result.HasAnalytics = true
		case CategoryAds:
			result.HasAds = true
		}
	}

	return result
}
