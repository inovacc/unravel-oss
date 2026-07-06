/*
Copyright (c) 2026 Security Research

Package risk implements the UWP capability-scoring rubric (D-10/D-11/D-12/D-13)
and the signature multiplier (via pkg/cert).
*/
package risk

import (
	"errors"
	"io/fs"
	"maps"
	"strings"

	"github.com/inovacc/unravel-oss/manifests"
	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// normalizeNamespace folds vendor namespace URIs back onto canonical short
// codes (BUG-05 / D-05). When the AppxManifest parser hands us a raw URI it
// has prefixed with "unknown:", strip the prefix and re-test. Currently
// recognises the Windows10/11 (uap6) and Windows10/10 (uap5) URIs.
func normalizeNamespace(raw string) string {
	switch {
	case strings.Contains(raw, "appx/manifest/uap/windows10/11"):
		return "uap6"
	case strings.Contains(raw, "appx/manifest/uap/windows10/10"):
		return "uap5"
	case strings.HasPrefix(raw, "unknown:"):
		return normalizeNamespace(strings.TrimPrefix(raw, "unknown:"))
	}
	return raw
}

// DefaultWeights returns the Go-baked per-capability weight table. These
// anchors mirror the RESEARCH.md scoring table and manifests/capabilities.yaml
// so the binary works out of the box (D-11). Security reviewers MUST audit
// changes to this table.
func DefaultWeights() map[string]int {
	return map[string]int{
		// Foundation
		"internetClient":             40,
		"internetClientServer":       60,
		"privateNetworkClientServer": 60,
		"documentsLibrary":           100,
		"picturesLibrary":            100,
		"videosLibrary":              15,
		"musicLibrary":               15,
		"removableStorage":           40,
		"enterpriseAuthentication":   100,
		"sharedUserCertificates":     50,
		"appointments":               20,
		"contacts":                   20,
		"phoneCall":                  45,
		"voipCall":                   45,
		"objects3D":                  10,
		"recordedCallsFolder":        15,
		"chat":                       15,

		// uap*
		"userDataSystem":           75,
		"userAccountInformation":   20,
		"phoneCallHistorySystem":   45,
		"spatialPerception":        50,
		"userDataAccountsProvider": 50,
		"backgroundMediaPlayback":  25,
		"walletSystem":             60,
		"cellularDeviceIdentity":   50,
		"screenCapture":            75,
		"cellularData":             40,
		"globalMediaControl":       50,
		"storeLicenseManagement":   50,
		"oneProcessVoIP":           40,
		"packagedServices":         50,

		// Hardware / IO
		"webcam":          70,
		"microphone":      70,
		"location":        70,
		"bluetooth":       40,
		"wifiControl":     50,
		"radios":          40,
		"proximity":       40,
		"lowLevelDevices": 50,

		// rescap (auto-critical via namespace; weight kept for trace)
		"runFullTrust":           100,
		"allowElevation":         100,
		"broadFileSystemAccess":  100,
		"confirmAppClose":        100,
		"inputObservation":       100,
		"inputInjectionBrokered": 100,
		"packageManagement":      100,
		"packagePolicySystem":    100,
		"unvirtualizedResources": 100,

		// uap6 — silent screen-capture family (BUG-05 / D-05).
		// graphicsCaptureWithoutBorder is the highest-risk member: it
		// suppresses the OS-rendered yellow border that normally signals
		// active capture, leaving no UI consent indicator.
		"graphicsCapture":              60,
		"graphicsCaptureProgrammatic":  80,
		"graphicsCaptureWithoutBorder": 90,

		// device namespace caps not previously listed (BUG-05 / D-05).
		"wiFiControl":          40,
		"usb":                  50,
		"humaninterfacedevice": 30,
	}
}

// DefaultLevelOverrides returns per-capability minimum-level pins
// (BUG-05 / D-05). When any of these capabilities is present, the final
// Score.Level is promoted upward to at least the listed level — never
// downgraded. This guarantees that silent screen-capture caps stay critical
// even when the trusted-microsoft multiplier (0.8) drags the numeric score
// below the critical bucket.
func DefaultLevelOverrides() map[string]string {
	return map[string]string{
		// uap6 graphicsCapture family
		"graphicsCapture":              "high",
		"graphicsCaptureProgrammatic":  "critical",
		"graphicsCaptureWithoutBorder": "critical",

		// device caps with privacy/network impact
		"wiFiControl":          "medium",
		"usb":                  "medium",
		"humaninterfacedevice": "low",
		"bluetooth":            "low",
		"radios":               "low",
		"webcam":               "high",
		"microphone":           "high",
		"location":             "high",

		// uap voip / phone
		"voipCall":  "medium",
		"phoneCall": "medium",

		// foundation network caps that benefit from a floor
		"internetClientServer":       "medium",
		"privateNetworkClientServer": "medium",
	}
}

// DefaultRubric returns the full Go-baked rubric — used when no YAML override
// is loaded.
func DefaultRubric() *uwp.Rubric {
	return &uwp.Rubric{
		Weights:                DefaultWeights(),
		LevelOverrides:         DefaultLevelOverrides(),
		AutoCriticalNamespaces: []string{"rescap"},
		AutoCriticalNames:      nil,
		UnknownCapBucket:       "high",
		UnknownCapWeight:       50,
		SignatureMultipliers: map[string]float64{
			"unsigned":          2.0,
			"invalid":           2.0,
			"self-signed":       1.5,
			"trusted-other":     1.0,
			"trusted-microsoft": 0.8,
		},
		TrustedMicrosoftMaxLevel: "high",
		Buckets: []uwp.Bucket{
			{Name: "low", Max: 25},
			{Name: "medium", Max: 50},
			{Name: "high", Max: 75},
			{Name: "critical", Max: 100},
		},
	}
}

// LoadRubric reads the YAML rubric at path, merges it with the Go defaults
// (config takes precedence), and returns the resolved *uwp.Rubric. When the
// file is absent it returns (nil, fs.ErrNotExist) so callers can fall back to
// DefaultRubric() explicitly.
func LoadRubric(path string) (*uwp.Rubric, error) {
	cfg, err := manifests.LoadCapabilities(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}

	rub := DefaultRubric()

	// Weights: override per-key (do not wipe defaults).
	maps.Copy(rub.Weights, cfg.Weights)

	if len(cfg.AutoCriticalNamespaces) > 0 {
		rub.AutoCriticalNamespaces = cfg.AutoCriticalNamespaces
	}
	if len(cfg.AutoCriticalNames) > 0 {
		rub.AutoCriticalNames = cfg.AutoCriticalNames
	}
	if cfg.UnknownCapability.Bucket != "" {
		rub.UnknownCapBucket = cfg.UnknownCapability.Bucket
	}
	if cfg.UnknownCapability.Weight != 0 {
		rub.UnknownCapWeight = cfg.UnknownCapability.Weight
	}
	if len(cfg.SignatureMultipliers) > 0 {
		rub.SignatureMultipliers = cfg.SignatureMultipliers
	}
	if cfg.TrustedMicrosoftMaxLevel != "" {
		rub.TrustedMicrosoftMaxLevel = cfg.TrustedMicrosoftMaxLevel
	}
	if len(cfg.Buckets) > 0 {
		rub.Buckets = make([]uwp.Bucket, 0, len(cfg.Buckets))
		for _, b := range cfg.Buckets {
			rub.Buckets = append(rub.Buckets, uwp.Bucket{Name: b.Name, Max: b.Max})
		}
	}

	return rub, nil
}
