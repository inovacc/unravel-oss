/*
Copyright (c) 2026 Security Research
*/
package telemetry

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// HasService checks whether the content contains indicators for the given telemetry service.
func HasService(content string, service manifest.TelemetryService) bool {
	for _, p := range service.Patterns {
		if strings.Contains(strings.ToLower(content), strings.ToLower(p)) {
			return true
		}
	}

	return false
}
