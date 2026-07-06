/* Copyright (c) 2026 Security Research */
package telemetry

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestHasService(t *testing.T) {
	tests := []struct {
		name    string
		content string
		service manifest.TelemetryService
		want    bool
	}{
		{
			name:    "case insensitive match",
			content: "connecting to SENTRY.IO for errors",
			service: manifest.TelemetryService{
				Name:     "Sentry",
				Patterns: []string{"sentry.io"},
			},
			want: true,
		},
		{
			name:    "no match",
			content: "no telemetry here",
			service: manifest.TelemetryService{
				Name:     "Sentry",
				Patterns: []string{"sentry.io"},
			},
			want: false,
		},
		{
			name:    "multiple patterns one matches",
			content: "uses analytics.segment.com",
			service: manifest.TelemetryService{
				Name:     "Segment",
				Patterns: []string{"segment.io", "segment.com", "analytics.js"},
			},
			want: true,
		},
		{
			name:    "empty patterns",
			content: "anything",
			service: manifest.TelemetryService{
				Name: "Empty",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasService(tt.content, tt.service); got != tt.want {
				t.Errorf("HasService() = %v, want %v", got, tt.want)
			}
		})
	}
}
