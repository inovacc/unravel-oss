/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// Finding is a detected IPC command.
type Finding struct {
	Channel   string `json:"channel"`
	Direction string `json:"direction"`
	Risk      string `json:"risk"`
}

// Find searches content for IPC channels matching the given pattern.
func Find(content string, pattern manifest.IPCPattern, dangerous []manifest.DangerousKeyword) []Finding {
	var findings []Finding

	re, err := regexp.Compile(pattern.Pattern)
	if err != nil {
		return findings
	}

	matches := re.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) <= pattern.CaptureGroup {
			continue
		}

		channel := match[pattern.CaptureGroup]
		if seen[channel] {
			continue
		}

		seen[channel] = true

		risk := "LOW"

		channelLower := strings.ToLower(channel)
		for _, d := range dangerous {
			if strings.Contains(channelLower, d.Keyword) {
				risk = d.Risk
				break
			}
		}

		findings = append(findings, Finding{
			Channel:   channel,
			Direction: pattern.Direction,
			Risk:      risk,
		})
	}

	return findings
}
