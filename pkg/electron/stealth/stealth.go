/*
Copyright (c) 2026 Security Research
*/
package stealth

import (
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// Finding is a detected stealth feature.
type Finding struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Risk        string `json:"risk"`
}

// Detect checks content for a stealth pattern and returns a finding if matched.
func Detect(content string, pattern manifest.StealthPattern) *Finding {
	for _, p := range pattern.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			if strings.Contains(content, p) {
				return &Finding{
					Name:        pattern.Name,
					Description: pattern.Description,
					Evidence:    p,
					Risk:        pattern.Risk,
				}
			}

			continue
		}

		loc := re.FindStringIndex(content)
		if loc != nil {
			start := max(loc[0]-30, 0)
			end := min(loc[1]+30, len(content))

			return &Finding{
				Name:        pattern.Name,
				Description: pattern.Description,
				Evidence:    content[start:end],
				Risk:        pattern.Risk,
			}
		}
	}

	return nil
}
