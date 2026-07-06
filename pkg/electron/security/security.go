/*
Copyright (c) 2026 Security Research
*/
package security

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// Finding is a single security configuration finding.
type Finding struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
}

// Check examines content for a security setting and returns a finding if matched.
func Check(content string, setting manifest.SecuritySetting) *Finding {
	for _, pattern := range setting.SearchPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			value := matches[1]

			risk := "LOW"
			if value == setting.InsecureValue {
				risk = setting.RiskIfInsecure
			}

			return &Finding{
				Name:        setting.Name,
				Value:       value,
				Risk:        risk,
				Description: setting.Description,
			}
		}
	}

	return nil
}
