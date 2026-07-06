/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"encoding/json"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/inject"
)

// autogenMeta is the FRIDA-GEN-01 metadata bundle (D-15). It is encoded as
// JSON inside the leading hook's Description field so that the on-disk
// criteria.json stays a pure frida.CriteriaFile and round-trips through
// `unravel_frida_validate` (which uses DisallowUnknownFields).
type autogenMeta struct {
	SeamID         string   `json:"seam_id"`
	Platform       string   `json:"platform"`
	TargetPath     string   `json:"target_path"`
	Tag            string   `json:"tag"`
	ExpectedEvents []string `json:"expected_events"`
	PreAttachCheck string   `json:"pre_attach_check,omitempty"`
	Severity       string   `json:"severity"`
}

// renderCriteria builds the criteria.json sidecar for a seam. The on-disk
// file is exactly `frida.CriteriaFile` shape (schema_version + script +
// hooks); FRIDA-GEN-01 metadata (D-15) is embedded as JSON in the lead
// hook's Description so the file round-trips through `frida.Validate`
// (which rejects unknown top-level fields).
func renderCriteria(s inject.Seam, platform, id string) ([]byte, error) {
	path, tag := extractTargetPathTag(s)
	sev := string(s.Confidence)
	if sev == "" {
		sev = "low"
	}
	events := []string{"hook_loaded"}
	var pre string
	switch platform {
	case "linux":
		events = append([]string{"preflight_failed"}, events...)
		pre = "ptrace_scope <= 1 (host kernel.yama.ptrace_scope policy)"
	case "macos":
		events = append(events, "dlopen_intercepted")
	}
	hookID := fmt.Sprintf("%s-%s", platform, id)
	scriptName := fmt.Sprintf("%s-%s-%s.js", platShort(platform), sanitizeTag(tag), id)

	meta := autogenMeta{
		SeamID:         id,
		Platform:       platform,
		TargetPath:     path,
		Tag:            tag,
		ExpectedEvents: events,
		PreAttachCheck: pre,
		Severity:       sev,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal meta: %w", err)
	}

	cf := frida.CriteriaFile{
		SchemaVersion: 1,
		Script:        scriptName,
		Hooks: []frida.HookCriteria{
			{
				ID:          hookID,
				Description: "unravel-autogen-v1: " + string(metaJSON),
				Criteria: []frida.Criterion{
					{Op: "present", Target: "seam_id"},
				},
			},
		},
	}
	return json.MarshalIndent(cf, "", "  ")
}
