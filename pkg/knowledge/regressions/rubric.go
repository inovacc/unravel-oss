/*
Copyright (c) 2026 Security Research

rubric.go — strict YAML loader for kb-regressions.yaml with size cap and
enum validation. T-07-04 mitigation lives here.
*/
package regressions

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// maxRubricSize bounds an attacker-supplied YAML file (T-07-04).
const maxRubricSize = 1 << 20 // 1 MiB

var (
	validSeverities = map[string]bool{
		SeverityBlock: true,
		SeverityFlag:  true,
		SeverityPass:  true,
	}
	validDimensions = map[string]bool{
		DimPermissions:    true,
		DimSecurityConfig: true,
		DimStructural:     true,
		DimText:           true,
	}
)

// LoadRubric reads the YAML rubric at path, validates it strictly, and
// merges it with the embedded defaults (user rules override defaults by
// ID; new IDs append). When path is empty or missing it returns the
// embedded defaults.
//
// Strict mode: KnownFields(true), 1 MiB size cap, severity and dimension
// enums validated, IDs must be non-empty and unique within the file.
func LoadRubric(path string) ([]Rule, error) {
	if path == "" {
		return DefaultRules(), nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return DefaultRules(), nil
		}
		return nil, fmt.Errorf("stat rubric: %w", err)
	}
	if info.Size() > maxRubricSize {
		return nil, fmt.Errorf("rubric exceeds %d bytes (got %d) — T-07-04", maxRubricSize, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rubric: %w", err)
	}
	user, err := decodeRubric(data)
	if err != nil {
		return nil, fmt.Errorf("decode rubric: %w", err)
	}
	if err := validateRubric(user); err != nil {
		return nil, err
	}

	// Mark provenance.
	for i := range user.Rules {
		user.Rules[i].Source = SourceRubric
	}

	return mergeRules(DefaultRules(), user.Rules), nil
}

// decodeRubric decodes YAML strictly (rejects unknown fields).
func decodeRubric(data []byte) (*Rubric, error) {
	var rub Rubric
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&rub); err != nil {
		return nil, err
	}
	return &rub, nil
}

// validateRubric checks the enum values and ID uniqueness.
func validateRubric(rub *Rubric) error {
	seen := make(map[string]bool, len(rub.Rules))
	for i, r := range rub.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule[%d]: id is empty", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
		if !validSeverities[r.Severity] {
			return fmt.Errorf("rule[%d] %s: invalid severity %q (must be BLOCK|FLAG|PASS)", i, r.ID, r.Severity)
		}
		if !validDimensions[r.Dimension] {
			return fmt.Errorf("rule[%d] %s: invalid dimension %q", i, r.ID, r.Dimension)
		}
	}
	return nil
}

// mergeRules overlays user rules on defaults (override by ID).
func mergeRules(defaults, user []Rule) []Rule {
	out := make([]Rule, 0, len(defaults)+len(user))
	idx := make(map[string]int)
	for _, r := range defaults {
		idx[r.ID] = len(out)
		out = append(out, r)
	}
	for _, r := range user {
		if i, ok := idx[r.ID]; ok {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}
