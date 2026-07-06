/*
Copyright (c) 2026 Security Research
*/
package components

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// maxOverrideBytes caps the override file size to limit YAML parser exposure
// (T-07-04). Files above this threshold are rejected before unmarshal.
const maxOverrideBytes int64 = 1 << 20 // 1 MiB

// LoadOverride reads a `<kb>/components.override.yaml`-style mapping of
// source-relative path to bucket name and returns a parsed map. A missing file
// returns (nil, nil); an oversized file or unknown bucket value returns an
// error.
func LoadOverride(path string) (map[string]Bucket, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat override: %w", err)
	}
	if info.Size() > maxOverrideBytes {
		return nil, fmt.Errorf("override file %q exceeds %d bytes (got %d)", path, maxOverrideBytes, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read override: %w", err)
	}
	raw := make(map[string]string)
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode override: %w", err)
	}
	out := make(map[string]Bucket, len(raw))
	for k, v := range raw {
		b := Bucket(v)
		if !IsValidBucket(b) {
			return nil, fmt.Errorf("override %q: unknown bucket %q", k, v)
		}
		out[k] = b
	}
	return out, nil
}
