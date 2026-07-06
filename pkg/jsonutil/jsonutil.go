// Package jsonutil provides shared JSON marshalling helpers with the canonical
// 2-space indent used across unravel's CLI output, knowledge base reports,
// dissect artifacts, and capture pipeline.
package jsonutil

import (
	"encoding/json"
	"fmt"
)

// MarshalIndented returns v marshalled to JSON with the canonical 2-space
// indent. Equivalent to json.MarshalIndent(v, "", "  ").
func MarshalIndented(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// MarshalIndentedString is a convenience returning the indented JSON as a
// string. Returns the marshal error on failure (no string fallback).
func MarshalIndentedString(v any) (string, error) {
	b, err := MarshalIndented(v)
	if err != nil {
		return "", fmt.Errorf("marshal indented: %w", err)
	}
	return string(b), nil
}

// MarshalIndentedNewline returns indented JSON with a trailing newline. Common
// for files written via os.WriteFile so editors/diff tools render cleanly.
func MarshalIndentedNewline(v any) ([]byte, error) {
	b, err := MarshalIndented(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
