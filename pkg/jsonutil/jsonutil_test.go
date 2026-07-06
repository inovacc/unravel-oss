package jsonutil

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalIndented(t *testing.T) {
	type sample struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	got, err := MarshalIndented(sample{Name: "x", Count: 1})
	if err != nil {
		t.Fatalf("MarshalIndented: %v", err)
	}
	want, _ := json.MarshalIndent(sample{Name: "x", Count: 1}, "", "  ")
	if string(got) != string(want) {
		t.Errorf("MarshalIndented output diverges from json.MarshalIndent canonical form")
	}
	if !strings.Contains(string(got), "\n  \"name\"") {
		t.Errorf("expected 2-space indent before \"name\" key, got %q", string(got))
	}
}

func TestMarshalIndentedString(t *testing.T) {
	s, err := MarshalIndentedString(map[string]int{"a": 1})
	if err != nil {
		t.Fatalf("MarshalIndentedString: %v", err)
	}
	if !strings.Contains(s, "\"a\": 1") {
		t.Errorf("expected \"a\": 1 in output, got %q", s)
	}
}

func TestMarshalIndentedNewline(t *testing.T) {
	b, err := MarshalIndentedNewline(map[string]int{"a": 1})
	if err != nil {
		t.Fatalf("MarshalIndentedNewline: %v", err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Errorf("expected trailing newline, got %q", string(b))
	}
}

func TestMarshalIndented_ErrorPropagation(t *testing.T) {
	// Channels can't be marshalled — ensure error surfaces.
	_, err := MarshalIndentedString(make(chan int))
	if err == nil {
		t.Error("expected error marshalling channel, got nil")
	}
}
