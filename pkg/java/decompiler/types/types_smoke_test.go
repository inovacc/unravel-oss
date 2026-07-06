/*
Copyright (c) 2026 Security Research

types_smoke_test.go — pure-Go smoke for descriptor parsing + java-rendering.
No classfiles needed; descriptors are tiny strings.
*/
package types

import (
	"strings"
	"testing"
)

func TestParseFieldDescriptor_Primitives(t *testing.T) {
	cases := map[string]string{
		"I": "int", "J": "long", "Z": "boolean", "B": "byte",
		"C": "char", "S": "short", "F": "float", "D": "double",
	}
	for desc, want := range cases {
		t.Run(desc, func(t *testing.T) {
			jt, err := ParseFieldDescriptor(desc)
			if err != nil {
				t.Fatalf("parse %q: %v", desc, err)
			}
			got := DescriptorToJava(desc)
			if got != want {
				t.Errorf("descriptor %q -> %q, want %q (jt=%v)", desc, got, want, jt)
			}
		})
	}
}

func TestParseFieldDescriptor_Reference(t *testing.T) {
	jt, err := ParseFieldDescriptor("Ljava/lang/String;")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if jt == nil {
		t.Fatal("nil JavaType")
	}
}

func TestParseFieldDescriptor_Array(t *testing.T) {
	jt, err := ParseFieldDescriptor("[I")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if jt == nil {
		t.Fatal("nil JavaType")
	}
}

func TestParseFieldDescriptor_Invalid(t *testing.T) {
	if _, err := ParseFieldDescriptor(""); err == nil {
		t.Error("expected error on empty descriptor")
	}
	if _, err := ParseFieldDescriptor("X"); err == nil {
		t.Error("expected error on unknown tag X")
	}
}

func TestParseMethodDescriptor(t *testing.T) {
	params, ret, err := ParseMethodDescriptor("(ILjava/lang/String;)V")
	if err != nil {
		t.Fatalf("parse method: %v", err)
	}
	if len(params) != 2 {
		t.Errorf("params: got %d want 2", len(params))
	}
	if ret == nil {
		t.Error("nil return type")
	}
}

func TestParseMethodDescriptor_Invalid(t *testing.T) {
	if _, _, err := ParseMethodDescriptor(""); err == nil {
		t.Error("expected error on empty")
	}
	if _, _, err := ParseMethodDescriptor("missingparens"); err == nil {
		t.Error("expected error on missing parens")
	}
}

func TestCountMethodParams(t *testing.T) {
	count, slots := CountMethodParams("(IJD)V")
	if count != 3 {
		t.Errorf("count: got %d want 3", count)
	}
	// J + D are 2-slot, I is 1-slot.
	if slots < 3 {
		t.Errorf("slots: got %d, want >= 3", slots)
	}
}

func TestMethodDescriptorToJava(t *testing.T) {
	got := MethodDescriptorToJava("toString", "()Ljava/lang/String;")
	if !strings.Contains(got, "toString") {
		t.Errorf("rendering: %q must contain method name", got)
	}
}

func TestGenericTypeWildcards(t *testing.T) {
	w := NewWildcard()
	if w == nil {
		t.Fatal("NewWildcard nil")
	}
	we := NewWildcardExtends(w)
	if we == nil {
		t.Fatal("NewWildcardExtends nil")
	}
	gt := NewGenericType(w)
	if gt == nil {
		t.Fatal("NewGenericType nil")
	}
}
