/*
Copyright (c) 2026 Security Research
*/
package ast

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

func TestArrayConstructors(t *testing.T) {
	intType, err := types.ParseFieldDescriptor("I")
	if err != nil {
		t.Fatalf("parse I: %v", err)
	}
	if NewArrayLength(nil) == nil {
		t.Error("NewArrayLength nil")
	}
	if NewNewArray(intType, nil) == nil {
		t.Error("NewNewArray nil")
	}
	if NewNewObjectArray(intType, nil) == nil {
		t.Error("NewNewObjectArray nil")
	}
	if NewMultiNewArray(intType, nil) == nil {
		t.Error("NewMultiNewArray nil")
	}
	if NewArrayAccess(nil, nil, intType) == nil {
		t.Error("NewArrayAccess nil")
	}
}
