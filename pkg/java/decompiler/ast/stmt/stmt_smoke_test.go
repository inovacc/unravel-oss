/*
Copyright (c) 2026 Security Research
*/
package stmt

import "testing"

func TestStmtConstructors(t *testing.T) {
	if NewNop() == nil {
		t.Error("NewNop nil")
	}
	if NewReturnVoid() == nil {
		t.Error("NewReturnVoid nil")
	}
	if NewReturn(nil) == nil {
		t.Error("NewReturn nil")
	}
	if NewThrow(nil) == nil {
		t.Error("NewThrow nil")
	}
	if NewGoto(0) == nil {
		t.Error("NewGoto nil")
	}
	if NewIf(nil, 0) == nil {
		t.Error("NewIf nil")
	}
	if NewExpressionStatement(nil) == nil {
		t.Error("NewExpressionStatement nil")
	}
	if NewAssignment(nil, nil) == nil {
		t.Error("NewAssignment nil")
	}
}
