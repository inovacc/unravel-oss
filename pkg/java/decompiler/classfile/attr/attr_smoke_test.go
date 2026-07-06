/*
Copyright (c) 2026 Security Research
*/
package attr

import "testing"

func TestNewMap(t *testing.T) {
	m := NewMap()
	if m == nil {
		t.Fatal("NewMap returned nil")
	}
}
