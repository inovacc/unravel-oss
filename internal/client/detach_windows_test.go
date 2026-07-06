//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package client

import (
	"testing"
)

func TestDetachAttr_Windows(t *testing.T) {
	tests := []struct {
		name                 string
		wantHideWindow       bool
		wantCreationFlagsAnd uint32 // flags that must ALL be set
	}{
		{
			name:                 "returns non-nil SysProcAttr with correct flags",
			wantHideWindow:       true,
			wantCreationFlagsAnd: createNewProcessGroup | createNoWindow,
		},
		{
			name:                 "CREATE_NEW_PROCESS_GROUP bit is set",
			wantHideWindow:       true,
			wantCreationFlagsAnd: createNewProcessGroup,
		},
		{
			name:                 "CREATE_NO_WINDOW bit is set",
			wantHideWindow:       true,
			wantCreationFlagsAnd: createNoWindow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attr := detachAttr()
			if attr == nil {
				t.Fatal("detachAttr() returned nil, want non-nil *syscall.SysProcAttr")
			}
			if attr.HideWindow != tc.wantHideWindow {
				t.Errorf("HideWindow = %v, want %v", attr.HideWindow, tc.wantHideWindow)
			}
			if attr.CreationFlags&tc.wantCreationFlagsAnd != tc.wantCreationFlagsAnd {
				t.Errorf("CreationFlags = 0x%08x, missing expected bits 0x%08x",
					attr.CreationFlags, tc.wantCreationFlagsAnd)
			}
		})
	}
}

func TestDetachAttr_Windows_FlagValues(t *testing.T) {
	tests := []struct {
		name  string
		flag  uint32
		value uint32
	}{
		{"createNewProcessGroup value", createNewProcessGroup, 0x00000200},
		{"createNoWindow value", createNoWindow, 0x08000000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.flag != tc.value {
				t.Errorf("flag = 0x%08x, want 0x%08x", tc.flag, tc.value)
			}
		})
	}
}
