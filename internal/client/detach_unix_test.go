//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package client

import (
	"testing"
)

func TestDetachAttr_Unix(t *testing.T) {
	tests := []struct {
		name        string
		wantSetpgid bool
	}{
		{
			name:        "returns non-nil SysProcAttr",
			wantSetpgid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attr := detachAttr()
			if attr == nil {
				t.Fatal("detachAttr() returned nil, want non-nil *syscall.SysProcAttr")
			}
			if attr.Setpgid != tc.wantSetpgid {
				t.Errorf("Setpgid = %v, want %v", attr.Setpgid, tc.wantSetpgid)
			}
		})
	}
}
