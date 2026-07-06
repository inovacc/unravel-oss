//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package client

import "syscall"

// Windows process-creation flags.
// CREATE_NEW_PROCESS_GROUP prevents Ctrl-C propagation from the parent
// terminal. CREATE_NO_WINDOW suppresses the conhost console window that
// Windows would otherwise allocate for a console-subsystem child.
const (
	createNewProcessGroup = 0x00000200
	createNoWindow        = 0x08000000
)

func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | createNoWindow,
		HideWindow:    true,
	}
}
