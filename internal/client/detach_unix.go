//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package client

import "syscall"

func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}
