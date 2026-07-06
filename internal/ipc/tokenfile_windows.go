//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"fmt"
	"os"
)

// WriteTokenFile writes the token to path. On Windows the containing
// directory (supervisor.DefaultSocketDir under %LOCALAPPDATA%) is already
// user-scoped by NTFS inheritance; 0600 maps to owner read/write.
func WriteTokenFile(path, token string) error {
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return fmt.Errorf("write token file %s: %w", path, err)
	}
	return nil
}
