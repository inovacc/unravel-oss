package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const envKBStore = "UNRAVEL_KB_STORE"

// KBStoreRoot resolves the kb-store root.
//
// Resolution order:
//  1. $UNRAVEL_KB_STORE if set; must be an absolute path.
//  2. $LOCALAPPDATA/Unravel/kb-store if set (Windows default).
//  3. Otherwise <user-home>/unravel/kb-store/.
//
// A relative override is rejected with an explicit error so that misconfigured
// callers do not write KB artifacts under the current working directory.
func KBStoreRoot() (string, error) {
	if v := os.Getenv(envKBStore); v != "" {
		if !filepath.IsAbs(v) {
			return "", errors.New("UNRAVEL_KB_STORE must be absolute path")
		}
		return v, nil
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "Unravel", "kb-store"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, "unravel", "kb-store"), nil
}
