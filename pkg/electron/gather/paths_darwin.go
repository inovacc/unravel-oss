//go:build darwin

/*
Copyright (c) 2026 Security Research
*/
package gather

import (
	"os"
	"path/filepath"
)

func searchPaths() []string {
	paths := []string{
		"/Applications",
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, "Applications"))
	}

	return paths
}
