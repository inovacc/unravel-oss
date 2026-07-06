//go:build linux

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
		"/usr/share",
		"/usr/lib",
		"/opt",
		"/snap",
		"/var/lib/flatpak/app",
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".local", "share"),
			filepath.Join(home, ".local", "lib"),
		)
	}

	return paths
}
