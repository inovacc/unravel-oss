//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package gather

import (
	"os"
	"path/filepath"
)

func searchPaths() []string {
	var paths []string

	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		paths = append(paths, programFiles)
	}

	if programFilesX86 := os.Getenv("ProgramFiles(x86)"); programFilesX86 != "" {
		paths = append(paths, programFilesX86)
	}

	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		paths = append(paths, filepath.Join(localAppData, "Programs"))
		// Microsoft Store / MSIX apps
		paths = append(paths, filepath.Join(localAppData, "Microsoft", "WindowsApps"))
		// Packaged app data (MSIX/UWP)
		paths = append(paths, filepath.Join(localAppData, "Packages"))
	}

	if appData := os.Getenv("APPDATA"); appData != "" {
		paths = append(paths, appData)
	}

	// Windows system-wide MSIX/Store installations
	programFilesWA := filepath.Join(os.Getenv("ProgramFiles"), "WindowsApps")
	paths = append(paths, programFilesWA)

	// Scoop, Chocolatey, WinGet installs
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		paths = append(paths, filepath.Join(userProfile, "scoop", "apps"))
	}
	if programData := os.Getenv("ProgramData"); programData != "" {
		paths = append(paths, filepath.Join(programData, "chocolatey", "lib"))
	}

	return paths
}
