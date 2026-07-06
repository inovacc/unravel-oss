/*
Copyright (c) 2026 Security Research
*/

package udf

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// EnumerateProfiles lists Chromium profiles contained in an EBWebView
// directory (D-10, pitfall 3). Recognized names:
//   - "Default"
//   - "Guest Profile"
//   - "System Profile"
//   - "Profile N" where N is a positive integer
//
// Other directories (and files) are skipped. When ebWebViewDir does not exist
// the function returns (nil, nil). Other read errors are wrapped.
// Output order: Default first, then Profile N ascending, then Guest, System.
func EnumerateProfiles(ebWebViewDir string) ([]ProfileInfo, error) {
	entries, err := os.ReadDir(ebWebViewDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("enumerate profiles: %w", err)
	}

	var profiles []ProfileInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !isProfileDirName(name) {
			continue
		}
		profiles = append(profiles, ProfileInfo{
			Name: name,
			Path: filepath.Join(ebWebViewDir, name),
		})
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		return profileRank(profiles[i].Name) < profileRank(profiles[j].Name)
	})
	return profiles, nil
}

// isProfileDirName reports whether name is a recognized Chromium profile dir.
func isProfileDirName(name string) bool {
	switch name {
	case DefaultProfileDir, GuestProfileDir, SystemProfileDir:
		return true
	}
	if strings.HasPrefix(name, ProfileNumberedPrefix) {
		suffix := strings.TrimPrefix(name, ProfileNumberedPrefix)
		n, err := strconv.Atoi(suffix)
		if err == nil && n > 0 {
			return true
		}
	}
	return false
}

// profileRank returns a sort key that orders Default < Profile N (by N) <
// Guest < System for stable output.
func profileRank(name string) int {
	switch name {
	case DefaultProfileDir:
		return 0
	case GuestProfileDir:
		return 1_000_001
	case SystemProfileDir:
		return 1_000_002
	}
	if strings.HasPrefix(name, ProfileNumberedPrefix) {
		n, err := strconv.Atoi(strings.TrimPrefix(name, ProfileNumberedPrefix))
		if err == nil && n > 0 {
			return n
		}
	}
	return 1_000_000
}
