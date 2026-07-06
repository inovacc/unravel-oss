//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package udf

import (
	"golang.org/x/sys/windows/registry"
)

// policyUDFCandidates reads the WebView2 UserDataDir override from the user
// registry policy hive (HKCU\Software\Policies\Microsoft\Edge\WebView2).
// Uses QUERY_VALUE only (V14 ASVS, T-03-12).
func policyUDFCandidates() []string {
	const keyPath = `Software\Policies\Microsoft\Edge\WebView2`
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("UserDataDir")
	if err != nil || v == "" {
		return nil
	}
	return []string{v}
}
