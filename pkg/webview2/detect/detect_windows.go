//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package detect

import (
	"fmt"

	"golang.org/x/sys/windows/registry"

	"github.com/inovacc/unravel-oss/pkg/webview2"
)

// evergreenRegistryPaths are the documented registry locations for the
// WebView2 Evergreen runtime (research D-03, D-05).
var evergreenRegistryPaths = []struct {
	Root registry.Key
	Path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + EvergreenRuntimeGUID},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + EvergreenRuntimeGUID},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + EvergreenRuntimeGUID},
}

// DetectEvergreenRuntime probes the Windows registry for the installed
// WebView2 Evergreen runtime version (pv string value). Uses QUERY_VALUE only
// (V14 ASVS, T-03-03, T-03-05). Returns Mode="unknown" if no key is found.
func DetectEvergreenRuntime() (webview2.RuntimeInfo, error) {
	for _, entry := range evergreenRegistryPaths {
		k, err := registry.OpenKey(entry.Root, entry.Path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		pv, _, pvErr := k.GetStringValue("pv")
		location, _, _ := k.GetStringValue("location")
		_ = k.Close()
		if pvErr != nil {
			continue
		}
		return webview2.RuntimeInfo{
			Mode:       "evergreen",
			Version:    pv,
			InstallDir: location,
		}, nil
	}
	return webview2.RuntimeInfo{Mode: "unknown"}, fmt.Errorf("webview2 detect: evergreen runtime not found in registry")
}
