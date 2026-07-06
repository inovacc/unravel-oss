//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package analyze

import "golang.org/x/sys/windows/registry"

// evergreenRuntimeGUID is the WebView2 Evergreen runtime registry GUID.
const evergreenRuntimeGUID = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

var evergreenRegistryPaths = []struct {
	Root registry.Key
	Path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + evergreenRuntimeGUID},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + evergreenRuntimeGUID},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + evergreenRuntimeGUID},
}

// detectEvergreen probes the Windows registry for the installed WebView2
// Evergreen runtime version (pv string value). QUERY_VALUE only (V14 ASVS,
// T-03-03, T-03-05).
func detectEvergreen() (RuntimeInfo, bool) {
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
		return RuntimeInfo{
			Mode:       "evergreen",
			Version:    pv,
			InstallDir: location,
		}, true
	}
	return RuntimeInfo{}, false
}
