/*
Copyright (c) 2026 Security Research
*/

package detect

// Known DLL names, package prefixes, and bootstrapper executables for
// WinUI 3 / WindowsAppSDK detection.
const (
	// DLLMUX is the WinUI 3 (Microsoft.UI.Xaml) host DLL. Disambiguate from
	// WinUI 2 via deps.json; on its own it is medium-to-high confidence.
	DLLMUX = "Microsoft.UI.Xaml.dll"
	// DLLWUX is the legacy Windows.UI.Xaml DLL — UWP / WinUI 2.
	DLLWUX = "Windows.UI.Xaml.dll"
	// DLLWindowsAppSDKBootstr is the WindowsAppSDK bootstrapper DLL.
	DLLWindowsAppSDKBootstr = "Microsoft.WindowsAppSDK.Bootstrap.dll"
	// ExeWindowsAppRuntimeB is the WindowsAppRuntime bootstrapper executable.
	ExeWindowsAppRuntimeB = "WindowsAppRuntimeBootstrapper.exe"

	// PkgPrefixWinUI is the deps.json package prefix for WinUI 3.
	PkgPrefixWinUI = "Microsoft.WinUI"
	// PkgPrefixWindowsAppSDK is the deps.json package prefix for WindowsAppSDK.
	PkgPrefixWindowsAppSDK = "Microsoft.WindowsAppSDK"
	// PkgPrefixWindowsAppRT is the deps.json package prefix for the
	// WindowsAppRuntime bootstrap (medium-confidence corroborator).
	PkgPrefixWindowsAppRT = "Microsoft.WindowsAppRuntime"
)
