/*
Copyright (c) 2026 Security Research
*/

package webview2

// Preset captures the OS-level metadata for a known CDP target Kind.
// Faithful port of spectra cdpboot Preset (83-CONTEXT D-03/D-06).
type Preset struct {
	// Kind matches Target.Kind ("teams-desktop", "wa-desktop").
	Kind string

	// Port is the default CDP remote-debugging port.
	Port int

	// Method selects the launch path. See LaunchMethod docs.
	Method LaunchMethod

	// ProcessName is the image name passed to tasklist/taskkill. For
	// WhatsApp Desktop this is "WhatsApp.Root.exe" (NOT "WhatsApp.exe",
	// which is a stub — Pitfall 1).
	ProcessName string

	// PkgName is the short package name for `Get-AppxPackage -Name <PkgName>`.
	// WhatsApp's is "5319275A.WhatsAppDesktop" — the leading digit is
	// significant and must be passed via an arg slice / single-quoted PS
	// string, never shell-interpolated (Landmine #5).
	PkgName string

	// ExeBasename is appended to InstallLocation for MethodDirect launches.
	ExeBasename string

	// AUMID is the AppUserModelId for shell:AppsFolder activation, used
	// only by MethodAUMID targets.
	AUMID string

	// URLContains is the substring required in at least one /json page
	// target URL before Probe declares ready.
	URLContains string
}

// Presets is the canonical Kind → Preset table — EXACTLY the two locked
// VALD targets (83-PATTERNS lines 60-69). Adding a new target means adding
// a row here and (83-04) wiring a Cobra subcommand.
var Presets = map[string]Preset{
	"teams-desktop": {
		Kind:        "teams-desktop",
		Port:        9223,
		Method:      MethodDirect,
		ProcessName: "ms-teams.exe",
		PkgName:     "MSTeams",
		ExeBasename: "ms-teams.exe",
		// "teams." matches BOTH enterprise (teams.microsoft.com) and the
		// consumer build (teams.live.com/v2/) — the new MSTeams ships either
		// depending on the signed-in account; the narrower host blocked
		// consumer Teams CDP attach (no target url matched).
		URLContains: "teams.",
	},
	// WhatsApp Desktop is true-UWP: WindowsApps\<package>\WhatsApp.Root.exe
	// is ACL-locked. Direct exec returns "Access is denied". Launch via the
	// COM activation broker (shell:AppsFolder) is the only supported path.
	// PkgName retains the digit-prefixed short name (Landmine #5).
	"wa-desktop": {
		Kind:        "wa-desktop",
		Port:        9222,
		Method:      MethodAUMID,
		ProcessName: "WhatsApp.Root.exe",
		PkgName:     "5319275A.WhatsAppDesktop",
		ExeBasename: "WhatsApp.Root.exe",
		AUMID:       "5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App",
		URLContains: "web.whatsapp.com",
	},
}

// PresetFor is a safe lookup: (preset, true) on hit, (zero, false) on miss.
// Closed allowlist — unknown kind yields no route (T-83-03-05).
func PresetFor(kind string) (Preset, bool) {
	p, ok := Presets[kind]
	return p, ok
}
