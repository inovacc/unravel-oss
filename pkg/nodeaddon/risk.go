/*
Copyright (c) 2026 Security Research
*/
package nodeaddon

import "strings"

// Import library risk categories and their weights.
var libraryCategories = map[string]struct {
	Category string
	Weight   int
}{
	// Windows crypto
	"bcrypt.dll":   {Category: "crypto", Weight: 5},
	"crypt32.dll":  {Category: "crypto", Weight: 5},
	"ncrypt.dll":   {Category: "crypto", Weight: 5},
	"advapi32.dll": {Category: "registry", Weight: 10},
	"secur32.dll":  {Category: "crypto", Weight: 5},
	// Windows network
	"ws2_32.dll":   {Category: "network", Weight: 10},
	"winhttp.dll":  {Category: "network", Weight: 10},
	"wininet.dll":  {Category: "network", Weight: 10},
	"dnsapi.dll":   {Category: "network", Weight: 5},
	"iphlpapi.dll": {Category: "network", Weight: 5},
	// Windows process/system
	"kernel32.dll": {Category: "system", Weight: 3},
	"ntdll.dll":    {Category: "system", Weight: 8},
	"user32.dll":   {Category: "system", Weight: 3},
	"psapi.dll":    {Category: "process", Weight: 15},
	"dbghelp.dll":  {Category: "process", Weight: 15},
	// Linux shared objects
	"libssl.so":     {Category: "crypto", Weight: 5},
	"libcrypto.so":  {Category: "crypto", Weight: 5},
	"libcurl.so":    {Category: "network", Weight: 10},
	"libpthread.so": {Category: "system", Weight: 2},
	"libdl.so":      {Category: "system", Weight: 5},
	// macOS frameworks
	"security":  {Category: "crypto", Weight: 5},
	"cfnetwork": {Category: "network", Weight: 10},
}

// Dangerous function patterns and their severity.
var dangerousFunctions = []struct {
	Pattern     string
	Name        string
	Description string
	Severity    string
	Weight      int
}{
	// Process injection
	{"CreateRemoteThread", "Process Injection", "Can inject code into other processes", "CRITICAL", 30},
	{"VirtualAllocEx", "Remote Memory Allocation", "Allocates memory in remote process", "CRITICAL", 25},
	{"WriteProcessMemory", "Remote Memory Write", "Writes to another process memory", "CRITICAL", 30},
	{"NtCreateThreadEx", "NT Thread Creation", "Low-level thread creation in remote process", "CRITICAL", 30},
	// Hooking / keylogging
	{"SetWindowsHookEx", "System Hooking", "Can install system-wide hooks (keylogger potential)", "HIGH", 25},
	{"GetAsyncKeyState", "Key State Monitor", "Can monitor keyboard input", "HIGH", 20},
	{"RegisterRawInputDevices", "Raw Input Capture", "Can capture raw keyboard/mouse input", "HIGH", 20},
	// Anti-debug / anti-analysis
	{"IsDebuggerPresent", "Debugger Detection", "Checks if debugger is attached", "MEDIUM", 10},
	{"NtQueryInformationProcess", "Process Inspection", "Can query detailed process info", "MEDIUM", 10},
	{"CheckRemoteDebuggerPresent", "Remote Debugger Detection", "Checks for remote debugger", "MEDIUM", 10},
	// Privilege escalation
	{"AdjustTokenPrivileges", "Privilege Manipulation", "Can adjust process privileges", "HIGH", 20},
	{"OpenProcessToken", "Token Access", "Opens process token for manipulation", "MEDIUM", 15},
	// File system manipulation
	{"DeleteFileW", "File Deletion", "Can delete files", "LOW", 3},
	{"MoveFileEx", "File Move/Rename", "Can move or rename files with options", "LOW", 3},
	// Registry
	{"RegOpenKeyEx", "Registry Access", "Reads Windows registry", "LOW", 5},
	{"RegSetValueEx", "Registry Modification", "Modifies Windows registry", "MEDIUM", 10},
	{"RegCreateKeyEx", "Registry Key Creation", "Creates Windows registry keys", "MEDIUM", 10},
	// Dynamic library loading
	{"dlopen", "Dynamic Library Load", "Loads shared libraries at runtime", "LOW", 5},
	{"LoadLibrary", "Dynamic Library Load", "Loads DLLs at runtime", "LOW", 5},
	// Crypto mining indicators
	{"RandomX", "Crypto Mining", "RandomX mining algorithm detected", "CRITICAL", 30},
	{"CryptoNight", "Crypto Mining", "CryptoNight mining algorithm detected", "CRITICAL", 30},
	{"ethash", "Crypto Mining", "Ethash mining algorithm detected", "CRITICAL", 30},
}

// assessRisk computes a risk score and factors for the addon.
func assessRisk(imports []ImportedLib, exports []ExportedFunc) (int, []RiskFactor) {
	var (
		score   int
		factors []RiskFactor
	)

	// Check imports against dangerous function patterns
	for _, imp := range imports {
		for _, fn := range imp.Functions {
			for _, danger := range dangerousFunctions {
				if strings.Contains(fn, danger.Pattern) {
					score += danger.Weight
					factors = append(factors, RiskFactor{
						Name:        danger.Name,
						Description: danger.Description + " (via " + fn + " in " + imp.Library + ")",
						Severity:    danger.Severity,
					})
				}
			}
		}
	}

	// Check library categories for suspicious combinations
	var hasNetwork, hasCrypto, hasProcess, hasRegistry bool
	for _, imp := range imports {
		switch imp.Category {
		case "network":
			hasNetwork = true
		case "crypto":
			hasCrypto = true
		case "process":
			hasProcess = true
		case "registry":
			hasRegistry = true
		}
	}

	if hasNetwork && hasCrypto {
		score += 10
		factors = append(factors, RiskFactor{
			Name:        "Network + Crypto",
			Description: "Combines network and cryptographic capabilities",
			Severity:    "MEDIUM",
		})
	}

	if hasProcess {
		score += 15
		factors = append(factors, RiskFactor{
			Name:        "Process Manipulation",
			Description: "Imports process manipulation libraries",
			Severity:    "HIGH",
		})
	}

	if hasRegistry {
		score += 5
		factors = append(factors, RiskFactor{
			Name:        "Registry Access",
			Description: "Can read/write Windows registry",
			Severity:    "LOW",
		})
	}

	// Check if no N-API exports found (suspicious for a .node file)
	if exports != nil {
		hasNAPI := false
		for _, e := range exports {
			if e.IsNAPI {
				hasNAPI = true
				break
			}
		}
		if !hasNAPI {
			score += 20
			factors = append(factors, RiskFactor{
				Name:        "Missing N-API Exports",
				Description: "No standard N-API registration functions found — may not be a legitimate Node addon",
				Severity:    "HIGH",
			})
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score, factors
}

// classifyLibrary determines the category of a library by name and its imported functions.
func classifyLibrary(libName string, functions []string) string {
	lower := strings.ToLower(libName)

	// Check exact matches first
	for pattern, info := range libraryCategories {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return info.Category
		}
	}

	// Check by imported function names
	for _, fn := range functions {
		for _, danger := range dangerousFunctions {
			if strings.Contains(fn, danger.Pattern) {
				switch {
				case strings.Contains(danger.Name, "Inject") || strings.Contains(danger.Name, "Process") || strings.Contains(danger.Name, "Thread"):
					return "process"
				case strings.Contains(danger.Name, "Registry"):
					return "registry"
				case strings.Contains(danger.Name, "Hook") || strings.Contains(danger.Name, "Key"):
					return "input"
				case strings.Contains(danger.Name, "Crypto") || strings.Contains(danger.Name, "Mining"):
					return "crypto"
				}
			}
		}
	}

	// Generic classification by name pattern
	switch {
	case strings.Contains(lower, "ssl") || strings.Contains(lower, "crypto") || strings.Contains(lower, "crypt"):
		return "crypto"
	case strings.Contains(lower, "net") || strings.Contains(lower, "sock") || strings.Contains(lower, "http") || strings.Contains(lower, "curl"):
		return "network"
	case strings.Contains(lower, "pthread") || strings.Contains(lower, "thread"):
		return "system"
	case strings.Contains(lower, "stdc++") || lower == "libc.so" || strings.HasPrefix(lower, "libc.so.") || lower == "libm.so" || strings.HasPrefix(lower, "libm.so.") || strings.Contains(lower, "msvcrt"):
		return "runtime"
	case strings.Contains(lower, "node") || strings.Contains(lower, "napi") || strings.Contains(lower, "v8"):
		return "node"
	case strings.Contains(lower, "filesystem") || strings.Contains(lower, "fs"):
		return "filesystem"
	default:
		return "system"
	}
}
