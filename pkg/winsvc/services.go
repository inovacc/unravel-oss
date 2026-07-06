/*
Copyright (c) 2026 Security Research
*/
package winsvc

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ServiceInfo describes a registered Windows service.
type ServiceInfo struct {
	Name         string   `json:"name"`
	DisplayName  string   `json:"display_name"`
	BinaryPath   string   `json:"binary_path"`
	StartType    string   `json:"start_type"` // auto, manual, disabled, boot, system
	Status       string   `json:"status,omitempty"`
	Description  string   `json:"description,omitempty"`
	Account      string   `json:"account,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// ScanResult holds all services found for an application.
type ScanResult struct {
	Directory    string        `json:"directory"`
	Services     []ServiceInfo `json:"services"`
	TotalScanned int           `json:"total_scanned"`
}

// ScanForServices finds Windows services whose binary paths match files in the given directory.
// On non-Windows platforms, returns an empty result with no error.
func ScanForServices(appDir string) (*ScanResult, error) {
	if runtime.GOOS != "windows" {
		return &ScanResult{Directory: appDir}, nil
	}

	return scanServicesWindows(appDir)
}

// psService is the JSON shape returned by Get-Service via PowerShell.
type psService struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Status      int    `json:"Status"`
	StartType   int    `json:"StartType"`
}

// statusText maps the .NET ServiceControllerStatus enum values to strings.
func statusText(code int) string {
	switch code {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

// startTypeText maps the .NET ServiceStartMode enum values to strings.
func startTypeText(code int) string {
	switch code {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "auto"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

func scanServicesWindows(appDir string) (*ScanResult, error) {
	absDir, err := filepath.Abs(appDir)
	if err != nil {
		return nil, fmt.Errorf("resolve app dir: %w", err)
	}

	result := &ScanResult{
		Directory: absDir,
		Services:  []ServiceInfo{},
	}

	// Get all services as JSON via PowerShell.
	psCmd := `Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
	if err != nil {
		return result, fmt.Errorf("powershell Get-Service: %w", err)
	}

	var services []psService
	if err := json.Unmarshal(out, &services); err != nil {
		// PowerShell returns a single object (not array) when only one service exists.
		var single psService
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return result, fmt.Errorf("parse service list: %w", err)
		}
		services = []psService{single}
	}

	result.TotalScanned = len(services)

	// For each service, query its binary path using sc qc.
	normDir := strings.ToLower(filepath.ToSlash(absDir))

	for _, svc := range services {
		binPath := queryBinaryPath(svc.Name)
		if binPath == "" {
			continue
		}

		// Normalize and compare path.
		normBin := strings.ToLower(filepath.ToSlash(binPath))
		if !strings.HasPrefix(normBin, normDir) {
			continue
		}

		si := ServiceInfo{
			Name:        svc.Name,
			DisplayName: svc.DisplayName,
			BinaryPath:  binPath,
			StartType:   startTypeText(svc.StartType),
			Status:      statusText(svc.Status),
		}

		// Try to get extra details.
		populateServiceDetails(&si)

		result.Services = append(result.Services, si)
	}

	return result, nil
}

// queryBinaryPath runs "sc qc <name>" and parses out the BINARY_PATH_NAME.
func queryBinaryPath(serviceName string) string {
	out, err := exec.Command("sc", "qc", serviceName).Output()
	if err != nil {
		return ""
	}

	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BINARY_PATH_NAME") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				binPath := strings.TrimSpace(parts[1])
				// Remove surrounding quotes if present.
				binPath = strings.Trim(binPath, `"`)
				// Handle paths like "C:\path\svc.exe -arg1" — take just the exe.
				if idx := strings.Index(strings.ToLower(binPath), ".exe "); idx != -1 {
					binPath = binPath[:idx+4]
				}
				return binPath
			}
		}
	}

	return ""
}

// populateServiceDetails runs "sc qdescription" and "sc qc" for account/deps.
func populateServiceDetails(si *ServiceInfo) {
	// Description.
	if out, err := exec.Command("sc", "qdescription", si.Name).Output(); err == nil {
		for line := range strings.SplitSeq(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "DESCRIPTION") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					si.Description = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// Account and dependencies from sc qc output.
	if out, err := exec.Command("sc", "qc", si.Name).Output(); err == nil {
		for line := range strings.SplitSeq(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "SERVICE_START_NAME") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					si.Account = strings.TrimSpace(parts[1])
				}
			}
			if strings.HasPrefix(line, "DEPENDENCIES") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					dep := strings.TrimSpace(parts[1])
					if dep != "" && dep != "(null)" {
						si.Dependencies = strings.Split(dep, "/")
					}
				}
			}
		}
	}
}
