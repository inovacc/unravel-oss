/*
Copyright (c) 2026 Security Research
*/
package winsvc

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ServiceAction defines the requested state change for a service.
type ServiceAction string

const (
	ActionStart   ServiceAction = "start"
	ActionStop    ServiceAction = "stop"
	ActionRestart ServiceAction = "restart"
)

// ControlService performs a state change (start/stop/restart) on a Windows service.
// This requires administrative privileges for the underlying 'sc' or 'net' calls.
func ControlService(name string, action ServiceAction) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("service control only supported on Windows")
	}

	var cmd *exec.Cmd
	switch action {
	case ActionStart:
		cmd = exec.Command("sc", "start", name)
	case ActionStop:
		cmd = exec.Command("sc", "stop", name)
	case ActionRestart:
		// sc doesn't have a native restart; use powershell for atomic restart
		psCmd := fmt.Sprintf("Restart-Service -Name %s", name)
		cmd = exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	default:
		return fmt.Errorf("unsupported service action: %s", action)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to %s service %q: %w (output: %s)", action, name, err, string(out))
	}

	return nil
}

// IsRunning checks if the given service is currently in the 'running' state.
func IsRunning(name string) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, nil
	}

	out, err := exec.Command("sc", "query", name).Output()
	if err != nil {
		return false, err
	}

	return strings.Contains(string(out), "RUNNING"), nil
}
