package httpshell

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// DoRequest performs an authenticated HTTP request
func (c *Client) DoRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.ServerURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-ID", c.AuthID)
	req.Header.Set("Content-Type", "application/json")

	return c.HTTPClient.Do(req)
}

// GetServerInfo fetches server information
func (c *Client) GetServerInfo() (*ServerInfo, error) {
	resp, err := c.DoRequest("GET", "/", nil)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil {
			return nil, fmt.Errorf("%s: %s", apiErr.Code, apiErr.Message)
		}

		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var info ServerInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

// ExecuteCommand executes a remote command
func (c *Client) ExecuteCommand(command, workDir string) (*CommandResponse, error) {
	req := CommandRequest{Command: command, WorkDir: workDir, Timeout: 60}

	body, _ := json.Marshal(req)

	resp, err := c.DoRequest("POST", "/exec", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil {
			return nil, fmt.Errorf("%s: %s", apiErr.Code, apiErr.Message)
		}

		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result CommandResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ChangeDir changes the remote working directory
func (c *Client) ChangeDir(path string) (string, error) {
	req := map[string]string{"path": path}
	body, _ := json.Marshal(req)

	resp, err := c.DoRequest("POST", "/cd", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil {
			return "", fmt.Errorf("%s: %s", apiErr.Code, apiErr.Message)
		}

		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result["workdir"], nil
}

// RunInteractive starts an interactive session
func (c *Client) RunInteractive() error {
	info, err := c.GetServerInfo()
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", c.ServerURL, err)
	}

	fmt.Printf("Connected to: %s\n", c.ServerURL)
	fmt.Printf("Server: %s (%s/%s)\n", info.Hostname, info.Platform, info.Arch)
	fmt.Printf("Shell: %s\n", info.Shell)
	fmt.Printf("WorkDir: %s\n", info.WorkDir)
	fmt.Printf("Type 'exit' or 'quit' to disconnect\n\n")

	reader := bufio.NewReader(os.Stdin)
	currentDir := info.WorkDir

	for {
		promptDir := currentDir
		if len(promptDir) > 40 {
			promptDir = "..." + promptDir[len(promptDir)-37:]
		}

		fmt.Printf("[%s]$ ", promptDir)

		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("\n[*] Disconnected")
				return nil
			}

			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		switch strings.ToLower(input) {
		case "exit", "quit":
			fmt.Println("[*] Disconnecting...")
			return nil
		}

		if strings.HasPrefix(strings.ToLower(input), "cd ") {
			path := strings.TrimSpace(input[3:])
			if newDir, err := c.ChangeDir(path); err == nil {
				currentDir = newDir
				fmt.Printf("[*] Changed to: %s\n", currentDir)
			} else {
				fmt.Printf("[-] Error: %v\n", err)
			}

			continue
		}

		resp, err := c.ExecuteCommand(input, currentDir)
		if err != nil {
			fmt.Printf("[-] Error: %v\n", err)
			continue
		}

		if resp.Output != "" {
			fmt.Print(resp.Output)

			if !strings.HasSuffix(resp.Output, "\n") {
				fmt.Println()
			}
		}

		if resp.ExitCode != 0 {
			fmt.Printf("[exit: %d] ", resp.ExitCode)

			if resp.Error != "" {
				fmt.Printf("(%s)", resp.Error)
			}

			fmt.Println()
		}
	}
}

// RunSingleCommand executes a single command and exits
func (c *Client) RunSingleCommand(command string) error {
	resp, err := c.ExecuteCommand(command, "")
	if err != nil {
		return err
	}

	fmt.Print(resp.Output)

	if resp.ExitCode != 0 {
		os.Exit(resp.ExitCode)
	}

	return nil
}

// ShowServerInfo displays server information
func (c *Client) ShowServerInfo() error {
	info, err := c.GetServerInfo()
	if err != nil {
		return err
	}

	fmt.Printf("\nServer Information:\n")
	fmt.Printf("  Version:  %s\n", info.Version)
	fmt.Printf("  Platform: %s/%s\n", info.Platform, info.Arch)
	fmt.Printf("  Hostname: %s\n", info.Hostname)
	fmt.Printf("  Shell:    %s\n", info.Shell)
	fmt.Printf("  WorkDir:  %s\n", info.WorkDir)
	fmt.Printf("  Uptime:   %s\n", info.Uptime)
	fmt.Println()

	return nil
}
