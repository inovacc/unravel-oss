package httpshell

import (
	"net/http"
	"sync"
	"time"
)

const Version = "1.1.0"

// CommandRequest represents a command to execute.
//
// Security note: a caller-supplied shell field has been intentionally removed.
// The server always uses its own server-detected shell; accepting an arbitrary
// binary path from a request body would allow any local process that can reach
// the endpoint to execute arbitrary binaries regardless of the command allowlist.
type CommandRequest struct {
	Command string `json:"command"`
	WorkDir string `json:"workdir,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

// CommandResponse represents the execution result
type CommandResponse struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Duration  string `json:"duration"`
	Timestamp string `json:"timestamp"`
	WorkDir   string `json:"workdir"`
}

// ServerInfo provides server metadata
type ServerInfo struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	Shell    string `json:"shell"`
	WorkDir  string `json:"workdir"`
	Uptime   string `json:"uptime"`
}

// APIError represents a structured error response
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Server holds server state
type Server struct {
	AuthID     string
	Shell      string
	ShellArgs  []string
	WorkDir    string
	StartTime  time.Time
	CmdHistory []CommandResponse
	Mu         sync.Mutex
	AllowedIPs []string
	CertFile   string
	KeyFile    string
	LocalIP    string
}

// Client holds client configuration
type Client struct {
	ServerURL  string
	AuthID     string
	HTTPClient *http.Client
}

// NewClient creates a new client with auth configuration.
//
// TLS note: the server generates a self-signed certificate so by default
// verification will fail. Callers that need to connect to the default
// self-signed server should obtain the server's certificate fingerprint
// and configure a custom transport, or run the server with a properly-signed
// certificate. InsecureSkipVerify is intentionally NOT set here because
// httpshell is a localhost-only dev tool — if you are connecting to
// 127.0.0.1 there is no network-level MitM risk, but hardcoding a TLS
// skip would silently eliminate the guard for any future non-loopback use.
func NewClient(serverURL, authID string) *Client {
	return &Client{
		ServerURL:  serverURL,
		AuthID:     authID,
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}
