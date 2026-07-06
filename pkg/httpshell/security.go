package httpshell

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// GenerateAuthID creates a cryptographically random 32-character token (~160 bits
// of entropy from a 32-symbol alphabet). The previous 6-character token (~30 bits)
// was brute-forceable in under a minute over loopback; this is not.
func GenerateAuthID() string {
	const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"
	const tokenLen = 32

	b := make([]byte, tokenLen)
	alphabetSize := big.NewInt(int64(len(chars)))

	for i := range b {
		n, err := rand.Int(rand.Reader, alphabetSize)
		if err != nil {
			// crypto/rand failure is fatal for a security token — do not fall back
			// to a weak source.
			panic(fmt.Sprintf("httpshell: crypto/rand failure: %v", err))
		}

		b[i] = chars[n.Int64()]
	}

	return string(b)
}

// NormalizeAuthID converts auth ID to uppercase and removes dashes
func NormalizeAuthID(authID string) string {
	return strings.ToUpper(strings.ReplaceAll(authID, "-", ""))
}

// IsAllowedIP checks if an IP is in the 192.168.15.100-109 range
func IsAllowedIP(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	if host == "::1" || host == "127.0.0.1" {
		return true
	}

	for i := 100; i <= 109; i++ {
		if host == fmt.Sprintf("192.168.15.%d", i) {
			return true
		}
	}

	return false
}

// IsAllowedURL checks if a URL targets an allowed IP
func IsAllowedURL(urlStr string) bool {
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")
	host := strings.Split(urlStr, "/")[0]
	host = strings.Split(host, ":")[0]

	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	for i := 100; i <= 109; i++ {
		if host == fmt.Sprintf("192.168.15.%d", i) {
			return true
		}
	}

	return false
}

// AllowedCommandPrefixes is an allowlist of command name prefixes that the
// httpshell server will execute. Only commands whose first token (the program
// name, lower-cased, with backslashes normalised to forward-slashes) begins
// with one of these prefixes are permitted. Everything else is denied by
// default — this is the inverse of the previous bypassable blocklist.
//
// The list covers the common localhost dev-workflow needs: directory listing,
// file inspection, process info, build tools, and shell builtins that arrive
// as part of a compound command string. Keep it conservative; add entries
// deliberately rather than broadly.
var AllowedCommandPrefixes = []string{
	// directory / file inspection
	"ls", "dir", "pwd", "echo", "printf", "cat", "head", "tail",
	"find", "tree", "file", "stat", "wc", "diff", "less", "more",
	// text processing
	"grep", "awk", "sed", "cut", "sort", "uniq", "tr", "jq", "yq",
	// process / system info
	"ps", "top", "uname", "whoami", "id", "hostname", "uptime",
	"df", "du", "free", "env", "printenv", "lsof", "ss", "netstat",
	// build / dev tools
	"go", "git", "make", "task", "npm", "node", "python3", "pip3",
	"cargo", "rustc", "java", "javac", "mvn", "gradle",
	"docker", "kubectl", "helm",
	// shell builtins / utilities
	"exit", "cd", "mkdir", "touch", "cp", "mv", "chmod", "chown",
	"which", "type", "where", "help",
	// Windows equivalents
	"cmd", "powershell", "pwsh",
	"type", "copy", "move", "del", "ren", "xcopy", "robocopy",
	"tasklist", "taskkill", "reg", "sc", "net",
}

// ForbiddenPaths contains paths that commands cannot access.
// These are checked as secondary path guards even for allowlisted commands.
var ForbiddenPaths = []string{
	"/etc", "/root", "/var", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys",
	"/lib", "/lib64", "/opt", "/srv", "/mnt", "/media", "/run", "/snap", "/lost+found",
	"c:/windows", "c:/program files", "c:/program files (x86)", "c:/programdata",
	"c:/system", "c:/recovery", "c:/perflogs", "c:/$recycle.bin",
	"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh",
	".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
	"id_rsa", "id_ed25519", ".pem", ".key", ".env",
}

// IsCommandAllowed checks if a command is safe to execute using allowlist semantics.
// The first token of the command string (the program name) must appear in
// AllowedCommandPrefixes; an absent or unrecognised program is denied.
// Additionally, the full command is checked against ForbiddenPaths to block
// accidental access to sensitive locations even via allowlisted programs.
func IsCommandAllowed(command string) (bool, string) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return false, "empty command"
	}

	// Extract the first token as the program name, normalised to lower-case
	// with backslashes converted to forward-slashes for cross-platform matching.
	firstToken := strings.Fields(trimmed)[0]
	firstToken = strings.ToLower(firstToken)
	firstToken = strings.ReplaceAll(firstToken, "\\", "/")
	// Strip any leading path component so "/bin/grep" matches "grep".
	if idx := strings.LastIndex(firstToken, "/"); idx >= 0 {
		firstToken = firstToken[idx+1:]
	}

	allowed := false

	for _, prefix := range AllowedCommandPrefixes {
		if firstToken == strings.ToLower(prefix) {
			allowed = true
			break
		}
	}

	if !allowed {
		return false, fmt.Sprintf("command %q is not in the allowed list", firstToken)
	}

	// Secondary: check the full command for forbidden path references.
	cmdLower := strings.ToLower(trimmed)
	cmdLower = strings.ReplaceAll(cmdLower, "\\", "/")

	for _, forbiddenPath := range ForbiddenPaths {
		pathLower := strings.ToLower(forbiddenPath)
		patterns := []string{
			pathLower,
			" " + pathLower,
			"\"" + pathLower,
			"'" + pathLower,
			"=" + pathLower,
			">" + pathLower,
			"<" + pathLower,
		}

		for _, pattern := range patterns {
			if strings.Contains(cmdLower, pattern) {
				return false, fmt.Sprintf("access to forbidden path: %s", forbiddenPath)
			}
		}
	}

	return true, ""
}

// IsAllowedPath checks if a path is within allowed directories
func IsAllowedPath(path string) bool {
	normalizedPath := strings.ToLower(filepath.Clean(path))
	normalizedPath = strings.ReplaceAll(normalizedPath, "\\", "/")

	allowedPrefixes := []string{
		"/home/", "/home",
		"b:/", "b:",
		"c:/users/", "c:/users",
	}

	blockedPaths := []string{
		"c:/", "c:/windows", "c:/program files", "c:/program files (x86)",
		"c:/programdata", "c:/system",
	}

	for _, blocked := range blockedPaths {
		if normalizedPath == blocked || strings.HasPrefix(normalizedPath, blocked+"/") {
			if strings.HasPrefix(normalizedPath, "c:/users") {
				continue
			}

			return false
		}
	}

	for _, prefix := range allowedPrefixes {
		if normalizedPath == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(normalizedPath, prefix) {
			return true
		}
	}

	return false
}

// GetLocalAllowedIP finds a local IP in the allowed range
func GetLocalAllowedIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ip := ipNet.IP.String()
				for i := 100; i <= 109; i++ {
					if ip == fmt.Sprintf("192.168.15.%d", i) {
						return ip
					}
				}
			}
		}
	}

	return ""
}

// GetLocalIPs returns all local IPv4 addresses
func GetLocalIPs() []string {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}

	return ips
}

// GenerateSelfSignedCert creates a self-signed certificate
func GenerateSelfSignedCert(certPath, keyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	hostname, _ := os.Hostname()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"HTTP Shell Dev"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	for i := 100; i <= 109; i++ {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(fmt.Sprintf("192.168.15.%d", i)))
	}

	template.DNSNames = []string{"localhost", hostname}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}

	defer func() { _ = certFile.Close() }()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}

	defer func() { _ = keyFile.Close() }()

	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}

// MustGetwd returns the current working directory or "/" on error
func MustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "/"
	}

	return wd
}

// Truncate shortens a string to maxLen with "..." prefix if needed
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	return "..." + s[len(s)-maxLen+3:]
}

// IsAbsPath checks if a path is absolute
func IsAbsPath(path string) bool {
	if runtime.GOOS == "windows" {
		return len(path) >= 2 && path[1] == ':'
	}

	return len(path) > 0 && path[0] == '/'
}

// JoinPath joins two path components
func JoinPath(base, rel string) string {
	if runtime.GOOS == "windows" {
		return base + "\\" + rel
	}

	return base + "/" + rel
}
