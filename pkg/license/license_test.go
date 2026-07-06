/* Copyright (c) 2026 Security Research */
package license

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunTestsAnalyzeOnly(t *testing.T) {
	config := Config{
		TargetURL:   "http://unused.example.com",
		AnalyzeOnly: true,
		Timeout:     5 * time.Second,
	}

	report := RunTests(config)

	if report == nil {
		t.Fatal("RunTests() returned nil")
	}

	if len(report.Results) != 0 {
		t.Errorf("RunTests(AnalyzeOnly) Results count = %d, want 0", len(report.Results))
	}

	if len(report.MachineIDs) == 0 {
		t.Error("RunTests() MachineIDs is empty, want populated")
	}

	if report.Summary.TotalTests != 0 {
		t.Errorf("RunTests(AnalyzeOnly) TotalTests = %d, want 0", report.Summary.TotalTests)
	}
}

func TestRunTestsWithServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := LicenseResponse{
			Success:         false,
			IsActive:        false,
			LastValidatedAt: time.Now().Format(time.RFC3339),
			Error:           "invalid license key",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := Config{
		TargetURL:  server.URL,
		Timeout:    5 * time.Second,
		LicenseKey: "test-key-12345",
	}

	report := RunTests(config)

	if report == nil {
		t.Fatal("RunTests() returned nil")
	}

	if len(report.Results) == 0 {
		t.Error("RunTests() Results is empty, want populated")
	}

	if report.Summary.TotalTests == 0 {
		t.Error("RunTests() TotalTests = 0, want > 0")
	}

	if report.Summary.TotalTests != len(report.Results) {
		t.Errorf("TotalTests = %d, len(Results) = %d, want equal",
			report.Summary.TotalTests, len(report.Results))
	}
}
