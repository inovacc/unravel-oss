/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/cert"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type certInfoInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to PE or ELF binary"`
}

type certVerifyInput struct {
	BinaryPath string `json:"binary_path" jsonschema:"Path to PE or ELF binary to verify"`
}

type certCompareInput struct {
	BinaryPaths []string `json:"binary_paths" jsonschema:"List of binary paths to compare certificates"`
}

type certScanInput struct {
	DirectoryPath string `json:"directory_path" jsonschema:"Directory to scan for signed binaries"`
	Verbose       bool   `json:"verbose,omitempty" jsonschema:"Show verbose output"`
}

func registerCertTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_cert_info",
		Description: "Extract Authenticode (PE) or kernel module (ELF) certificates from a binary",
	}, handleCertInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_cert_verify",
		Description: "Extract and verify certificate validity for a signed binary",
	}, handleCertVerify)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_cert_compare",
		Description: "Compare certificates across multiple binaries",
	}, handleCertCompare)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_cert_scan",
		Description: "Scan a directory for all signed PE/ELF binaries with certificate summary",
	}, handleCertScan)
}

func handleCertInfo(_ context.Context, _ *mcp.CallToolRequest, input certInfoInput) (*mcp.CallToolResult, any, error) {
	result, err := cert.ExtractCertificates(input.BinaryPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleCertVerify(_ context.Context, _ *mcp.CallToolRequest, input certVerifyInput) (*mcp.CallToolResult, any, error) {
	result, err := cert.VerifyCertificate(input.BinaryPath)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleCertCompare(_ context.Context, _ *mcp.CallToolRequest, input certCompareInput) (*mcp.CallToolResult, any, error) {
	var results []*cert.CertInfo

	for _, path := range input.BinaryPaths {
		info, err := cert.ExtractCertificates(path)
		if err != nil {
			return errorResult(err), nil, nil
		}

		results = append(results, info)
	}

	return jsonResult(results), nil, nil
}

func handleCertScan(_ context.Context, _ *mcp.CallToolRequest, input certScanInput) (*mcp.CallToolResult, any, error) {
	results, err := cert.ScanDirectory(input.DirectoryPath, input.Verbose)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(results), nil, nil
}
