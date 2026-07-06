/*
Copyright (c) 2026 Security Research
*/

// Package tpm interacts with the Trusted Platform Module for key extraction and sealing.
//
// It queries TPM status, scans for sealed key blobs, and performs seal/unseal
// operations using the sealbox library.
//
// Build constraint: !notpm (enabled by default, use -tags notpm to disable)
//
// Entry points:
//   - CheckTPM: query TPM availability and version info
//   - ScanAndExtract: scan directories for sealed key blobs
//   - UnsealKey: unseal a TPM-protected key blob
//   - SealKey: seal data to the TPM
package tpm
