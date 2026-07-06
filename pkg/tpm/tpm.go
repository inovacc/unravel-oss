//go:build !notpm

// Package tpm extracts keys from Trusted Platform Module (TPM) using sealbox.
package tpm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/inovacc/sealbox"
)

// TPMInfo holds TPM availability information.
type TPMInfo struct {
	Available bool   `json:"tpm_available"`
	Platform  string `json:"platform"`
	Error     string `json:"error,omitempty"`
}

// SealedKeyInfo holds information about a found sealed blob.
type SealedKeyInfo struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ModTime   string `json:"modified_time"`
	SHA256    string `json:"sha256"`
	CanUnseal bool   `json:"can_unseal"`
	KeyHex    string `json:"key_hex,omitempty"`
	KeyLen    int    `json:"key_length,omitempty"`
	UnsealErr string `json:"unseal_error,omitempty"`
}

// ExtractionResult holds the complete scan/extraction result.
type ExtractionResult struct {
	ExtractedAt   string          `json:"extracted_at"`
	TPMInfo       TPMInfo         `json:"tpm_info"`
	SearchPaths   []string        `json:"search_paths"`
	SealedKeys    []SealedKeyInfo `json:"sealed_keys"`
	ExtractedKeys int             `json:"extracted_keys_count"`
	Errors        []string        `json:"errors,omitempty"`
}

// CheckTPM returns information about TPM availability.
func CheckTPM() TPMInfo {
	info := TPMInfo{
		Platform:  runtime.GOOS,
		Available: sealbox.IsAvailable(),
	}
	if !info.Available {
		info.Error = "TPM device not available or not accessible"
	}

	return info
}

// ScanAndExtract scans a directory for sealed blobs and attempts extraction.
func ScanAndExtract(searchPath, outputPath string) (*ExtractionResult, error) {
	result := &ExtractionResult{
		ExtractedAt: time.Now().UTC().Format(time.RFC3339),
		TPMInfo:     CheckTPM(),
		SearchPaths: []string{searchPath},
		SealedKeys:  []SealedKeyInfo{},
		Errors:      []string{},
	}

	if outputPath != "" {
		_ = os.MkdirAll(outputPath, 0755)
	}

	patterns := []string{
		"*.sealed", "*.seal", "*.tpm", "*.blob",
		"sealed_*", "*sealbox*", "*master_key*", "*keystore*",
	}

	var foundFiles []string

	for _, pattern := range patterns {
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			matched, _ := filepath.Match(pattern, strings.ToLower(info.Name()))
			if matched {
				foundFiles = append(foundFiles, path)
			}

			if info.Size() > 0 && info.Size() < 2048 {
				if isBinaryFile(path) && !containsString(foundFiles, path) {
					data, err := os.ReadFile(path)
					if err == nil && looksLikeSealed(data) {
						foundFiles = append(foundFiles, path)
					}
				}
			}

			return nil
		})
	}

	for _, file := range foundFiles {
		info, _ := os.Stat(file)
		keyInfo := SealedKeyInfo{
			Path:    file,
			Size:    info.Size(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
		}

		data, err := os.ReadFile(file)
		if err == nil {
			hash := sha256.Sum256(data)
			keyInfo.SHA256 = hex.EncodeToString(hash[:])
		}

		if result.TPMInfo.Available {
			key, err := tryUnsealFromStore(file)
			if err != nil {
				keyInfo.CanUnseal = false
				keyInfo.UnsealErr = err.Error()
			} else {
				keyInfo.CanUnseal = true
				keyInfo.KeyHex = hex.EncodeToString(key)
				keyInfo.KeyLen = len(key)
				result.ExtractedKeys++

				if outputPath != "" {
					keyPath := filepath.Join(outputPath, "keys", filepath.Base(file)+".key")
					_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
					_ = os.WriteFile(keyPath, key, 0600)
				}

				sealbox.SecureZero(key)
			}
		} else {
			keyInfo.CanUnseal = false
			keyInfo.UnsealErr = "TPM not available"
		}

		result.SealedKeys = append(result.SealedKeys, keyInfo)
	}

	if outputPath != "" {
		resultPath := filepath.Join(outputPath, "extraction_results.json")
		resultData, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile(resultPath, resultData, 0644)
	}

	return result, nil
}

// UnsealKey attempts to unseal a specific blob file.
func UnsealKey(blobPath string) ([]byte, error) {
	info := CheckTPM()
	if !info.Available {
		return nil, fmt.Errorf("TPM not available: %s", info.Error)
	}

	return tryUnsealFromStore(blobPath)
}

// SealKey creates and seals a new key at the given path.
func SealKey(outputPath string) ([]byte, error) {
	info := CheckTPM()
	if !info.Available {
		return nil, fmt.Errorf("TPM not available: %s", info.Error)
	}

	opts := sealbox.WithStorePath(outputPath)
	if err := sealbox.Initialize(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize/seal: %w", err)
	}

	key, err := sealbox.GetSealedMasterKey(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sealed key: %w", err)
	}

	return key, nil
}

func tryUnsealFromStore(path string) ([]byte, error) {
	opts := sealbox.WithStorePath(path)
	return sealbox.GetSealedMasterKey(opts)
}

func isBinaryFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}

	defer func() { _ = file.Close() }()

	buf := make([]byte, 512)

	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	return slices.Contains(buf[:n], 0)
}

func looksLikeSealed(data []byte) bool {
	if len(data) < 50 || len(data) > 2048 {
		return false
	}

	return calculateEntropy(data) >= 7.0
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64

	for _, count := range freq {
		p := float64(count) / float64(len(data))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func containsString(slice []string, s string) bool {

	return slices.Contains(slice, s)
}
