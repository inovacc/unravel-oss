/*
Copyright (c) 2026 Security Research
*/
package secret

import (
	"archive/zip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestScan_NonExistentFile(t *testing.T) {
	_, err := Scan("/nonexistent/test.apk")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestScan_EmptyAPK(t *testing.T) {
	apkPath := createTestAPK(t, nil)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", result.TotalFindings)
	}
}

func TestScan_GoogleAPIKey(t *testing.T) {
	files := map[string]string{
		"assets/config.json": `{"api_key": "` + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv" + `"}`,
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypeGoogleAPIKey {
			found = true

			if f.Confidence != "high" {
				t.Errorf("expected high confidence, got %q", f.Confidence)
			}

			break
		}
	}

	if !found {
		t.Error("expected to find Google API Key")
	}
}

func TestScan_AWSAccessKey(t *testing.T) {
	files := map[string]string{
		"assets/env.properties": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypeAWSAccessKey {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find AWS Access Key")
	}
}

func TestScan_PrivateKey(t *testing.T) {
	files := map[string]string{
		"assets/key.pem": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypePrivateKey {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find Private Key")
	}
}

func TestScan_GitHubToken(t *testing.T) {
	files := map[string]string{
		"assets/config.txt": "token=ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n",
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypeGitHubToken {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find GitHub token")
	}
}

func TestScan_FirebaseURL(t *testing.T) {
	files := map[string]string{
		"assets/firebase.json": `{"url": "https://myapp-12345.firebaseio.com"}`,
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypeFirebaseURL {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find Firebase URL")
	}
}

func TestScan_JWT(t *testing.T) {
	files := map[string]string{
		"assets/token.txt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A",
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypeJWT {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find JWT token")
	}
}

func TestScan_MultipleSecrets(t *testing.T) {
	files := map[string]string{
		"assets/config.json": `{
			"google_key": "` + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv" + `",
			"stripe_key": "` + "sk_live_" + "abcdefghijklmnopqrstuvwx" + `"
		}`,
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", result.TotalFindings)
	}
}

func TestScan_DEXBinaryStrings(t *testing.T) {
	// Create an APK with a fake DEX containing a planted secret.
	apkPath := filepath.Join(t.TempDir(), "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	// Write AndroidManifest.xml.
	w, _ := zw.Create("AndroidManifest.xml")
	_, _ = w.Write([]byte{0x03, 0x00, 0x08, 0x00})

	// Write fake DEX with embedded Google API key.
	w, _ = zw.Create("classes.dex")
	dexContent := make([]byte, 100)
	copy(dexContent, "dex\n035\x00")
	// Embed a Google API key in binary data.
	secret := "AIza" + "SyBcDefGhiJklMnoPqrStUvWxYz12345Abc"
	copy(dexContent[20:], secret)
	_, _ = w.Write(dexContent)

	_ = zw.Close()
	_ = f.Close()

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, finding := range result.Findings {
		if finding.Type == TypeGoogleAPIKey {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find Google API Key in DEX binary strings")
	}
}

func TestScan_Deduplication(t *testing.T) {
	files := map[string]string{
		"assets/config1.json": `{"key": "` + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv" + `"}`,
		"assets/config2.json": `{"key": "` + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv" + `"}`,
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be deduplicated.
	googleCount := 0

	for _, f := range result.Findings {
		if f.Type == TypeGoogleAPIKey {
			googleCount++
		}
	}

	if googleCount != 1 {
		t.Errorf("expected 1 deduplicated Google API Key finding, got %d", googleCount)
	}
}

func TestScan_ConfidenceCounting(t *testing.T) {
	files := map[string]string{
		"assets/mixed.txt": "AIza" + "SyA1234567890abcdefghijklmnopqrstuv\napi_key=some_secret_value_here_16ch",
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.HighConfidence+result.MedConfidence != result.TotalFindings {
		t.Errorf("confidence counts don't add up: high=%d + med=%d != total=%d",
			result.HighConfidence, result.MedConfidence, result.TotalFindings)
	}
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AIzaSyA123456", "AIza***3456"},
		{"short", "shor***"},
		{"ab", "ab***"},
		{"abcdefghijklm", "abcd***jklm"},
	}

	for _, tt := range tests {
		got := maskValue(tt.input)
		if got != tt.expected {
			t.Errorf("maskValue(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestClassifyEntry(t *testing.T) {
	tests := []struct {
		name     string
		expected scanStrategy
	}{
		{"classes.dex", scanBinaryStrings},
		{"classes2.dex", scanBinaryStrings},
		{"lib/arm64-v8a/libnative.so", scanBinaryStrings},
		{"assets/config.json", scanText},
		{"assets/data.bin", scanBinaryStrings},
		{"res/values/strings.xml", scanBinaryStrings},
		{"AndroidManifest.xml", scanText},
		{"resources.arsc", scanBinaryStrings},
		{"res/drawable/icon.png", scanSkip},
		{"META-INF/CERT.RSA", scanSkip},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyEntry(tt.name)
			if got != tt.expected {
				t.Errorf("classifyEntry(%q) = %d, want %d", tt.name, got, tt.expected)
			}
		})
	}
}

func TestScan_FirebaseConfig(t *testing.T) {
	files := map[string]string{
		"assets/google-services.json": `{
			"project_info": {
				"project_number": "123456789",
				"firebase_url": "https://myapp-12345.firebaseio.com",
				"project_id": "myapp-12345",
				"storage_bucket": "myapp-12345.appspot.com"
			},
			"client": [{
				"client_info": {"mobilesdk_app_id": "1:123456789:android:abc123"},
				"api_key": [{"current_key": "AIzaSyTestKeyForFirebaseConfig123"}],
				"oauth_client": [{"client_id": "123456789-abc.apps.googleusercontent.com"}]
			}]
		}`,
	}

	apkPath := createTestAPK(t, files)

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundConfig := false
	foundAPIKey := false

	for _, f := range result.Findings {
		if f.Type == TypeFirebaseConfig {
			foundConfig = true
		}
		if f.Type == TypeFirebaseAPIKey {
			foundAPIKey = true
		}
	}

	if !foundConfig {
		t.Error("expected to find Firebase Config")
	}
	if !foundAPIKey {
		t.Error("expected to find Firebase API Key from google-services.json")
	}
}

func TestScan_EmbeddedKeystore(t *testing.T) {
	apkPath := filepath.Join(t.TempDir(), "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	w, _ := zw.Create("AndroidManifest.xml")
	_, _ = w.Write([]byte{0x03, 0x00, 0x08, 0x00})

	// Embed a file with .keystore extension
	w, _ = zw.Create("assets/debug.keystore")
	_, _ = w.Write([]byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00, 0x00, 0x02})

	_ = zw.Close()
	_ = f.Close()

	result, err := Scan(apkPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, finding := range result.Findings {
		if finding.Type == TypeEmbeddedKeystore {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find embedded keystore")
	}
}

func TestScanBuildConfig(t *testing.T) {
	content := `public final class BuildConfig {
  public static final String APPLICATION_ID = "com.test.app";
  public static final String BUILD_TYPE = "release";
  public static final String API_BASE_URL = "https://api.example.com";
  public static final String API_KEY = "sk_live_test123456789abc";
}`

	findings := scanBuildConfig(content, "com/test/app/BuildConfig.java")

	if len(findings) != 2 {
		t.Fatalf("expected 2 BuildConfig findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Type != TypeBuildConfig {
			t.Errorf("expected TypeBuildConfig, got %q", f.Type)
		}
	}
}

func TestExtractPrintableStrings(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minLen   int
		contains string
		absent   string
	}{
		{
			name:     "BinaryWithEmbeddedASCII",
			data:     []byte{0x00, 0x01, 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', 0x00, 0xFF},
			minLen:   8,
			contains: "Hello World",
		},
		{
			name:     "ShortStringsExcluded",
			data:     []byte{'A', 'B', 'C', 0x00, 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 0x00},
			minLen:   8,
			contains: "DEFGHIJK",
			absent:   "ABC",
		},
		{
			name:   "AllNonPrintable",
			data:   []byte{0x00, 0x01, 0x02, 0xFF},
			minLen: 4,
		},
		{
			name:     "StringAtEOF",
			data:     []byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'},
			minLen:   8,
			contains: "ABCDEFGH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrintableStrings(tt.data, tt.minLen)

			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, got)
			}

			if tt.absent != "" && strings.Contains(got, tt.absent) {
				t.Errorf("expected result NOT to contain %q, got %q", tt.absent, got)
			}

			if tt.contains == "" && got != "" {
				t.Errorf("expected empty string, got %q", got)
			}
		})
	}
}

func TestExtractCandidateTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
		empty    bool
	}{
		{
			name:     "KeyValuePair",
			input:    "key=value",
			contains: []string{"key", "value"},
		},
		{
			name:     "QuotedString",
			input:    `"quoted"`,
			contains: []string{"quoted"},
		},
		{
			name:     "NestedData",
			input:    "{nested: data}",
			contains: []string{"nested", "data"},
		},
		{
			name:  "WhitespaceOnly",
			input: "  ",
			empty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCandidateTokens(tt.input)

			if tt.empty {
				if len(got) != 0 {
					t.Errorf("expected empty slice, got %v", got)
				}

				return
			}

			for _, want := range tt.contains {
				found := slices.Contains(got, want)

				if !found {
					t.Errorf("expected tokens to contain %q, got %v", want, got)
				}
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		substrs []string
		want    bool
	}{
		{"MatchesKey", "api_key", []string{"key", "secret"}, true},
		{"MatchesToken", "my_token", []string{"key", "token"}, true},
		{"NoMatch", "hostname", []string{"key", "secret"}, false},
		{"EmptyString", "", []string{"key"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsAny(tt.s, tt.substrs...)
			if got != tt.want {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.s, tt.substrs, got, tt.want)
			}
		})
	}
}

func TestMergeResults(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		dst := &ScanResult{
			Findings: []Finding{{Type: TypeGoogleAPIKey, Value: "a"}},
		}
		src := &ScanResult{
			Findings: []Finding{{Type: TypeAWSAccessKey, Value: "b"}},
		}

		MergeResults(dst, src)

		if len(dst.Findings) != 2 {
			t.Errorf("expected 2 findings, got %d", len(dst.Findings))
		}
	})

	t.Run("Dedup", func(t *testing.T) {
		dst := &ScanResult{
			Findings: []Finding{{Type: TypeGoogleAPIKey, Value: "a"}},
		}
		src := &ScanResult{
			Findings: []Finding{{Type: TypeGoogleAPIKey, Value: "a"}},
		}

		MergeResults(dst, src)

		if len(dst.Findings) != 1 {
			t.Errorf("expected 1 finding after dedup, got %d", len(dst.Findings))
		}
	})

	t.Run("NilSrc", func(t *testing.T) {
		dst := &ScanResult{
			Findings: []Finding{{Type: TypeGoogleAPIKey, Value: "a"}},
		}

		MergeResults(dst, nil) // should not panic

		if len(dst.Findings) != 1 {
			t.Errorf("expected 1 finding unchanged, got %d", len(dst.Findings))
		}
	})

	t.Run("NilDst", func(t *testing.T) {
		src := &ScanResult{
			Findings: []Finding{{Type: TypeGoogleAPIKey, Value: "a"}},
		}

		MergeResults(nil, src) // should not panic
	})

	t.Run("StatsRecomputed", func(t *testing.T) {
		dst := &ScanResult{
			Findings: []Finding{{Type: TypeGoogleAPIKey, Value: "a", Confidence: "high"}},
		}
		src := &ScanResult{
			Findings: []Finding{{Type: TypeAWSAccessKey, Value: "b", Confidence: "medium"}},
		}

		MergeResults(dst, src)

		if dst.HighConfidence != 1 {
			t.Errorf("expected HighConfidence=1, got %d", dst.HighConfidence)
		}

		if dst.MedConfidence != 1 {
			t.Errorf("expected MedConfidence=1, got %d", dst.MedConfidence)
		}

		if dst.TotalFindings != 2 {
			t.Errorf("expected TotalFindings=2, got %d", dst.TotalFindings)
		}
	})
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()

	srcDir := filepath.Join(dir, "src", "com", "example")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(srcDir, "BuildConfig.java"),
		[]byte(`public static final String API_KEY = "sk_live_test123456789abc";`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(dir, "src", "config.json"),
		[]byte(`{"api": "`+"AIza"+"SyA1234567890abcdefghijklmnopqrstuv"+`"}`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalFindings == 0 {
		t.Error("expected TotalFindings > 0")
	}

	if result.FilesScanned != 2 {
		t.Errorf("expected FilesScanned=2, got %d", result.FilesScanned)
	}
}

func TestScanDirectory_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()

	largeData := make([]byte, 1153434)
	for i := range largeData {
		largeData[i] = 'a'
	}

	if err := os.WriteFile(filepath.Join(dir, "big.json"), largeData, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.FilesScanned != 0 {
		t.Errorf("expected FilesScanned=0, got %d", result.FilesScanned)
	}
}

func TestScanDirectory_SmaliHighConfOnly(t *testing.T) {
	dir := t.TempDir()

	content := "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
	if err := os.WriteFile(filepath.Join(dir, "classes.smali"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ScanDirectory(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false

	for _, f := range result.Findings {
		if f.Type == TypeGoogleAPIKey {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find Google API Key in smali file")
	}
}

func TestScanBuildConfig_NonBuildConfig(t *testing.T) {
	content := `public static final String API_KEY = "sk_live_test123456789abc";`
	findings := scanBuildConfig(content, "com/example/Main.java")

	if findings != nil {
		t.Errorf("expected nil for non-BuildConfig file, got %v", findings)
	}
}

func TestScanBuildConfig_SkipsStandardFields(t *testing.T) {
	content := `public final class BuildConfig {
  public static final String APPLICATION_ID = "com.test.app";
  public static final String BUILD_TYPE = "release";
}`

	findings := scanBuildConfig(content, "com/test/app/BuildConfig.java")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for standard fields only, got %d", len(findings))
	}
}

func TestScanEmbeddedKeystore_Extensions(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		data    []byte
		wantNil bool
	}{
		{
			name: "JKS_Extension_With_Magic",
			file: "assets/debug.jks",
			data: []byte{0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00},
		},
		{
			name: "P12_Extension",
			file: "assets/cert.p12",
			data: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "PFX_Extension",
			file: "assets/cert.pfx",
			data: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "BKS_Extension",
			file: "assets/cert.bks",
			data: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "MagicByteFallback",
			file: "assets/data.bin",
			data: []byte{0xFE, 0xED, 0xFE, 0xED},
		},
		{
			name:    "NoMatch",
			file:    "assets/data.bin",
			data:    []byte{0x00, 0x00, 0x00, 0x00},
			wantNil: true,
		},
		{
			name:    "TooShort_NoKeystoreExt",
			file:    "assets/data.bin",
			data:    []byte{0x01, 0x02},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanEmbeddedKeystore(tt.data, tt.file)

			if tt.wantNil {
				if findings != nil {
					t.Errorf("expected nil, got %v", findings)
				}

				return
			}

			if len(findings) == 0 {
				t.Error("expected at least one finding")
			}

			if findings[0].Type != TypeEmbeddedKeystore {
				t.Errorf("expected TypeEmbeddedKeystore, got %q", findings[0].Type)
			}
		})
	}
}

func TestScanFirebaseConfig_MissingFields(t *testing.T) {
	// Missing "project_info"
	content1 := `{"mobilesdk_app_id": "1:123:android:abc"}`
	if findings := scanFirebaseConfig(content1, "google-services.json"); findings != nil {
		t.Errorf("expected nil when project_info missing, got %v", findings)
	}

	// Missing "mobilesdk_app_id"
	content2 := `{"project_info": {"project_id": "test"}}`
	if findings := scanFirebaseConfig(content2, "google-services.json"); findings != nil {
		t.Errorf("expected nil when mobilesdk_app_id missing, got %v", findings)
	}
}

func TestScanFirebaseConfig_InvalidJSON(t *testing.T) {
	content := `not valid json but has project_info and mobilesdk_app_id`
	findings := scanFirebaseConfig(content, "google-services.json")

	if findings != nil {
		t.Errorf("expected nil for invalid JSON, got %v", findings)
	}
}

// --- Test helpers ---

// createTestAPK creates a minimal APK with optional text files.
func createTestAPK(t *testing.T, files map[string]string) string {
	t.Helper()

	apkPath := filepath.Join(t.TempDir(), "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	// Always include AndroidManifest.xml.
	w, _ := zw.Create("AndroidManifest.xml")
	_, _ = w.Write([]byte{0x03, 0x00, 0x08, 0x00})

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}

		_, _ = w.Write([]byte(content))
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return apkPath
}
