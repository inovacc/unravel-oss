//go:build windows && cgo

// Package dpapi decrypts Windows DPAPI-protected Chromium data.
// Only works on Windows for the current user's data. Requires CGO for SQLite.
package dpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	_ "modernc.org/sqlite"
)

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

// DATA_BLOB structure for DPAPI.
type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

type localState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

// DecryptedCookie represents a single decrypted cookie.
type DecryptedCookie struct {
	Host        string `json:"host"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Path        string `json:"path"`
	ExpiresUTC  string `json:"expires_utc"`
	IsSecure    bool   `json:"is_secure"`
	IsHTTPOnly  bool   `json:"is_httponly"`
	CreationUTC string `json:"creation_utc"`
}

// DecryptedPassword represents a single decrypted password.
type DecryptedPassword struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// DecryptionResult holds the complete decryption result.
type DecryptionResult struct {
	AppName     string              `json:"app_name"`
	SourcePath  string              `json:"source_path"`
	DecryptedAt string              `json:"decrypted_at"`
	MasterKey   string              `json:"master_key_hex"`
	Cookies     []DecryptedCookie   `json:"cookies,omitempty"`
	Passwords   []DecryptedPassword `json:"passwords,omitempty"`
	Errors      []string            `json:"errors,omitempty"`
}

// ExtractMasterKey reads and decrypts the master key from the Local State file.
func ExtractMasterKey(profilePath string) ([]byte, error) {
	localStatePath := filepath.Join(profilePath, "Local State")

	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %w", err)
	}

	var ls localState
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %w", err)
	}

	if ls.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key found in Local State")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode encrypted key: %w", err)
	}

	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil, fmt.Errorf("invalid encrypted key format (missing DPAPI prefix)")
	}

	encryptedKey = encryptedKey[5:]

	return decryptDPAPI(encryptedKey)
}

func decryptDPAPI(data []byte) ([]byte, error) {
	var outBlob DATA_BLOB

	inBlob := DATA_BLOB{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}

	ret, _, err := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	localFree := kernel32.NewProc("LocalFree")
	_, _, _ = localFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	return decrypted, nil
}

// DecryptCookies decrypts all cookies from the profile.
func DecryptCookies(profilePath string, masterKey []byte) ([]DecryptedCookie, []string) {
	var (
		cookies []DecryptedCookie
		errors  []string
	)

	cookiePaths := []string{
		filepath.Join(profilePath, "Network", "Cookies"),
		filepath.Join(profilePath, "Cookies"),
	}

	var cookiesPath string

	for _, path := range cookiePaths {
		if _, err := os.Stat(path); err == nil {
			cookiesPath = path
			break
		}
	}

	if cookiesPath == "" {
		errors = append(errors, "Cookies database not found")
		return cookies, errors
	}

	tempDB := filepath.Join(os.TempDir(), "cookies_temp.db")
	if err := copyFile(cookiesPath, tempDB); err != nil {
		errors = append(errors, fmt.Sprintf("Failed to copy cookies database: %v", err))
		return cookies, errors
	}

	defer func() { _ = os.Remove(tempDB) }()

	db, err := sql.Open("sqlite", tempDB+"?mode=ro")
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to open cookies database: %v", err))
		return cookies, errors
	}

	defer func() { _ = db.Close() }()

	rows, err := db.Query(`
		SELECT host_key, name, encrypted_value, path, expires_utc,
		       is_secure, is_httponly, creation_utc
		FROM cookies
	`)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to query cookies: %v", err))
		return cookies, errors
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			host, name, path        string
			encryptedValue          []byte
			expiresUTC, creationUTC int64
			isSecure, isHTTPOnly    int
		)

		err := rows.Scan(&host, &name, &encryptedValue, &path, &expiresUTC,
			&isSecure, &isHTTPOnly, &creationUTC)
		if err != nil {
			continue
		}

		decryptedValue, err := decryptChromiumValue(encryptedValue, masterKey)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to decrypt cookie %s@%s: %v", name, host, err))
			continue
		}

		cookies = append(cookies, DecryptedCookie{
			Host:        host,
			Name:        name,
			Value:       decryptedValue,
			Path:        path,
			ExpiresUTC:  chromiumTimeToString(expiresUTC),
			IsSecure:    isSecure == 1,
			IsHTTPOnly:  isHTTPOnly == 1,
			CreationUTC: chromiumTimeToString(creationUTC),
		})
	}

	return cookies, errors
}

// DecryptPasswords decrypts saved passwords from Login Data.
func DecryptPasswords(profilePath string, masterKey []byte) ([]DecryptedPassword, []string) {
	var (
		passwords []DecryptedPassword
		errors    []string
	)

	loginDataPath := filepath.Join(profilePath, "Login Data")
	if _, err := os.Stat(loginDataPath); os.IsNotExist(err) {
		errors = append(errors, "Login Data database not found")
		return passwords, errors
	}

	tempDB := filepath.Join(os.TempDir(), "login_data_temp.db")
	if err := copyFile(loginDataPath, tempDB); err != nil {
		errors = append(errors, fmt.Sprintf("Failed to copy Login Data: %v", err))
		return passwords, errors
	}

	defer func() { _ = os.Remove(tempDB) }()

	db, err := sql.Open("sqlite", tempDB+"?mode=ro")
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to open Login Data: %v", err))
		return passwords, errors
	}

	defer func() { _ = db.Close() }()

	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to query passwords: %v", err))
		return passwords, errors
	}

	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			url, username     string
			encryptedPassword []byte
		)

		if err := rows.Scan(&url, &username, &encryptedPassword); err != nil {
			continue
		}

		decryptedPassword, err := decryptChromiumValue(encryptedPassword, masterKey)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to decrypt password for %s: %v", url, err))
			continue
		}

		passwords = append(passwords, DecryptedPassword{
			URL:      url,
			Username: username,
			Password: decryptedPassword,
		})
	}

	return passwords, errors
}

func decryptChromiumValue(encryptedValue []byte, masterKey []byte) (string, error) {
	if len(encryptedValue) < 3 {
		return "", fmt.Errorf("encrypted value too short")
	}

	if string(encryptedValue[:3]) == "v10" || string(encryptedValue[:3]) == "v11" {
		return decryptAESGCM(encryptedValue[3:], masterKey)
	}

	decrypted, err := decryptDPAPI(encryptedValue)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func decryptAESGCM(encryptedData []byte, key []byte) (string, error) {
	if len(encryptedData) < 12+16 {
		return "", fmt.Errorf("encrypted data too short for AES-GCM")
	}

	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return string(plaintext), nil
}

func chromiumTimeToString(chromiumTime int64) string {
	if chromiumTime == 0 {
		return "never"
	}

	const chromiumEpochOffset = 11644473600000000

	unixMicro := chromiumTime - chromiumEpochOffset
	if unixMicro < 0 {
		return "invalid"
	}

	t := time.UnixMicro(unixMicro)

	return t.UTC().Format(time.RFC3339)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0600)
}
