/*
Copyright (c) 2026 Security Research

Package dpapidump enumerates Windows DPAPI master keys + Chromium-stored
DPAPI-wrapped secrets WITHOUT decrypting them. The dump is flag-only by
default per D-14 / D-18: we report *that* a secret is present, the
algorithm wrapper, and the ciphertext length, but never the plaintext.

Decryption lives in pkg/dpapi (build-tagged windows && cgo) and is
opt-in via a separate `--reveal-secret` flag in the CLI surface.

Phase 20.2.
*/
package dpapidump

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DumpOptions controls what to enumerate.
type DumpOptions struct {
	// MasterKeyRoots is the list of master-key directories to walk. If
	// empty, defaults to the per-user roots resolved from APPDATA.
	MasterKeyRoots []string

	// ChromiumProfiles is the list of Chromium profile directories to
	// inspect (each must contain a "Local State" + optionally a
	// "Default/Login Data" + "Default/Cookies"). If empty, no Chromium
	// walk runs.
	ChromiumProfiles []string

	// MaxFiles caps the number of master-key files reported per root
	// (default 256). Defends against runaway directories.
	MaxFiles int
}

// MasterKeyEntry is one master-key file with flag-only metadata.
type MasterKeyEntry struct {
	Path          string `json:"path"`
	GUID          string `json:"guid"` // filename basename — DPAPI uses GUID-named files
	Size          int64  `json:"size"`
	ModTime       string `json:"mod_time"`        // RFC3339
	LooksLikeBlob bool   `json:"looks_like_blob"` // header sanity: starts with a non-zero version uint32
}

// ChromiumEnvelope is a DPAPI-wrapped Chromium secret report. The
// EncryptedKey is the raw blob from Local State (Base64 still wrapped);
// callers that want plaintext must opt in via pkg/dpapi.
type ChromiumEnvelope struct {
	ProfilePath        string `json:"profile_path"`
	LocalStatePath     string `json:"local_state_path"`
	HasEncryptedKey    bool   `json:"has_encrypted_key"`
	EncryptedKeyB64Len int    `json:"encrypted_key_b64_len,omitempty"`
	EncryptedKeyPrefix string `json:"encrypted_key_prefix,omitempty"` // first 5 bytes hex — usually "DPAPI" sentinel "44504150" prefix
	CookiesPath        string `json:"cookies_path,omitempty"`         // present if file exists; no read
	CookiesSize        int64  `json:"cookies_size,omitempty"`
	LoginDataPath      string `json:"login_data_path,omitempty"`
	LoginDataSize      int64  `json:"login_data_size,omitempty"`
}

// Result is the top-level envelope.
type Result struct {
	GeneratedAt string             `json:"generated_at"`
	Platform    string             `json:"platform"`
	MasterKeys  []MasterKeyEntry   `json:"master_keys"`
	Chromium    []ChromiumEnvelope `json:"chromium"`
	Errors      []string           `json:"errors,omitempty"`
}

// Dump runs the enumeration. Pure-Go and cross-platform. On non-Windows
// hosts it still works against paths the caller supplies (useful for
// offline analysis of a copied profile), but no auto-resolve happens.
func Dump(opts DumpOptions) (*Result, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 256
	}

	res := &Result{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Platform:    runtime.GOOS,
		MasterKeys:  []MasterKeyEntry{},
		Chromium:    []ChromiumEnvelope{},
	}

	roots := opts.MasterKeyRoots
	if len(roots) == 0 {
		if runtime.GOOS == "windows" {
			if appdata := os.Getenv("APPDATA"); appdata != "" {
				roots = []string{filepath.Join(appdata, "Microsoft", "Protect")}
			}
		}
	}
	for _, root := range roots {
		entries, err := walkMasterKeys(root, opts.MaxFiles)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("master-key root %s: %v", root, err))
			continue
		}
		res.MasterKeys = append(res.MasterKeys, entries...)
	}

	for _, profile := range opts.ChromiumProfiles {
		env, err := inspectChromiumProfile(profile)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("chromium profile %s: %v", profile, err))
			continue
		}
		res.Chromium = append(res.Chromium, env)
	}

	return res, nil
}

func walkMasterKeys(root string, cap int) ([]MasterKeyEntry, error) {
	var out []MasterKeyEntry
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // best-effort: a SID we can't read is fine
		}
		if d.IsDir() {
			return nil
		}
		if len(out) >= cap {
			return filepath.SkipAll
		}
		name := d.Name()
		if !looksLikeGUIDName(name) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		header := readHeader(path, 16)
		entry := MasterKeyEntry{
			Path:          path,
			GUID:          name,
			Size:          info.Size(),
			ModTime:       info.ModTime().UTC().Format(time.RFC3339),
			LooksLikeBlob: looksLikeMKBlob(header),
		}
		out = append(out, entry)
		return nil
	})
	return out, err
}

// looksLikeGUIDName checks for a Windows DPAPI master-key filename:
// 8-4-4-4-12 hex with dashes (or a "Preferred"/"BK-..." sibling).
func looksLikeGUIDName(name string) bool {
	if len(name) == 36 {
		var n int
		for _, c := range name {
			switch {
			case c == '-':
				if n != 8 && n != 13 && n != 18 && n != 23 {
					return false
				}
			case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
				// ok
			default:
				return false
			}
			n++
		}
		return true
	}
	return false
}

// looksLikeMKBlob: first DWORD is the master-key version; in practice
// it's 1 or 2. Anything obviously zero/garbage is reported as "no".
func looksLikeMKBlob(h []byte) bool {
	if len(h) < 8 {
		return false
	}
	// Version is little-endian uint32 at offset 0.
	v := uint32(h[0]) | uint32(h[1])<<8 | uint32(h[2])<<16 | uint32(h[3])<<24
	return v == 1 || v == 2
}

func readHeader(path string, n int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	read, _ := f.Read(buf)
	return buf[:read]
}

func inspectChromiumProfile(profile string) (ChromiumEnvelope, error) {
	env := ChromiumEnvelope{ProfilePath: profile}
	lsPath := filepath.Join(profile, "Local State")
	env.LocalStatePath = lsPath

	data, err := os.ReadFile(lsPath)
	if err != nil {
		return env, fmt.Errorf("read Local State: %w", err)
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if jerr := json.Unmarshal(data, &ls); jerr == nil {
		ek := ls.OSCrypt.EncryptedKey
		env.HasEncryptedKey = ek != ""
		if env.HasEncryptedKey {
			env.EncryptedKeyB64Len = len(ek)
			raw, derr := base64.StdEncoding.DecodeString(ek)
			if derr == nil && len(raw) >= 5 {
				env.EncryptedKeyPrefix = hexBytes(raw[:5])
			}
		}
	}

	// Optional sibling files — report path + size only, never read.
	for sibling, dest := range map[string]*string{
		"Default/Cookies":    &env.CookiesPath,
		"Default/Login Data": &env.LoginDataPath,
	} {
		p := filepath.Join(profile, sibling)
		if info, statErr := os.Stat(p); statErr == nil {
			*dest = p
			if dest == &env.CookiesPath {
				env.CookiesSize = info.Size()
			} else {
				env.LoginDataSize = info.Size()
			}
		}
	}

	return env, nil
}

func hexBytes(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hex[c>>4], hex[c&0x0F])
	}
	return strings.ToUpper(string(out))
}
