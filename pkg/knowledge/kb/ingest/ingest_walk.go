/*
Copyright (c) 2026 Security Research

KS folder walker for the v2.5 ingest writer.

Walks a fingerprinted knowledge-source folder under the kb-store root
and produces a WalkResult bundle of module/body/file rows ready for
INSERT (multi-value <=100, pgx.CopyFrom otherwise — caller's choice).

Path-traversal mitigation (T-30-03-02): the supplied ksDir MUST resolve
under one of opts.AllowedRoots after filepath.Clean. Symbolic links are
skipped during walk to avoid escape via .lnk / symlink (T-30-03-02).

License: BSD-3-Clause.
*/

package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WalkOptions configure WalkKSFolder.
type WalkOptions struct {
	// AllowedRoots is the list of acceptable kb-store root prefixes.
	// ksDir must filepath.Clean under one of these. Empty list disables
	// the check (test convenience only — production ALWAYS sets at least
	// one root).
	AllowedRoots []string

	// RetainBodyBytes keeps the raw body content in memory inside each
	// ModuleBody row. Default false — we stream sha256 only.
	RetainBodyBytes bool

	// MaxFileSize caps individual file size for body retention. 0 means
	// no cap. When body exceeds this and RetainBodyBytes is true, we
	// silently fall back to digest-only for that file.
	MaxFileSize int64
}

// ModuleBody represents a deduplicated body row keyed by body_sha256.
type ModuleBody struct {
	BodySHA256 string `json:"body_sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	Lang       string `json:"lang,omitempty"`
	Body       []byte `json:"-"`
}

// ModuleRow represents a per-app module metadata row.
type ModuleRow struct {
	App        string `json:"app"`
	BodySHA256 string `json:"body_sha256"`
	Name       string `json:"name"`
	RelPath    string `json:"rel_path"`
	Lang       string `json:"lang,omitempty"`
}

// ModuleAppRef wires a module body to a kb_id for cross-app dedup.
type ModuleAppRef struct {
	App        string `json:"app"`
	BodySHA256 string `json:"body_sha256"`
	KBID       string `json:"kb_id"`
}

// FileRow represents a per-file inventory row keyed by file_sha256.
type FileRow struct {
	FileSHA256 string `json:"file_sha256"`
	RelPath    string `json:"rel_path"`
	SizeBytes  int64  `json:"size_bytes"`
}

// FileAppRef wires a file to a kb_id.
type FileAppRef struct {
	App        string `json:"app"`
	FileSHA256 string `json:"file_sha256"`
	KBID       string `json:"kb_id"`
}

// WalkResult is the batched output of WalkKSFolder.
type WalkResult struct {
	ModuleBodies  []ModuleBody
	Modules       []ModuleRow
	ModuleAppRefs []ModuleAppRef
	Files         []FileRow
	FileAppRefs   []FileAppRef
	BinarySHA256  string
	ModuleCount   int64
	BodyCount     int64
	FileCount     int64
}

// moduleExtensions enumerates the file extensions classified as
// "modules" (executable code). Everything else is classified as a
// data file recorded only in files / file_app_refs.
var moduleExtensions = map[string]string{
	".so":    "native",
	".dylib": "native",
	".dll":   "native",
	".exe":   "native",
	".js":    "javascript",
	".mjs":   "javascript",
	".cjs":   "javascript",
	".ts":    "typescript",
	".class": "java",
	".jar":   "java",
	".dex":   "android",
	".wasm":  "wasm",
	".py":    "python",
	".pyc":   "python",
}

// WalkKSFolder traverses ksDir and produces a WalkResult batched for
// INSERT. Streams body bytes via io.Copy + sha256 — never holds whole
// body unless opts.RetainBodyBytes is set.
//
// Path safety: filepath.Clean(ksDir) must be under one of
// opts.AllowedRoots; otherwise returns error containing
// "ks dir outside kb-store root" (T-30-03-02).
func WalkKSFolder(ctx context.Context, ksDir, kbID, app string, opts WalkOptions) (*WalkResult, error) {
	if ksDir == "" {
		return nil, errors.New("ksDir required")
	}
	if kbID == "" {
		return nil, errors.New("kbID required")
	}
	if app == "" {
		return nil, errors.New("app required")
	}

	cleaned := filepath.Clean(ksDir)
	if len(opts.AllowedRoots) > 0 {
		ok := false
		for _, root := range opts.AllowedRoots {
			rootClean := filepath.Clean(root)
			if cleaned == rootClean ||
				strings.HasPrefix(cleaned, rootClean+string(filepath.Separator)) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errors.New("ks dir outside kb-store root")
		}
	}

	st, err := os.Stat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("stat ksDir: %w", err)
	}
	if !st.IsDir() {
		return nil, errors.New("ksDir is not a directory")
	}

	res := &WalkResult{}
	bodySeen := map[string]struct{}{}
	fileSeen := map[string]struct{}{}

	walkErr := filepath.WalkDir(cleaned, func(path string, d fs.DirEntry, errIn error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errIn != nil {
			return errIn
		}
		if d.IsDir() {
			return nil
		}
		// T-30-03-02: skip symlinks to avoid escape.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		size := info.Size()

		rel, err := filepath.Rel(cleaned, path)
		if err != nil {
			return fmt.Errorf("rel path: %w", err)
		}
		rel = filepath.ToSlash(rel)

		sha, body, err := digestFile(path, opts)
		if err != nil {
			return fmt.Errorf("digest %s: %w", path, err)
		}

		// File-level inventory (every file).
		if _, dup := fileSeen[sha]; !dup {
			fileSeen[sha] = struct{}{}
			res.Files = append(res.Files, FileRow{
				FileSHA256: sha,
				RelPath:    rel,
				SizeBytes:  size,
			})
			res.FileAppRefs = append(res.FileAppRefs, FileAppRef{
				App:        app,
				FileSHA256: sha,
				KBID:       kbID,
			})
			res.FileCount++
		}

		// Module classification by extension.
		ext := strings.ToLower(filepath.Ext(rel))
		lang, isModule := moduleExtensions[ext]
		if isModule {
			if _, dup := bodySeen[sha]; !dup {
				bodySeen[sha] = struct{}{}
				mb := ModuleBody{
					BodySHA256: sha,
					SizeBytes:  size,
					Lang:       lang,
				}
				if opts.RetainBodyBytes {
					if opts.MaxFileSize == 0 || size <= opts.MaxFileSize {
						mb.Body = body
					}
				}
				res.ModuleBodies = append(res.ModuleBodies, mb)
				res.BodyCount++
			}
			res.Modules = append(res.Modules, ModuleRow{
				App:        app,
				BodySHA256: sha,
				Name:       filepath.Base(rel),
				RelPath:    rel,
				Lang:       lang,
			})
			res.ModuleAppRefs = append(res.ModuleAppRefs, ModuleAppRef{
				App:        app,
				BodySHA256: sha,
				KBID:       kbID,
			})
			res.ModuleCount++
		}

		// BinarySHA256 = first PE/ELF top-level binary file. We use the
		// first .exe / .so / .dylib / .dll / file named "binary" as the
		// surrogate. For ingest the caller may also pass a precomputed
		// digest; this walk-result value is best-effort.
		if res.BinarySHA256 == "" {
			base := strings.ToLower(filepath.Base(rel))
			if base == "binary" || ext == ".exe" || ext == ".so" ||
				ext == ".dylib" || ext == ".dll" {
				res.BinarySHA256 = sha
			}
		}

		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return res, nil
}

// digestFile streams the file at path into sha256 and (optionally) into
// memory when opts.RetainBodyBytes is true.
func digestFile(path string, opts WalkOptions) (string, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if opts.RetainBodyBytes {
		// Read fully — caller decided memory is acceptable.
		data, err := io.ReadAll(f)
		if err != nil {
			return "", nil, err
		}
		_, _ = h.Write(data)
		return hex.EncodeToString(h.Sum(nil)), data, nil
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(h.Sum(nil)), nil, nil
}
