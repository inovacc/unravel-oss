package npm

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Decompression-bomb guards for tarball extraction. These are vars (not
// consts) so tests can shrink them without crafting gigabyte inputs. Defaults
// are generous: legitimate npm packages are far under these bounds.
var (
	// maxDownloadBytes caps the total DECOMPRESSED bytes pulled from the gzip
	// stream (counted across file bodies AND bytes the tar reader skips), to
	// defend against gzip/tar decompression bombs.
	maxDownloadBytes int64 = 1 << 30 // 1 GiB

	// maxCompressedBytes caps the COMPRESSED input read from the source. npm
	// tarballs are well under this; it bounds worst-case inflate work.
	maxCompressedBytes int64 = 256 << 20 // 256 MiB

	// maxTarEntries caps the number of tar headers processed regardless of
	// typeflag, defeating inode/syscall floods of many tiny entries.
	maxTarEntries = 50_000
)

// countingReader counts every byte produced by the wrapped reader, so bytes
// the tar reader inflates while SKIPPING entries are accounted, not just bytes
// copied into output files.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// DownloadResult holds information about a downloaded and extracted package.
type DownloadResult struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	OutputDir string `json:"output_dir"`
	Files     int    `json:"files"`
	Size      int64  `json:"size"`
}

// Download fetches the tarball for a package version and extracts to outDir.
// If version is empty, the latest version is used.
func Download(name, version, outDir string) (*DownloadResult, error) {
	pv, err := FetchVersion(name, version)
	if err != nil {
		return nil, fmt.Errorf("fetching version info: %w", err)
	}

	if pv.Dist.Tarball == "" {
		return nil, fmt.Errorf("no tarball URL for %s@%s", name, pv.Version)
	}

	// SSRF guard: the tarball URL comes from registry JSON. Only allow it
	// if its host matches the configured registry host.
	allowedHost, err := registryHost()
	if err != nil {
		return nil, err
	}
	tarballURL, err := url.Parse(pv.Dist.Tarball)
	if err != nil {
		return nil, fmt.Errorf("invalid tarball URL: %w", err)
	}
	if !hostAllowed(tarballURL.Hostname(), allowedHost) {
		return nil, fmt.Errorf("tarball host %q not in registry allowlist", tarballURL.Hostname())
	}

	client := &http.Client{
		Timeout: 60 * time.Second,
		// Reject redirects that leave the allowed host (another SSRF vector).
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if !hostAllowed(req.URL.Hostname(), allowedHost) {
				return fmt.Errorf("redirect to disallowed host %q", req.URL.Hostname())
			}
			return nil
		},
	}
	resp, err := client.Get(pv.Dist.Tarball)
	if err != nil {
		return nil, fmt.Errorf("downloading tarball: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tarball download returned status %d", resp.StatusCode)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	files, size, err := extractTarGz(resp.Body, outDir)
	if err != nil {
		return nil, fmt.Errorf("extracting tarball: %w", err)
	}

	return &DownloadResult{
		Package:   name,
		Version:   pv.Version,
		OutputDir: outDir,
		Files:     files,
		Size:      size,
	}, nil
}

// registryHost returns the hostname of the configured npm registry.
func registryHost() (string, error) {
	u, err := url.Parse(registryURL)
	if err != nil {
		return "", fmt.Errorf("parsing registry URL: %w", err)
	}
	return u.Hostname(), nil
}

// hostAllowed reports whether host matches the allowed registry host.
// A subdomain of the registry host is also permitted (npm serves
// tarballs from registry.npmjs.org, the same host as metadata).
func hostAllowed(host, allowed string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	allowed = strings.ToLower(allowed)
	if host == "" || allowed == "" {
		return false
	}
	return host == allowed || strings.HasSuffix(host, "."+allowed)
}

// extractTarGz decompresses a gzip stream and extracts the tar archive.
// It strips the leading "package/" prefix that npm tarballs always include.
// Reads are bounded by maxDownloadBytes to defend against decompression bombs.
func extractTarGz(r io.Reader, outDir string) (int, int64, error) {
	// Cap total bytes read from the (compressed) source as a coarse first
	// line of defence, then cap decompressed output below.
	limited := io.LimitReader(r, maxCompressedBytes)
	// counted wraps the gzip output so EVERY decompressed byte is accounted —
	// including bytes the tar reader inflates while skipping non-regular or
	// unknown-typeflag entries, which io.Copy on file bodies alone would miss.
	gzr, err := gzip.NewReader(limited)
	if err != nil {
		return 0, 0, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()
	counted := &countingReader{r: gzr}

	// budget tracks remaining decompressed bytes allowed across all entries.
	budget := maxDownloadBytes
	tr := tar.NewReader(counted)
	var fileCount int
	var totalSize int64
	var entryCount int

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fileCount, totalSize, fmt.Errorf("reading tar entry: %w", err)
		}

		// SEC: bound the number of headers processed regardless of typeflag.
		// A flood of tiny entries (highly gzip-compressible) would otherwise
		// drive unbounded mkdir/create syscalls and inode exhaustion.
		entryCount++
		if entryCount > maxTarEntries {
			return fileCount, totalSize, fmt.Errorf("tar entry count exceeds %d", maxTarEntries)
		}

		// SEC: every tr.Next() may have inflated bytes (e.g. skipping an
		// unknown-typeflag entry's declared body). Check the unified counter
		// so a high-ratio stream cannot burn unbounded inflate CPU.
		if counted.n > maxDownloadBytes {
			return fileCount, totalSize, fmt.Errorf("decompressed size exceeds %d byte budget", maxDownloadBytes)
		}

		// Strip the "package/" prefix from paths
		entryName := hdr.Name
		if idx := strings.Index(entryName, "/"); idx >= 0 {
			entryName = entryName[idx+1:]
		}
		if entryName == "" {
			continue
		}

		target := filepath.Join(outDir, filepath.FromSlash(entryName))

		// Prevent zip-slip path traversal. A prefix check without a
		// separator is unsafe ("outDir-evil" passes); use filepath.Rel
		// and reject any result that climbs out of outDir.
		rel, err := filepath.Rel(outDir, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fileCount, totalSize, fmt.Errorf("creating directory %s: %w", target, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fileCount, totalSize, fmt.Errorf("creating parent directory: %w", err)
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o755)
			if err != nil {
				return fileCount, totalSize, fmt.Errorf("creating file %s: %w", target, err)
			}

			// Bound the copy to the remaining decompressed budget (+1 so
			// we can detect when an entry would exceed it).
			n, err := io.Copy(f, io.LimitReader(tr, budget+1))
			_ = f.Close()
			if err != nil {
				return fileCount, totalSize, fmt.Errorf("writing file %s: %w", target, err)
			}
			if n > budget {
				return fileCount, totalSize, fmt.Errorf("decompressed size exceeds %d byte budget", maxDownloadBytes)
			}
			budget -= n

			fileCount++
			totalSize += n

		default:
			// SEC: reject unknown/unsupported typeflags. archive/tar will not
			// skip an unknown type's body for us at the next call without
			// inflating it, and only TypeReg/TypeDir are meaningful for npm
			// tarballs. Aborting avoids unbounded inflate of a hostile body.
			return fileCount, totalSize, fmt.Errorf("unsupported tar entry type %q for %s", hdr.Typeflag, entryName)
		}
	}

	return fileCount, totalSize, nil
}
