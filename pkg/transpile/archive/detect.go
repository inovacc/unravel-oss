package archive

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// zipMagic is the ZIP local file header signature (PK\x03\x04).
var zipMagic = []byte{0x50, 0x4B, 0x03, 0x04}

// IsArchive checks whether the given path looks like a Java archive based on
// its magic bytes and file extension.
func IsArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".jar" && ext != ".war" && ext != ".ear" {
		return false
	}

	return hasZipMagic(path)
}

// DetectType determines the archive type from its file extension and internal
// structure. It reads magic bytes first, then classifies by extension. If the
// extension is ambiguous (.jar), it peeks inside the archive for WEB-INF/web.xml
// (WAR) or META-INF/application.xml (EAR).
func DetectType(path string) ArchiveType {
	if !hasZipMagic(path) {
		return ArchiveUnknown
	}

	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".war":
		return ArchiveWAR
	case ".ear":
		return ArchiveEAR
	case ".jar":
		// Peek inside to disambiguate
		return classifyJAR(path)
	default:
		return ArchiveUnknown
	}
}

// hasZipMagic reads the first 4 bytes of the file and checks for the ZIP
// local file header signature.
func hasZipMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	header := make([]byte, 4)

	n, err := io.ReadFull(f, header)
	if err != nil || n < 4 {
		return false
	}

	return header[0] == zipMagic[0] &&
		header[1] == zipMagic[1] &&
		header[2] == zipMagic[2] &&
		header[3] == zipMagic[3]
}

// classifyJAR peeks inside a JAR to see if it's actually a WAR or EAR.
func classifyJAR(path string) ArchiveType {
	r, err := zip.OpenReader(path)
	if err != nil {
		return ArchiveUnknown
	}

	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		name := filepath.ToSlash(f.Name)
		switch {
		case name == "WEB-INF/web.xml" || strings.HasPrefix(name, "WEB-INF/"):
			return ArchiveWAR
		case name == "META-INF/application.xml":
			return ArchiveEAR
		}
	}

	return ArchiveJAR
}
