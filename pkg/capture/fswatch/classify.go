package fswatch

import (
	"path/filepath"
	"strings"
)

// Category classifies a file path into a storage category.
func Category(path string) string {
	base := filepath.Base(path)
	dir := filepath.Dir(path)

	switch {
	case strings.Contains(dir, "Local Storage"):
		return "localstorage"
	case strings.Contains(dir, "leveldb") || strings.HasSuffix(base, ".ldb") || strings.HasSuffix(base, ".log"):
		if strings.Contains(dir, "leveldb") {
			return "leveldb"
		}
	case base == "Cookies" || base == "Cookies-journal":
		return "cookies"
	case base == "Preferences" || base == "Secure Preferences":
		return "preferences"
	case strings.HasSuffix(base, ".sqlite") || strings.HasSuffix(base, ".db"):
		return "sqlite"
	}

	return "unknown"
}
