package archive

import (
	"bufio"
	"bytes"
	"strings"
)

// ManifestInfo holds parsed data from META-INF/MANIFEST.MF.
type ManifestInfo struct {
	MainClass             string            `json:"main_class,omitempty"`
	ClassPath             []string          `json:"class_path,omitempty"`
	ImplementationVersion string            `json:"implementation_version,omitempty"`
	ImplementationTitle   string            `json:"implementation_title,omitempty"`
	Entries               map[string]string `json:"entries"`
}

// ParseManifest parses a MANIFEST.MF file into ManifestInfo.
// It handles continuation lines (lines starting with a single space)
// and blank-line separated sections.
func ParseManifest(data []byte) (*ManifestInfo, error) {
	info := &ManifestInfo{
		Entries: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	var (
		currentKey   string
		currentValue strings.Builder
	)

	flush := func() {
		if currentKey == "" {
			return
		}

		val := strings.TrimSpace(currentValue.String())
		info.Entries[currentKey] = val

		switch strings.ToLower(currentKey) {
		case "main-class":
			info.MainClass = val
		case "class-path":
			info.ClassPath = splitClassPath(val)
		case "implementation-version":
			info.ImplementationVersion = val
		case "implementation-title":
			info.ImplementationTitle = val
		}

		currentKey = ""

		currentValue.Reset()
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Blank line separates sections
		if line == "" {
			flush()
			continue
		}

		// Continuation line (starts with single space)
		if strings.HasPrefix(line, " ") && currentKey != "" {
			currentValue.WriteString(strings.TrimPrefix(line, " "))
			continue
		}

		// New key-value pair
		flush()

		before, after, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		currentKey = strings.TrimSpace(before)
		// Preserve trailing whitespace in value for continuation line support.
		// Leading space after ':' is trimmed per spec.
		v := after
		if len(v) > 0 && v[0] == ' ' {
			v = v[1:]
		}

		currentValue.WriteString(v)
	}

	flush()

	return info, scanner.Err()
}

// splitClassPath splits a Class-Path value into individual entries.
func splitClassPath(cp string) []string {
	parts := strings.Fields(cp)

	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}

	return result
}
