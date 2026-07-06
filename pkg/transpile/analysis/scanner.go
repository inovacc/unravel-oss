package analysis

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
)

// cppExtensions is the set of file extensions treated as C/C++ source.
var cppExtensions = map[string]struct{}{
	".c":   {},
	".cpp": {},
	".cc":  {},
	".cxx": {},
	".c++": {},
	".h":   {},
	".hpp": {},
	".hxx": {},
}

// pyExtensions is the set of file extensions treated as Python source.
var pyExtensions = map[string]struct{}{
	".py": {},
}

// javaExtensions is the set of file extensions treated as Java source.
var javaExtensions = map[string]struct{}{
	".java": {},
}

// allExtensions is the union of all supported language extensions.
var allExtensions = func() map[string]struct{} {
	m := make(map[string]struct{}, len(cppExtensions)+len(pyExtensions)+len(javaExtensions))
	maps.Copy(m, cppExtensions)
	maps.Copy(m, pyExtensions)
	maps.Copy(m, javaExtensions)
	return m
}()

// defaultExcludeDirs are directory names skipped during scanning.
var defaultExcludeDirs = map[string]struct{}{
	".git":                {},
	".svn":                {},
	".hg":                 {},
	"build":               {},
	"cmake-build-debug":   {},
	"cmake-build-release": {},
	"node_modules":        {},
	"vendor":              {},
	"third_party":         {},
	"__pycache__":         {},
}

// SourceFile represents a discovered source file.
type SourceFile struct {
	Path     string `json:"path"`
	RelPath  string `json:"rel_path"`
	Size     int64  `json:"size"`
	Language string `json:"language"` // "C Source", "C++ Source", "C/C++ Header", "Python Source"
}

// Scanner discovers source files in a directory tree.
type Scanner struct {
	Root       string
	Extensions map[string]struct{}
	Exclude    map[string]struct{}
	MaxDepth   int // 0 means unlimited
}

// NewScanner creates a scanner with default settings.
// It scans for all supported languages (C/C++ and Python).
func NewScanner(root string) *Scanner {
	return &Scanner{
		Root:       root,
		Extensions: allExtensions,
		Exclude:    defaultExcludeDirs,
	}
}

// Scan walks the source tree and returns all matching source files.
func (s *Scanner) Scan() ([]*SourceFile, error) {
	var files []*SourceFile

	rootDepth := strings.Count(filepath.ToSlash(s.Root), "/")

	err := filepath.WalkDir(s.Root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()

			// Skip hidden directories and excluded names
			if name != "." && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}

			if _, ok := s.Exclude[name]; ok {
				return filepath.SkipDir
			}

			// Skip cmake-build-* pattern
			if strings.HasPrefix(name, "cmake-build-") {
				return filepath.SkipDir
			}

			// Enforce max depth
			if s.MaxDepth > 0 {
				currentDepth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
				if currentDepth >= s.MaxDepth {
					return filepath.SkipDir
				}
			}

			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := s.Extensions[ext]; !ok {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil // skip files we can't stat
		}

		relPath, err := filepath.Rel(s.Root, path)
		if err != nil {
			relPath = path
		}

		sf := &SourceFile{
			Path:     path,
			RelPath:  filepath.ToSlash(relPath),
			Size:     info.Size(),
			Language: classifyLanguage(ext),
		}

		files = append(files, sf)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// classifyLanguage returns a human-readable language label for a file extension.
func classifyLanguage(ext string) string {
	switch ext {
	case ".py":
		return "Python Source"
	case ".java":
		return "Java Source"
	case ".h":
		return "C/C++ Header"
	case ".hpp", ".hxx":
		return "C++ Header"
	case ".c":
		return "C Source"
	default:
		return "C++ Source"
	}
}

// IsPython returns true if the source file is a Python file.
func IsPython(f *SourceFile) bool {
	return f.Language == "Python Source"
}

// IsJava returns true if the source file is a Java file.
func IsJava(f *SourceFile) bool {
	return f.Language == "Java Source"
}

// IsCpp returns true if the source file is a C or C++ file.
func IsCpp(f *SourceFile) bool {
	return f.Language != "Python Source" && f.Language != "Java Source"
}
