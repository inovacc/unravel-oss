/*
Copyright (c) 2026 Security Research
*/
package reconstruct

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Content-analysis patterns for language detection (primary signal).
var (
	javaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`package\s+[\w.]+;`),
		regexp.MustCompile(`import\s+java\.`),
		regexp.MustCompile(`public\s+class\s+\w+`),
	}

	jsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`require\(`),
		regexp.MustCompile(`import\s+.*from\s+`),
		regexp.MustCompile(`export\s+(default\s+)?`),
		regexp.MustCompile(`module\.exports`),
	}

	tsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`:\s*(string|number|boolean|any|void)\b`),
		regexp.MustCompile(`interface\s+\w+\s*\{`),
		regexp.MustCompile(`<[A-Z]\w*>`),
	}

	csharpPatterns = []*regexp.Regexp{
		regexp.MustCompile(`using\s+System`),
		regexp.MustCompile(`namespace\s+\w+`),
		regexp.MustCompile(`public\s+(class|struct|interface)\s+\w+`),
	}

	goPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?m)^package\s+\w+`),
		regexp.MustCompile(`func\s+\w+`),
	}

	pythonPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?m)^(import|from)\s+\w+`),
		regexp.MustCompile(`def\s+\w+\(`),
		regexp.MustCompile(`class\s+\w+:`),
	}
)

// extensionMap maps file extensions to languages (fallback signal).
var extensionMap = map[string]Language{
	".java": LangJava,
	".js":   LangJavaScript,
	".mjs":  LangJavaScript,
	".cjs":  LangJavaScript,
	".ts":   LangTypeScript,
	".tsx":  LangTypeScript,
	".cs":   LangCSharp,
	".go":   LangGo,
	".py":   LangPython,
	".pyw":  LangPython,
}

// DetectLanguage identifies the programming language of source content.
// Primary detection uses content analysis (regex patterns). If inconclusive,
// file extension is used as fallback. Content always takes precedence (D-21).
func DetectLanguage(content string, ext string) Language {
	// Score each language by pattern matches in content.
	type scored struct {
		lang  Language
		score int
	}

	candidates := []scored{
		{LangJava, countMatches(content, javaPatterns)},
		{LangCSharp, countMatches(content, csharpPatterns)},
		{LangGo, countMatches(content, goPatterns)},
		{LangPython, countMatches(content, pythonPatterns)},
	}

	// JS vs TS: score JS first, then check for TS-specific patterns.
	jsScore := countMatches(content, jsPatterns)
	tsScore := countMatches(content, tsPatterns)

	if tsScore > 0 && jsScore > 0 {
		candidates = append(candidates, scored{LangTypeScript, jsScore + tsScore})
	} else if jsScore > 0 {
		candidates = append(candidates, scored{LangJavaScript, jsScore})
	}

	// Pick highest scoring language with at least 1 match.
	best := scored{LangUnknown, 0}
	for _, c := range candidates {
		if c.score > best.score {
			best = c
		}
	}

	if best.score > 0 {
		return best.lang
	}

	// Fallback to extension.
	if ext != "" {
		normalized := strings.ToLower(ext)
		if !strings.HasPrefix(normalized, ".") {
			normalized = "." + normalized
		}
		if lang, ok := extensionMap[normalized]; ok {
			return lang
		}
	}

	return LangUnknown
}

// DetectLanguageFromPath detects language using both content and file path.
func DetectLanguageFromPath(content string, path string) Language {
	ext := filepath.Ext(path)
	return DetectLanguage(content, ext)
}

func countMatches(content string, patterns []*regexp.Regexp) int {
	count := 0
	for _, p := range patterns {
		if p.MatchString(content) {
			count++
		}
	}
	return count
}
