package reconstruct

import (
	"fmt"
	"go/parser"
	"go/token"
	"math"
	"regexp"
	"strings"
)

// VerificationResult holds the outcome of all 4 verification checks.
type VerificationResult struct {
	Passed           bool
	SyntaxValid      bool
	SymbolsPreserved bool
	ASTSimilarity    float64 // 0.0-1.0
	LineDelta        float64 // fractional change (positive = growth)
	RetryRecommended bool
	Failures         []string
}

// Verify runs 4 verification checks on reconstructed code against the original.
//
// Checks:
//  1. Syntax validity (Go: go/parser; others: brace balance)
//  2. Symbol preservation (exported/public names must appear in reconstructed)
//  3. AST similarity (structural token Jaccard similarity > 0.6)
//  4. Line count sanity (|delta| < 0.5)
//
// RetryRecommended = !Passed AND SyntaxValid (syntax errors are not retryable).
func Verify(original, reconstructed string, lang Language) VerificationResult {
	var res VerificationResult
	var failures []string

	// Check 1: Syntax validity
	res.SyntaxValid = checkSyntax(reconstructed, lang)
	if !res.SyntaxValid {
		failures = append(failures, "syntax: invalid")
	}

	// Check 2: Symbol preservation
	res.SymbolsPreserved = checkSymbols(original, reconstructed, lang)
	if !res.SymbolsPreserved {
		failures = append(failures, "symbols: missing exported symbols")
	}

	// Check 3: AST similarity
	res.ASTSimilarity = computeASTSimilarity(original, reconstructed, lang)
	if res.ASTSimilarity <= 0.6 {
		failures = append(failures, fmt.Sprintf("ast-similarity: %.2f <= 0.6", res.ASTSimilarity))
	}

	// Check 4: Line count sanity
	res.LineDelta = computeLineDelta(original, reconstructed)
	if math.Abs(res.LineDelta) > 0.5 {
		failures = append(failures, fmt.Sprintf("line-delta: %.2f exceeds 50%%", res.LineDelta))
	}

	res.Failures = failures
	res.Passed = len(failures) == 0

	// Retry recommended only when syntax is valid but other checks fail (per D-16).
	res.RetryRecommended = !res.Passed && res.SyntaxValid

	return res
}

// checkSyntax validates syntax. For Go, uses go/parser. For others, brace balance.
func checkSyntax(code string, lang Language) bool {
	if lang == LangGo {
		fset := token.NewFileSet()
		_, err := parser.ParseFile(fset, "check.go", code, parser.AllErrors)
		return err == nil
	}

	// For Java/C#/JS/unknown: brace balance
	return checkBraceBalance(code)
}

// checkBraceBalance checks that {}, (), [] are balanced, respecting strings.
func checkBraceBalance(code string) bool {
	var stack []rune
	inString := false
	var stringChar rune
	escaped := false

	for _, ch := range code {
		if escaped {
			escaped = false
			continue
		}

		if ch == '\\' && inString {
			escaped = true
			continue
		}

		if inString {
			if ch == stringChar {
				inString = false
			}
			continue
		}

		if ch == '"' || ch == '\'' || ch == '`' {
			inString = true
			stringChar = ch
			continue
		}

		switch ch {
		case '{', '(', '[':
			stack = append(stack, ch)
		case '}':
			if len(stack) == 0 || stack[len(stack)-1] != '{' {
				return false
			}
			stack = stack[:len(stack)-1]
		case ')':
			if len(stack) == 0 || stack[len(stack)-1] != '(' {
				return false
			}
			stack = stack[:len(stack)-1]
		case ']':
			if len(stack) == 0 || stack[len(stack)-1] != '[' {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}

	return len(stack) == 0
}

// checkSymbols verifies that all exported/public symbols from original appear in reconstructed.
func checkSymbols(original, reconstructed string, lang Language) bool {
	symbols := extractSymbols(original, lang)
	if len(symbols) == 0 {
		return true // no symbols to check
	}

	for _, sym := range symbols {
		if !strings.Contains(reconstructed, sym) {
			return false
		}
	}

	return true
}

// extractSymbols extracts exported/public symbol names from code.
func extractSymbols(code string, lang Language) []string {
	var patterns []*regexp.Regexp

	switch lang {
	case LangJava:
		patterns = []*regexp.Regexp{
			regexp.MustCompile(`(?:public|protected)\s+(?:static\s+)?(?:final\s+)?(?:\w+\s+)?(\w+)\s*\(`),
			regexp.MustCompile(`(?:public|protected)\s+class\s+(\w+)`),
			regexp.MustCompile(`(?:public|protected)\s+interface\s+(\w+)`),
		}
	case LangJavaScript:
		patterns = []*regexp.Regexp{
			regexp.MustCompile(`export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)`),
			regexp.MustCompile(`module\.exports\s*=\s*(\w+)`),
		}
	case LangGo:
		patterns = []*regexp.Regexp{
			regexp.MustCompile(`func\s+([A-Z]\w*)`),
			regexp.MustCompile(`type\s+([A-Z]\w*)`),
		}
	case LangCSharp:
		patterns = []*regexp.Regexp{
			regexp.MustCompile(`(?:public|protected)\s+(?:static\s+)?(?:async\s+)?(?:\w+\s+)?(\w+)\s*\(`),
			regexp.MustCompile(`(?:public|protected)\s+class\s+(\w+)`),
		}
	case LangPython:
		patterns = []*regexp.Regexp{
			regexp.MustCompile(`def\s+([a-zA-Z]\w*)\s*\(`),
			regexp.MustCompile(`class\s+([a-zA-Z]\w*)`),
		}
	default:
		return nil
	}

	seen := make(map[string]bool)
	var symbols []string

	for _, pat := range patterns {
		matches := pat.FindAllStringSubmatch(code, -1)
		for _, m := range matches {
			if len(m) > 1 && !seen[m[1]] {
				seen[m[1]] = true
				symbols = append(symbols, m[1])
			}
		}
	}

	return symbols
}

// computeASTSimilarity computes Jaccard similarity of structural tokens between
// original and reconstructed code. This is a heuristic structural comparison.
func computeASTSimilarity(original, reconstructed string, lang Language) float64 {
	origTokens := extractStructuralTokens(original, lang)
	reconTokens := extractStructuralTokens(reconstructed, lang)

	if len(origTokens) == 0 && len(reconTokens) == 0 {
		return 1.0
	}

	if len(origTokens) == 0 || len(reconTokens) == 0 {
		return 0.0
	}

	// Multiset Jaccard: min(a,b) / max(a,b) per token type.
	origCounts := countTokens(origTokens)
	reconCounts := countTokens(reconTokens)

	allTokens := make(map[string]bool)
	for k := range origCounts {
		allTokens[k] = true
	}
	for k := range reconCounts {
		allTokens[k] = true
	}

	var intersection, union float64
	for tok := range allTokens {
		a := float64(origCounts[tok])
		b := float64(reconCounts[tok])
		intersection += math.Min(a, b)
		union += math.Max(a, b)
	}

	if union == 0 {
		return 1.0
	}

	return intersection / union
}

// extractStructuralTokens extracts language-specific structural keywords and
// brace nesting patterns as tokens for similarity comparison.
func extractStructuralTokens(code string, lang Language) []string {
	var keywords []string

	switch lang {
	case LangJava, LangCSharp:
		keywords = []string{"class", "interface", "enum", "public", "private", "protected",
			"static", "void", "if", "else", "for", "while", "switch", "case",
			"return", "try", "catch", "finally", "throw", "new", "import"}
	case LangJavaScript:
		keywords = []string{"function", "class", "const", "let", "var", "if", "else",
			"for", "while", "switch", "case", "return", "try", "catch", "finally",
			"throw", "new", "import", "export", "async", "await"}
	case LangGo:
		keywords = []string{"func", "type", "struct", "interface", "if", "else",
			"for", "switch", "case", "return", "go", "defer", "select",
			"chan", "map", "range", "import", "package"}
	case LangPython:
		keywords = []string{"def", "class", "if", "elif", "else", "for", "while",
			"try", "except", "finally", "return", "import", "from", "with",
			"async", "await", "raise", "yield"}
	default:
		keywords = []string{"if", "else", "for", "while", "switch", "case",
			"return", "function", "class"}
	}

	var tokens []string

	for _, kw := range keywords {
		pat := regexp.MustCompile(`\b` + regexp.QuoteMeta(kw) + `\b`)
		matches := pat.FindAllString(code, -1)
		for range matches {
			tokens = append(tokens, kw)
		}
	}

	// Brace depth transitions as structural markers.
	tokens = append(tokens, extractBracePatterns(code)...)

	return tokens
}

// extractBracePatterns extracts brace nesting patterns as structural tokens.
func extractBracePatterns(code string) []string {
	var tokens []string
	depth := 0

	for _, ch := range code {
		switch ch {
		case '{':
			depth++
			tokens = append(tokens, fmt.Sprintf("open@%d", depth))
		case '}':
			tokens = append(tokens, fmt.Sprintf("close@%d", depth))
			if depth > 0 {
				depth--
			}
		}
	}

	return tokens
}

// countTokens counts occurrences of each token.
func countTokens(tokens []string) map[string]int {
	counts := make(map[string]int)
	for _, t := range tokens {
		counts[t]++
	}
	return counts
}

// computeLineDelta computes the fractional line count change between original
// and reconstructed code. Positive = growth, negative = shrinkage.
func computeLineDelta(original, reconstructed string) float64 {
	origLines := countLines(original)
	reconLines := countLines(reconstructed)

	if origLines == 0 {
		if reconLines == 0 {
			return 0
		}
		return 1.0
	}

	return float64(reconLines-origLines) / float64(origLines)
}

// countLines counts non-empty lines in code.
func countLines(code string) int {
	lines := strings.Split(code, "\n")
	count := 0

	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			count++
		}
	}

	return count
}
