/*
Copyright © 2026 Security Research
*/
package dotnet

import (
	"regexp"
	"strings"
	"unicode"
)

// FilteredStrings holds the result of .NET-specific string filtering.
type FilteredStrings struct {
	Namespaces  []string `json:"namespaces,omitempty"`  // System.*, Microsoft.*, etc.
	ClassNames  []string `json:"class_names,omitempty"` // PascalCase identifiers
	URLs        []string `json:"urls,omitempty"`        // http://, https://
	ConfigKeys  []string `json:"config_keys,omitempty"` // key=value patterns, JSON keys
	SQLQueries  []string `json:"sql_queries,omitempty"` // SELECT, INSERT, etc.
	FilePaths   []string `json:"file_paths,omitempty"`  // C:\, /usr/, *.dll, etc.
	APIRoutes   []string `json:"api_routes,omitempty"`  // /api/, /v1/, /health, etc.
	Interesting []string `json:"interesting,omitempty"` // everything else meaningful
	Total       int      `json:"total"`
	Filtered    int      `json:"filtered"` // how many garbage strings were removed
}

// FilterStrings takes raw strings from a binary and filters out .NET assembly noise,
// returning only meaningful strings categorized by type.
func FilterStrings(raw []string) *FilteredStrings {
	result := &FilteredStrings{
		Total: len(raw),
	}

	seen := make(map[string]bool)

	for _, s := range raw {
		if isNoise(s) {
			result.Filtered++
			continue
		}

		// Deduplicate
		if seen[s] {
			result.Filtered++
			continue
		}
		seen[s] = true

		// Classify into categories
		switch classifyDotnetString(s) {
		case dotnetCatNamespace:
			result.Namespaces = append(result.Namespaces, s)
		case dotnetCatURL:
			result.URLs = append(result.URLs, s)
		case dotnetCatConfigKey:
			result.ConfigKeys = append(result.ConfigKeys, s)
		case dotnetCatSQL:
			result.SQLQueries = append(result.SQLQueries, s)
		case dotnetCatFilePath:
			result.FilePaths = append(result.FilePaths, s)
		case dotnetCatAPIRoute:
			result.APIRoutes = append(result.APIRoutes, s)
		case dotnetCatClassName:
			result.ClassNames = append(result.ClassNames, s)
		default:
			result.Interesting = append(result.Interesting, s)
		}
	}

	return result
}

type dotnetCategory int

const (
	dotnetCatInteresting dotnetCategory = iota
	dotnetCatNamespace
	dotnetCatClassName
	dotnetCatURL
	dotnetCatConfigKey
	dotnetCatSQL
	dotnetCatFilePath
	dotnetCatAPIRoute
)

// isNoise returns true if a string is .NET assembly garbage that should be filtered out.
func isNoise(s string) bool {
	n := len(s)

	// Too short to be meaningful
	if n < 4 {
		return true
	}

	// Very long strings with no spaces are likely assembly data or base64 blobs
	if n > 200 && !strings.Contains(s, " ") {
		return true
	}

	// Strings that are entirely hex (0x prefix or raw hex blob)
	if reHexPrefix.MatchString(s) {
		return true
	}
	if n >= 32 && reHexBlob.MatchString(s) {
		return true
	}

	// Strings with >50% non-printable or non-ASCII characters
	nonPrintable := 0
	for _, r := range s {
		if !unicode.IsPrint(r) || r > 0x7e {
			nonPrintable++
		}
	}
	if nonPrintable > n/2 {
		return true
	}

	// Known .NET runtime noise patterns
	for _, pat := range noisePatterns {
		if strings.Contains(s, pat) {
			return true
		}
	}

	// Known .NET runtime noise regex patterns
	for _, re := range noiseRegexes {
		if re.MatchString(s) {
			return true
		}
	}

	// Strings that look like opcode sequences (short repeating patterns with no vowels)
	if n >= 8 && n <= 64 && reOpcodelike.MatchString(s) {
		return true
	}

	// x86/x64 assembly instruction patterns (mov, push, pop, call, ret, jmp, etc.)
	if reAsmInstruction.MatchString(s) {
		return true
	}

	// Strings that look like register dumps or hex addresses with commas/spaces
	if reRegisterDump.MatchString(s) {
		return true
	}

	// Repeated single character (e.g., "AAAAAAAA", "--------")
	if n >= 8 {
		allSame := true
		for i := 1; i < n; i++ {
			if s[i] != s[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	// Repeated 2-3 char pattern (e.g., "ababababab", "xyzxyzxyz")
	if n >= 12 {
		for patLen := 2; patLen <= 3; patLen++ {
			if n%patLen == 0 {
				pat := s[:patLen]
				isRepeated := true
				for i := patLen; i < n; i += patLen {
					if s[i:i+patLen] != pat {
						isRepeated = false
						break
					}
				}
				if isRepeated {
					return true
				}
			}
		}
	}

	// High entropy with no vowels and no recognizable structure
	if n >= 6 && n <= 100 && hasNoVowels(s) && !strings.Contains(s, ".") && !strings.Contains(s, "/") && !strings.Contains(s, "\\") {
		// Short no-vowel strings that aren't dotted paths or file paths are usually noise
		if n <= 20 {
			return true
		}
	}

	return false
}

// hasNoVowels checks if a string has no vowels (common in binary noise, rare in real text).
func hasNoVowels(s string) bool {
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'a', 'e', 'i', 'o', 'u':
			return false
		}
	}
	return true
}

// noisePatterns are substrings that indicate .NET runtime/compiler noise.
var noisePatterns = []string{
	"System.Private.CoreLib",
	"__StaticArrayInit",
	"<Module>",
	"CompilerGenerated",
	"DebuggerBrowsable",
	"DebuggerHidden",
	"DebuggerDisplay",
	"DebuggerStepThrough",
	"DebuggerNonUserCode",
	"DebuggerTypeProxy",
	"CompilationRelaxations",
	"RuntimeCompatibility",
	"NullableContext",
	"NullableAttribute",
	"IsReadOnlyAttribute",
	"IsByRefLikeAttribute",
	"ParamArrayAttribute",
	"AsyncStateMachine",
	"IteratorStateMachine",
	"CallerMemberName",
	"CallerFilePath",
	"CallerLineNumber",
	"InternalsVisibleTo",
	"TypeForwardedTo",
	"DefaultMember",
	"System.Runtime.CompilerServices",
	"System.Runtime.InteropServices",
	"System.Diagnostics.CodeAnalysis",
	"System.Diagnostics.DebuggerBrowsableState",
	"System.Reflection.Assembly",
	"Microsoft.CodeAnalysis",
	"<PrivateImplementationDetails>",
	"__DynamicallyInvokable",
	"EmbeddedAttribute",
	"RefSafetyRulesAttribute",
	"ScopedRefAttribute",
	"RequiresLocationAttribute",
	"CollectionBuilderAttribute",
	"InterpolatedStringHandler",
	".ctor",
	".cctor",
	"get_",
	"set_",
	"op_Implicit",
	"op_Explicit",
	"op_Equality",
	"op_Inequality",
	"b__",
	"<>c__DisplayClass",
	"<>f__AnonymousType",
	"CS$<>",
	"VB$StateMachine",
}

// noiseRegexes are compiled patterns for noise detection.
var noiseRegexes = []*regexp.Regexp{
	// Generic type mangling: `1, `2, etc.
	regexp.MustCompile("^[A-Za-z_]+`\\d+$"),
	// Anonymous/generated types: <>__something, <M>d__1
	regexp.MustCompile(`^<[^>]*>[a-z]__\d+$`),
	// IL opcodes and metadata tokens
	regexp.MustCompile(`^(?:nop|ret|ldarg|starg|ldloc|stloc|ldnull|ldc|ldstr|newobj|call|callvirt|brtrue|brfalse|br\.s|leave|endfinally|throw|ceq|cgt|clt|conv|mul|add|sub|div|rem|and|or|xor|shl|shr|neg|not|dup|pop|box|unbox|castclass|isinst)\b`),
	// Pure numeric strings (moved up — repeated chars handled in isNoise func)
	// Note: Go regexp2 doesn't support backreferences, so repeated-char detection
	// is done in isNoise() via a simple loop instead of regex.
	// Pure numeric strings
	regexp.MustCompile(`^\d+$`),
}

// reHexPrefix matches strings starting with 0x followed by hex digits.
var reHexPrefix = regexp.MustCompile(`^0[xX][0-9a-fA-F]+$`)

// reHexBlob matches long hex-only strings (hashes, GUIDs, assembly data).
var reHexBlob = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)

// reOpcodelike matches strings that look like sequences of opcode mnemonics.
var reOpcodelike = regexp.MustCompile(`^[bcdfghjklmnpqrstvwxyz0-9._]+$`)

// reAsmInstruction matches strings that start with x86/x64 assembly instruction mnemonics.
// These commonly appear when extracting strings from native .NET self-contained binaries.
var reAsmInstruction = regexp.MustCompile(`^(?:mov|push|pop|call|ret|jmp|jne|je|jz|jnz|jg|jge|jl|jle|ja|jae|jb|jbe|lea|xor|and|or|not|shl|shr|sar|sal|test|cmp|add|sub|mul|imul|div|idiv|inc|dec|nop|int|hlt|rep|movs|stos|lods|cmps|scas|enter|leave|pusha|popa|pushf|popf|cdq|cwde|cbw|syscall|sysenter|lock|xchg|bswap|rdtsc|cpuid|cmov|setcc|bt|bts|btr|btc|bsf|bsr|movzx|movsx|xadd)\s`)

// reRegisterDump matches strings that look like register references or hex address patterns.
var reRegisterDump = regexp.MustCompile(`^(?:(?:e[abcds][xip]|r[abcds][xip]|r[89]|r1[0-5]|[abcds][xiplh]|[cdefgs]s|[xy]mm\d|zmm\d|cr\d|dr\d)[,\s]){2,}`)

// reNamespace matches dotted PascalCase identifiers like System.Net.Http.
var reNamespace = regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*(\.[A-Z][a-zA-Z0-9]*){1,}$`)

// reClassName matches PascalCase identifiers with at least 2 humps.
var reClassName = regexp.MustCompile(`^[A-Z][a-z]+(?:[A-Z][a-z]+)+$`)

// reAPIRoute matches path-like strings with lowercase segments.
var reAPIRoute = regexp.MustCompile(`^/[a-z][a-z0-9/_-]*$`)

// reSQLKeyword matches SQL statement prefixes.
var reSQLKeyword = regexp.MustCompile(`(?i)^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|MERGE|EXEC)\s`)

// reFilePath matches Windows or Unix file paths.
var reFilePath = regexp.MustCompile(`(?:^[A-Z]:\\|^/(?:usr|etc|var|home|tmp|opt|proc)/|\.(?:dll|exe|config|json|xml|pdb|so|dylib|txt|log|dat|db|sqlite)$)`)

// reConfigKey matches key=value patterns or common config key formats.
var reConfigKey = regexp.MustCompile(`(?:^[A-Za-z][A-Za-z0-9_.:-]+=.+|^[A-Za-z][A-Za-z0-9_]*(?::[A-Za-z][A-Za-z0-9_]*)+$)`)

func classifyDotnetString(s string) dotnetCategory {
	// URLs first (most specific)
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return dotnetCatURL
	}

	// SQL queries
	if reSQLKeyword.MatchString(s) {
		return dotnetCatSQL
	}

	// API routes
	if strings.HasPrefix(s, "/") && reAPIRoute.MatchString(s) {
		return dotnetCatAPIRoute
	}

	// File paths
	if reFilePath.MatchString(s) {
		return dotnetCatFilePath
	}

	// Config keys (key=value or colon-separated)
	if reConfigKey.MatchString(s) && !strings.Contains(s, " ") {
		return dotnetCatConfigKey
	}

	// .NET namespaces (dotted PascalCase)
	if reNamespace.MatchString(s) {
		return dotnetCatNamespace
	}

	// Class names (PascalCase, no dots)
	if reClassName.MatchString(s) && !strings.Contains(s, ".") && !strings.Contains(s, " ") {
		return dotnetCatClassName
	}

	return dotnetCatInteresting
}
