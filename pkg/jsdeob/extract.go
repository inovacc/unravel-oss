package jsdeob

import (
	"regexp"
	"strings"
)

// ExtractStrings extracts all string literals from code
func ExtractStrings(code string) []string {
	var strs []string

	seen := make(map[string]bool)

	// Double-quoted strings
	doubleQuote := regexp.MustCompile(`"([^"\\]|\\.)*"`)
	for _, match := range doubleQuote.FindAllString(code, -1) {
		s := match[1 : len(match)-1]
		if len(s) > 2 && !seen[s] {
			seen[s] = true
			strs = append(strs, s)
		}
	}

	// Single-quoted strings
	singleQuote := regexp.MustCompile(`'([^'\\]|\\.)*'`)
	for _, match := range singleQuote.FindAllString(code, -1) {
		s := match[1 : len(match)-1]
		if len(s) > 2 && !seen[s] {
			seen[s] = true
			strs = append(strs, s)
		}
	}

	return strs
}

// ExtractURLs extracts URLs from code
func ExtractURLs(code string) []string {
	var urls []string

	seen := make(map[string]bool)

	urlPattern := regexp.MustCompile(`https?://[^\s"'<>()]+`)
	for _, match := range urlPattern.FindAllString(code, -1) {
		match = strings.TrimRight(match, ".,;:!?")
		if !seen[match] {
			seen[match] = true
			urls = append(urls, match)
		}
	}

	return urls
}

// ExtractFunctions extracts function names
func ExtractFunctions(code string) []string {
	var funcs []string

	seen := make(map[string]bool)

	// function name(...) pattern
	funcPattern := regexp.MustCompile(`function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(`)
	for _, match := range funcPattern.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			funcs = append(funcs, match[1])
		}
	}

	// const/let/var name = function pattern
	varFuncPattern := regexp.MustCompile(`(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:function|\([^)]*\)\s*=>)`)
	for _, match := range varFuncPattern.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			funcs = append(funcs, match[1])
		}
	}

	return funcs
}

// ExtractAPICalls extracts potential API endpoints and fetch/axios calls.
// It captures:
//   - fetch("url") and fetch(`url`) calls (static URLs)
//   - fetch(`https://${...}`) template literal calls
//   - axios.get/post/etc("url") calls
//   - XMLHttpRequest.open("METHOD", "url") calls
//   - Method+path patterns like {method:"POST",path:"/v1/..."}
//   - Standalone API path strings like "/v1/auth/login"
//   - HTTP request header names (x-device-*, Authorization, etc.)
func ExtractAPICalls(code string) []string {
	var calls []string

	seen := make(map[string]bool)

	add := func(entry string) {
		if !seen[entry] {
			seen[entry] = true
			calls = append(calls, entry)
		}
	}

	// fetch("url") and fetch('url') — static string URLs
	fetchQuoted := regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`)
	for _, match := range fetchQuoted.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 {
			add("fetch: " + match[1])
		}
	}

	// fetch(`https://...`) — template literal URLs (capture up to ${)
	fetchTemplate := regexp.MustCompile("fetch\\s*\\(\\s*`(https?://[^`]*)`")
	for _, match := range fetchTemplate.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 {
			add("fetch: " + match[1])
		}
	}

	// axios.get/post/etc pattern
	axiosPattern := regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	for _, match := range axiosPattern.FindAllStringSubmatch(code, -1) {
		if len(match) > 2 {
			add(match[1] + ": " + match[2])
		}
	}

	// XMLHttpRequest.open pattern
	xhrPattern := regexp.MustCompile(`\.open\s*\(\s*["'](\w+)["']\s*,\s*["']([^"']+)["']`)
	for _, match := range xhrPattern.FindAllStringSubmatch(code, -1) {
		if len(match) > 2 {
			add(match[1] + ": " + match[2])
		}
	}

	// Method+path pattern: {method:"POST",path:"/v1/auth/login"} (common in API clients)
	methodPath := regexp.MustCompile(`method:\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*path:\s*["']([^"']+)["']`)
	for _, match := range methodPath.FindAllStringSubmatch(code, -1) {
		if len(match) > 2 {
			add(match[1] + ": " + match[2])
		}
	}

	// Reverse order: path then method
	pathMethod := regexp.MustCompile(`path:\s*["']([^"']+)["']\s*,\s*method:\s*["'](GET|POST|PUT|DELETE|PATCH)["']`)
	for _, match := range pathMethod.FindAllStringSubmatch(code, -1) {
		if len(match) > 2 {
			add(match[2] + ": " + match[1])
		}
	}

	// Standalone API paths: "/v1/...", "/v2/...", "/api/..."
	apiPaths := regexp.MustCompile(`["'](/(?:v[0-9]+|api)/[a-zA-Z0-9/_-]+)["']`)
	for _, match := range apiPaths.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 {
			add("path: " + match[1])
		}
	}

	return calls
}

// ExtractHeaders extracts HTTP request header names from code.
// Looks for custom headers (x-*, Authorization, Content-Type, etc.)
func ExtractHeaders(code string) []string {
	var headers []string
	seen := make(map[string]bool)

	// Custom x-* headers
	customHeader := regexp.MustCompile(`["']((?:x|X)-[a-zA-Z][a-zA-Z0-9-]*)["']`)
	for _, match := range customHeader.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 {
			h := strings.ToLower(match[1])
			if !seen[h] {
				seen[h] = true
				headers = append(headers, match[1])
			}
		}
	}

	// Standard auth/content headers
	stdHeaders := regexp.MustCompile(`["'](Authorization|Content-Type|Accept|Cache-Control|Pragma)["']`)
	for _, match := range stdHeaders.FindAllStringSubmatch(code, -1) {
		if len(match) > 1 {
			h := strings.ToLower(match[1])
			if !seen[h] {
				seen[h] = true
				headers = append(headers, match[1])
			}
		}
	}

	return headers
}
