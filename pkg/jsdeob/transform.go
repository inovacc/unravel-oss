package jsdeob

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SimplifyMath simplifies constant mathematical expressions
func SimplifyMath(code string) (string, int) {
	count := 0
	result := code

	// Addition: 1 + 2 -> 3
	addPattern := regexp.MustCompile(`\b(\d+)\s*\+\s*(\d+)\b`)
	for range 10 {
		newResult := addPattern.ReplaceAllStringFunc(result, func(match string) string {
			parts := addPattern.FindStringSubmatch(match)
			if len(parts) == 3 {
				a, _ := strconv.Atoi(parts[1])
				b, _ := strconv.Atoi(parts[2])
				count++

				return strconv.Itoa(a + b)
			}

			return match
		})
		if newResult == result {
			break
		}

		result = newResult
	}

	// Subtraction: 10 - 3 -> 7
	subPattern := regexp.MustCompile(`\b(\d+)\s*-\s*(\d+)\b`)
	result = subPattern.ReplaceAllStringFunc(result, func(match string) string {
		parts := subPattern.FindStringSubmatch(match)
		if len(parts) == 3 {
			a, _ := strconv.Atoi(parts[1])
			b, _ := strconv.Atoi(parts[2])
			count++

			return strconv.Itoa(a - b)
		}

		return match
	})

	// Multiplication: 2 * 3 -> 6
	mulPattern := regexp.MustCompile(`\b(\d+)\s*\*\s*(\d+)\b`)
	result = mulPattern.ReplaceAllStringFunc(result, func(match string) string {
		parts := mulPattern.FindStringSubmatch(match)
		if len(parts) == 3 {
			a, _ := strconv.Atoi(parts[1])
			b, _ := strconv.Atoi(parts[2])
			count++

			return strconv.Itoa(a * b)
		}

		return match
	})

	// JSFuck simplification
	result = strings.ReplaceAll(result, "![]", "false")
	result = strings.ReplaceAll(result, "!![]", "true")
	result = strings.ReplaceAll(result, "!+[]", "true")
	result = strings.ReplaceAll(result, "+[]", "0")
	result = strings.ReplaceAll(result, "+!+[]", "1")

	return result, count
}

// RenameVariables renames _0x... style variable names to readable names
func RenameVariables(code string) (string, int) {
	count := 0
	result := code

	varPattern := regexp.MustCompile(`\b(_0x[a-f0-9]{4,8})\b`)
	varMap := make(map[string]string)
	varCounter := 0

	// Collect all obfuscated names
	matches := varPattern.FindAllString(result, -1)

	seen := make(map[string]bool)
	for _, match := range matches {
		if !seen[match] {
			seen[match] = true
			varCounter++
			varMap[match] = fmt.Sprintf("var_%d", varCounter)
		}
	}

	// Replace each one
	for oldName, newName := range varMap {
		pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(oldName) + `\b`)

		newResult := pattern.ReplaceAllString(result, newName)
		if newResult != result {
			count++
			result = newResult
		}
	}

	return result, count
}
