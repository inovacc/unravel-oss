/*
Copyright (c) 2026 Security Research
*/
package output

import "fmt"

// Truncate truncates a string to maxLen, appending "..." if needed.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	if maxLen <= 3 {
		return s[:maxLen]
	}

	return s[:maxLen-3] + "..."
}

// FormatSize formats bytes into a human-readable string (KB/MB/GB).
func FormatSize(bytes int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// BoolYesNo converts a bool to "Yes" or "No".
func BoolYesNo(b bool) string {
	if b {
		return "Yes"
	}

	return "No"
}

// CountDigits returns the number of digits in a non-negative integer.
func CountDigits(n int) int {
	if n == 0 {
		return 1
	}

	count := 0
	for n > 0 {
		count++
		n /= 10
	}

	return count
}

// WrapText wraps text at word boundaries to fit within maxLen columns.
func WrapText(s string, maxLen int) []string {
	if len(s) <= maxLen {
		return []string{s}
	}

	var lines []string

	for len(s) > maxLen {
		idx := -1
		for i := maxLen - 1; i >= 0; i-- {
			if s[i] == ' ' {
				idx = i
				break
			}
		}

		if idx <= 0 {
			idx = maxLen
		}

		lines = append(lines, s[:idx])

		if idx < len(s) && s[idx] == ' ' {
			s = s[idx+1:]
		} else {
			s = s[idx:]
		}
	}

	if s != "" {
		lines = append(lines, s)
	}

	return lines
}
