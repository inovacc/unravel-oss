/*
Copyright (c) 2026 Security Research
*/
package ai

import (
	"bufio"
	"os"
	"strings"
)

// LoadEnv reads a .env file and sets environment variables that are not already set.
// Silently returns if the file does not exist.
func LoadEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		// Don't override existing env vars
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
