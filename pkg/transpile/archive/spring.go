package archive

import (
	"bufio"
	"bytes"
	"strings"
)

// SpringConfig holds parsed Spring configuration.
type SpringConfig struct {
	ServerPort string            `json:"server_port,omitempty"`
	Datasource *DatasourceConfig `json:"datasource,omitempty"`
	Profiles   []string          `json:"profiles,omitempty"`
	Properties map[string]string `json:"properties"`
}

// DatasourceConfig holds database connection configuration.
type DatasourceConfig struct {
	URL      string `json:"url,omitempty"`
	Driver   string `json:"driver,omitempty"`
	Username string `json:"username,omitempty"`
}

// ParseSpringProperties parses an application.properties file.
func ParseSpringProperties(data []byte) (*SpringConfig, error) {
	config := &SpringConfig{
		Properties: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Handle = and : as delimiters
		var key, value string

		for i, r := range line {
			if r == '=' || r == ':' {
				key = strings.TrimSpace(line[:i])
				value = strings.TrimSpace(line[i+1:])

				break
			}
		}

		if key == "" {
			continue
		}

		config.Properties[key] = value
		applySpringProperty(config, key, value)
	}

	return config, scanner.Err()
}

// ParseSpringYAML parses a simplified application.yml file using line-based
// key flattening. This avoids adding a YAML dependency by handling the common
// case of simple key-value hierarchies.
func ParseSpringYAML(data []byte) (*SpringConfig, error) {
	config := &SpringConfig{
		Properties: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	var stack []stackEntry

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Calculate indentation level
		indent := 0

		for _, r := range line {
			if r == ' ' {
				indent++
			} else {
				break
			}
		}

		// Pop stack to current indent level
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}

		// Parse key: value
		before, after, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}

		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)

		if value == "" {
			// This is a parent key, push onto stack
			stack = append(stack, stackEntry{key: key, indent: indent})
			continue
		}

		// Build full key path
		fullKey := buildKeyPath(stack, key)
		config.Properties[fullKey] = value
		applySpringProperty(config, fullKey, value)
	}

	return config, scanner.Err()
}

type stackEntry struct {
	key    string
	indent int
}

func buildKeyPath(stack []stackEntry, key string) string {
	if len(stack) == 0 {
		return key
	}

	var parts []string
	for _, s := range stack {
		parts = append(parts, s.key)
	}

	parts = append(parts, key)

	return strings.Join(parts, ".")
}

// applySpringProperty extracts well-known Spring config values.
func applySpringProperty(config *SpringConfig, key, value string) {
	switch key {
	case "server.port":
		config.ServerPort = value
	case "spring.datasource.url":
		if config.Datasource == nil {
			config.Datasource = &DatasourceConfig{}
		}

		config.Datasource.URL = value
	case "spring.datasource.driver-class-name":
		if config.Datasource == nil {
			config.Datasource = &DatasourceConfig{}
		}

		config.Datasource.Driver = value
	case "spring.datasource.username":
		if config.Datasource == nil {
			config.Datasource = &DatasourceConfig{}
		}

		config.Datasource.Username = value
	case "spring.profiles.active":
		config.Profiles = strings.Split(value, ",")
		for i := range config.Profiles {
			config.Profiles[i] = strings.TrimSpace(config.Profiles[i])
		}
	}
}
