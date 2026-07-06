//go:build ignore
// +build ignore

// Package iniparser provides a simple INI file parser
// Inspired by inih (https://github.com/benhoyt/inih)
package iniparser

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	INI_MAX_LINE    = 256
	INI_MAX_SECTION = 64
	INI_MAX_NAME    = 64
	INI_MAX_ENTRIES = 128
)

// IniEntry represents a single key-value pair in an INI file
type IniEntry struct {
	Section string
	Name    string
	Value   string
}

// IniConfig holds the parsed INI configuration
type IniConfig struct {
	Entries []IniEntry
	Count   int
	Error   string
}

// IniHandler is a callback function type for parsing INI files
// Returns non-zero to stop parsing, zero to continue
type IniHandler func(user interface{}, section, name, value string) int

// IniParseFile parses an INI file, calling handler for each name=value pair
// Returns 0 on success, negative on file error, positive on parse error (line number)
func IniParseFile(filename string, handler IniHandler, user interface{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	return parseScanner(scanner, handler, user)
}

// IniParseString parses an INI string buffer
func IniParseString(buf string, handler IniHandler, user interface{}) error {
	scanner := bufio.NewScanner(strings.NewReader(buf))
	return parseScanner(scanner, handler, user)
}

// parseScanner is the internal parser implementation
func parseScanner(scanner *bufio.Scanner, handler IniHandler, user interface{}) error {
	section := ""
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Trim leading/trailing whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if len(line) == 0 || line[0] == ';' || line[0] == '#' {
			continue
		}

		// Section header
		if line[0] == '[' {
			endIdx := strings.IndexByte(line, ']')
			if endIdx == -1 {
				return fmt.Errorf("line %d: unclosed section bracket", lineNum)
			}
			section = strings.TrimSpace(line[1:endIdx])
			if len(section) > INI_MAX_SECTION {
				section = section[:INI_MAX_SECTION]
			}
			continue
		}

		// Key-value pair
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx == -1 {
			return fmt.Errorf("line %d: no '=' found", lineNum)
		}

		name := strings.TrimSpace(line[:eqIdx])
		value := strings.TrimSpace(line[eqIdx+1:])

		// Remove quotes from value if present
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' ||
			value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}

		// Truncate to max lengths
		if len(name) > INI_MAX_NAME {
			name = name[:INI_MAX_NAME]
		}
		if len(value) > INI_MAX_LINE {
			value = value[:INI_MAX_LINE]
		}

		// Call handler
		if handler != nil {
			if result := handler(user, section, name, value); result != 0 {
				return fmt.Errorf("line %d: handler returned non-zero: %d", lineNum, result)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// IniLoad loads an entire INI config file into an IniConfig struct
func IniLoad(filename string) (*IniConfig, error) {
	config := &IniConfig{
		Entries: make([]IniEntry, 0, INI_MAX_ENTRIES),
		Count:   0,
	}

	handler := func(user interface{}, section, name, value string) int {
		cfg := user.(*IniConfig)
		if cfg.Count >= INI_MAX_ENTRIES {
			cfg.Error = "maximum entries exceeded"
			return 1
		}
		cfg.Entries = append(cfg.Entries, IniEntry{
			Section: section,
			Name:    name,
			Value:   value,
		})
		cfg.Count++
		return 0
	}

	err := IniParseFile(filename, handler, config)
	if err != nil {
		config.Error = err.Error()
		return config, err
	}

	return config, nil
}

// IniGet retrieves a value by section and name, returns empty string if not found
func IniGet(config *IniConfig, section, name string) string {
	if config == nil {
		return ""
	}

	for i := 0; i < config.Count; i++ {
		entry := &config.Entries[i]
		if strings.EqualFold(entry.Section, section) && strings.EqualFold(entry.Name, name) {
			return entry.Value
		}
	}
	return ""
}

// IniGetInt retrieves a value as integer, returns defaultVal if not found or invalid
func IniGetInt(config *IniConfig, section, name string, defaultVal int) int {
	value := IniGet(config, section, name)
	if value == "" {
		return defaultVal
	}

	result, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return defaultVal
	}
	return result
}

// IniGetBool retrieves a value as boolean (true/yes/1 = true, false/no/0 = false)
// Returns defaultVal if not found
func IniGetBool(config *IniConfig, section, name string, defaultVal bool) bool {
	value := IniGet(config, section, name)
	if value == "" {
		return defaultVal
	}

	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	default:
		return defaultVal
	}
}

// Close is a no-op in Go (memory is garbage collected)
// Provided for API compatibility
func (config *IniConfig) Close() error {
	// No resources to free in Go
	return nil
}
