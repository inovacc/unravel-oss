//go:build ignore
// +build ignore

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

type IniEntry struct {
	Section string
	Name    string
	Value   string
}

type IniConfig struct {
	Entries []IniEntry
	Count   int
	Error   string
}

// IniHandler is the callback type for ini_parse_file
// Returns 0 on success, non-zero to stop parsing
type IniHandler func(user interface{}, section, name, value string) int

// IniParseFile parses an INI file, calling handler for each name=value pair
func IniParseFile(filename string, handler IniHandler, user interface{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	section := ""
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}

		// Parse section
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end == -1 {
				return fmt.Errorf("line %d: unclosed section", lineNum)
			}
			section = strings.TrimSpace(line[1:end])
			if len(section) > INI_MAX_SECTION {
				section = section[:INI_MAX_SECTION]
			}
			continue
		}

		// Parse name=value
		eq := strings.IndexByte(line, '=')
		if eq == -1 {
			// No '=' found, skip or error
			continue
		}

		name := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])

		// Remove quotes from value if present
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' ||
			value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}

		if len(name) > INI_MAX_NAME {
			name = name[:INI_MAX_NAME]
		}
		if len(value) > INI_MAX_LINE {
			value = value[:INI_MAX_LINE]
		}

		// Call handler
		if handler != nil {
			if ret := handler(user, section, name, value); ret != 0 {
				return fmt.Errorf("handler returned %d at line %d", ret, lineNum)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// IniParseString parses an INI string buffer
func IniParseString(buf string, handler IniHandler, user interface{}) error {
	scanner := bufio.NewScanner(strings.NewReader(buf))
	section := ""
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}

		// Parse section
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end == -1 {
				return fmt.Errorf("line %d: unclosed section", lineNum)
			}
			section = strings.TrimSpace(line[1:end])
			if len(section) > INI_MAX_SECTION {
				section = section[:INI_MAX_SECTION]
			}
			continue
		}

		// Parse name=value
		eq := strings.IndexByte(line, '=')
		if eq == -1 {
			// No '=' found, skip or error
			continue
		}

		name := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])

		// Remove quotes from value if present
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' ||
			value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}

		if len(name) > INI_MAX_NAME {
			name = name[:INI_MAX_NAME]
		}
		if len(value) > INI_MAX_LINE {
			value = value[:INI_MAX_LINE]
		}

		// Call handler
		if handler != nil {
			if ret := handler(user, section, name, value); ret != 0 {
				return fmt.Errorf("handler returned %d at line %d", ret, lineNum)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// IniLoad loads entire config into IniConfig struct
func IniLoad(filename string) (*IniConfig, error) {
	config := &IniConfig{
		Entries: make([]IniEntry, 0, INI_MAX_ENTRIES),
		Count:   0,
		Error:   "",
	}

	handler := func(user interface{}, section, name, value string) int {
		cfg := user.(*IniConfig)
		if cfg.Count >= INI_MAX_ENTRIES {
			cfg.Error = "too many entries"
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

// IniGet gets a value by section and name, returns empty string if not found
func IniGet(config *IniConfig, section, name string) string {
	if config == nil {
		return ""
	}

	for i := 0; i < config.Count; i++ {
		entry := &config.Entries[i]
		if entry.Section == section && entry.Name == name {
			return entry.Value
		}
	}

	return ""
}

// IniGetInt gets a value as integer, returns defaultVal if not found
func IniGetInt(config *IniConfig, section, name string, defaultVal int) int {
	value := IniGet(config, section, name)
	if value == "" {
		return defaultVal
	}

	result, err := strconv.Atoi(value)
	if err != nil {
		return defaultVal
	}

	return result
}

// IniGetBool gets a value as boolean (true/yes/1 = true, false/no/0 = false)
func IniGetBool(config *IniConfig, section, name string, defaultVal bool) bool {
	value := strings.ToLower(IniGet(config, section, name))
	if value == "" {
		return defaultVal
	}

	if value == "true" || value == "yes" || value == "1" || value == "on" {
		return true
	}

	if value == "false" || value == "no" || value == "0" || value == "off" {
		return false
	}

	return defaultVal
}

// IniFree frees config memory (no-op in Go due to GC)
func IniFree(config *IniConfig) {
	// No-op in Go - garbage collector handles memory
}
