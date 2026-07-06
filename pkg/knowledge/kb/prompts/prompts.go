package prompts

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed *.md
var promptFS embed.FS

var (
	loadOnce sync.Once
	loaded   map[string]*Prompt
	loadErr  error
)

// load parses every embedded *.md file once. Errors during parse are
// retained on loadErr so Get/List surface them lazily — the package
// init keeps no side effects beyond the embed.
func load() {
	loaded = map[string]*Prompt{}
	entries, err := promptFS.ReadDir(".")
	if err != nil {
		loadErr = fmt.Errorf("read embedded prompts: %w", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		raw, rerr := promptFS.ReadFile(e.Name())
		if rerr != nil {
			loadErr = fmt.Errorf("read %s: %w", e.Name(), rerr)
			return
		}
		p, perr := parsePrompt(raw)
		if perr != nil {
			loadErr = fmt.Errorf("parse %s: %w", e.Name(), perr)
			return
		}
		// op defaults to filename stem if frontmatter omits it.
		if p.Op == "" {
			p.Op = strings.TrimSuffix(e.Name(), ".md")
		}
		loaded[p.Op] = p
	}
}

// utf8BOM is the byte-order-mark sometimes prepended to UTF-8 text files
// by Windows editors. We strip it before frontmatter parsing.
const utf8BOM = "\ufeff"

// parsePrompt splits a raw .md file into frontmatter + body and parses
// the YAML preamble. Files without a leading "---" are treated as
// body-only with empty frontmatter.
func parsePrompt(raw []byte) (*Prompt, error) {
	src := strings.TrimPrefix(string(raw), utf8BOM)
	if !strings.HasPrefix(src, "---") {
		return &Prompt{Body: src}, nil
	}
	// Drop the opening "---" line, then find the closing one.
	lines := strings.SplitN(src, "\n", 2)
	if len(lines) < 2 {
		return nil, fmt.Errorf("frontmatter starts but file ends after %q", lines[0])
	}
	rest := lines[1]
	before, after, ok := strings.Cut(rest, "\n---")
	if !ok {
		return nil, fmt.Errorf("frontmatter not closed with ---")
	}
	yamlPart := before
	// Body starts after the closing "---" and the newline immediately
	// following it (if any).
	body := after
	body = strings.TrimPrefix(body, "\r")
	body = strings.TrimPrefix(body, "\n")

	var fm Frontmatter
	if err := yaml.Unmarshal([]byte(yamlPart), &fm); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return &Prompt{Frontmatter: fm, Body: body}, nil
}

// Get returns the prompt registered for op, or an error if it isn't
// embedded. The returned pointer is shared — callers must not mutate it.
func Get(op string) (*Prompt, error) {
	loadOnce.Do(load)
	if loadErr != nil {
		return nil, loadErr
	}
	p, ok := loaded[op]
	if !ok {
		return nil, fmt.Errorf("unknown prompt op: %q", op)
	}
	return p, nil
}

// List returns all registered op names in sorted order.
func List() []string {
	loadOnce.Do(load)
	if loadErr != nil {
		return nil
	}
	out := make([]string, 0, len(loaded))
	for k := range loaded {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Render performs a verbatim placeholder substitution on the prompt
// body. Callers pass a map of placeholder→replacement; placeholders are
// matched literally (no escaping). Unknown placeholders in the body are
// left intact so the caller can spot them in the rendered output.
func (p *Prompt) Render(vars map[string]string) string {
	body := p.Body
	for k, v := range vars {
		body = strings.ReplaceAll(body, "{"+k+"}", v)
	}
	return body
}
