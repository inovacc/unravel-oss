/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

var funcMap = template.FuncMap{
	"quoteJS":      quoteJS,
	"escapeJSPath": escapeJSPath,
	"joinSlice":    joinSlice,
}

// tmplData is the struct passed to text/template.Execute (D-07).
type tmplData struct {
	Seam       inject.Seam
	Platform   string
	SeamID     string
	TargetPath string
	Tag        string
}

// renderJS renders the platform template with seam data and returns the JS
// bytes. Returns an ErrUnknownPlatform-wrapped error if the platform is not
// one of windows / macos / linux.
func renderJS(s inject.Seam, platform, id string) ([]byte, error) {
	tmplName := fmt.Sprintf("templates/%s.tmpl", platform)
	raw, err := templatesFS.ReadFile(tmplName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownPlatform, platform)
	}
	t, err := template.New(platform).Funcs(funcMap).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse template %s: %w", platform, err)
	}
	path, tag := extractTargetPathTag(s)
	data := tmplData{
		Seam:       s,
		Platform:   platform,
		SeamID:     id,
		TargetPath: path,
		Tag:        tag,
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute template %s: %w", platform, err)
	}
	return buf.Bytes(), nil
}

// quoteJS produces a JSON-style double-quoted JS string literal that escapes
// backslashes, quotes, and control characters. Suitable for use inside JS
// source where a string is needed.
func quoteJS(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				_, _ = fmt.Fprintf(&b, `\u%04x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// escapeJSPath returns a forward-slash normalized path safe to embed in a
// JS comment or string literal.
func escapeJSPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// joinSlice joins elements with sep — handles nil safely.
func joinSlice(items []string, sep string) string {
	return strings.Join(items, sep)
}
