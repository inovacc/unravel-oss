package goversions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type osvEntry struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// ParseOSV decodes one vuln.go.dev OSV entry into a Vuln (Go-ecosystem ranges only).
func ParseOSV(b []byte) (Vuln, error) {
	var e osvEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return Vuln{}, fmt.Errorf("parse osv: %w", err)
	}
	v := Vuln{
		ID: e.ID, Summary: e.Summary, Aliases: e.Aliases,
		Published: dateOnly(e.Published), Modified: dateOnly(e.Modified),
		URL: "https://pkg.go.dev/vuln/" + e.ID,
	}
	for _, a := range e.Affected {
		if a.Package.Ecosystem != "Go" {
			continue
		}
		comp := a.Package.Name
		for _, r := range a.Ranges {
			var intro, fixed string
			for _, ev := range r.Events {
				if ev.Introduced != "" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
			}
			v.Affected = append(v.Affected, AffectedRange{Component: comp, Introduced: intro, Fixed: fixed})
		}
	}
	return v, nil
}

// dateOnly trims an RFC3339 timestamp to its date.
func dateOnly(s string) string {
	if i := strings.IndexByte(s, 'T'); i > 0 {
		return s[:i]
	}
	return s
}

var reReleased = regexp.MustCompile(`released\s+(\d{4}-\d{2}-\d{2})`)
var reGoVer = regexp.MustCompile(`^go\d`)

// ParseReleaseHistory extracts date + security note keyed by version. Fail-soft:
// any parse problem yields whatever was collected (possibly empty).
func ParseReleaseHistory(b []byte) map[string]ReleaseMeta {
	out := map[string]ReleaseMeta{}
	doc, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		return out
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "p" {
			var id string
			for _, a := range n.Attr {
				if a.Key == "id" && reGoVer.MatchString(a.Val) {
					id = a.Val
				}
			}
			if id != "" {
				text := nodeText(n)
				meta := ReleaseMeta{}
				if m := reReleased.FindStringSubmatch(text); m != nil {
					meta.Date = m[1]
				}
				if strings.Contains(strings.ToLower(text), "security") {
					meta.Security = strings.TrimSpace(text)
				}
				out[id] = meta
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func nodeText(n *html.Node) string {
	var sb strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return strings.Join(strings.Fields(sb.String()), " ")
}

// ParseDownloads decodes the go.dev/dl ?mode=json&include=all payload.
func ParseDownloads(b []byte) ([]Release, error) {
	var rels []Release
	if err := json.Unmarshal(b, &rels); err != nil {
		return nil, fmt.Errorf("parse dl json: %w", err)
	}
	return rels, nil
}
