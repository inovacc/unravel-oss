/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"
)

// Tree is the durable, framework-agnostic JSON shape written to tree.json.
type Tree struct {
	Tag      string            `json:"tag"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	Role     string            `json:"role,omitempty"`
	Bounds   *Bounds           `json:"bounds,omitempty"`
	Children []Tree            `json:"children,omitempty"`
}

// Bounds is the per-element rectangle + visibility flag used both inside
// Tree (correlated by layout pass) and inside LayoutEntry.
type Bounds struct {
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	W       float64 `json:"w"`
	H       float64 `json:"h"`
	Visible bool    `json:"visible"`
	ZIndex  string  `json:"z_index,omitempty"`
}

// FrameworkTree mirrors Tree but with framework-aware names (component name)
// instead of HTML tags. Written as tree-<fw>.json sibling artifact.
type FrameworkTree struct {
	Name     string          `json:"name"`
	Key      string          `json:"key,omitempty"`
	Props    json.RawMessage `json:"props,omitempty"`
	Children []FrameworkTree `json:"children,omitempty"`
}

// BuildJSONTree converts a CDP DOMNode tree into a Tree. NodeType==1 (Element)
// nodes only; text/comment/etc. are dropped. DOMNode.Attributes is a flat
// [name, value, name, value, ...] slice; we materialize it into a map.
//
// Returns nil when n is nil. Recurses depth-first; per D-22 the orchestrator's
// outer recover boundary catches any pathological depth panic.
func BuildJSONTree(n *cdp.DOMNode) *Tree {
	if n == nil {
		return nil
	}
	if n.NodeType != 1 {
		// Walk into a non-element root (Document) to find its first element child.
		for i := range n.Children {
			if t := BuildJSONTree(&n.Children[i]); t != nil {
				return t
			}
		}
		return nil
	}
	t := &Tree{Tag: strings.ToLower(n.LocalName)}
	if t.Tag == "" {
		t.Tag = strings.ToLower(n.NodeName)
	}
	if len(n.Attributes) >= 2 {
		t.Attrs = make(map[string]string, len(n.Attributes)/2)
		for i := 0; i+1 < len(n.Attributes); i += 2 {
			k, v := n.Attributes[i], n.Attributes[i+1]
			t.Attrs[k] = v
			if k == "role" {
				t.Role = v
			}
		}
	}
	for i := range n.Children {
		c := &n.Children[i]
		if c.NodeType != 1 {
			continue
		}
		if child := BuildJSONTree(c); child != nil {
			t.Children = append(t.Children, *child)
		}
	}
	return t
}

// extractorFn is the per-framework devtools-hook extractor signature.
type extractorFn func(ctx context.Context, c *cdp.Client) (*FrameworkTree, error)

// registry maps the canonical (lowercase) framework slug to its extractor.
// Framework names from pkg/jsdeob/framework are PascalCase ("React", "Vue",
// "Next.js"); ExtractFrameworkTree normalizes before lookup.
var registry = map[string]extractorFn{
	"react":   extractReactTree,
	"vue":     extractVue3Tree,
	"angular": extractAngularTree,
	"svelte":  extractSvelteTree,
	"solid":   extractSolidTree,
	"preact":  extractPreactTree,
}

// ExtractFrameworkTree dispatches to the per-framework extractor selected by
// the Phase 6 detector. Returns (nil, "", nil) for D-06 silent fallback when:
//   - infos is empty, or
//   - top confidence < 0.5, or
//   - the per-framework devtools hook is absent at runtime (extractor returns nil).
//
// Next.js / Remix route to the React extractor; Nuxt routes to Vue (RESEARCH
// §"Next.js / Nuxt / Remix").
//
// On panic during JSON decode the recover boundary returns the framework name
// recognised so far plus the formatted error (D-22).
func ExtractFrameworkTree(ctx context.Context, c *cdp.Client, infos []framework.FrameworkInfo) (out *FrameworkTree, fwName string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("framework tree panic: %v", r)
		}
	}()
	if len(infos) == 0 || infos[0].Confidence < 0.5 {
		return nil, "", nil
	}
	name := strings.ToLower(infos[0].Name)
	switch name {
	case "next.js", "nextjs", "remix":
		name = "react"
	case "nuxt":
		name = "vue"
	}
	fn, ok := registry[name]
	if !ok {
		return nil, name, nil
	}
	t, err := fn(ctx, c)
	return t, name, err
}

// decodeFrameworkTree decodes a JSON value into a FrameworkTree, accepting
// either a single root object or an array of roots (extractors that walk
// multiple Vue apps / fiber roots return arrays). When raw is the JS literal
// "null" (hook absent), returns (nil, nil) so the caller can silently fall
// back to tree.json only (D-06).
func decodeFrameworkTree(raw json.RawMessage) (*FrameworkTree, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var arr []FrameworkTree
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("decode framework tree array: %w", err)
		}
		if len(arr) == 0 {
			return nil, nil
		}
		if len(arr) == 1 {
			r := arr[0]
			return &r, nil
		}
		// Synthetic root wrapping all detected mounts.
		return &FrameworkTree{Name: "(roots)", Children: arr}, nil
	}
	var t FrameworkTree
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("decode framework tree: %w", err)
	}
	return &t, nil
}
