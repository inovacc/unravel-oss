/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/json"
	"fmt"
)

// DOMNode is a minimal subset of CDP's DOM.Node for tree extraction in Phase 8.
type DOMNode struct {
	NodeID         int64     `json:"nodeId"`
	NodeType       int       `json:"nodeType"`
	NodeName       string    `json:"nodeName"`
	LocalName      string    `json:"localName"`
	NodeValue      string    `json:"nodeValue"`
	ChildNodeCount int       `json:"childNodeCount,omitempty"`
	Children       []DOMNode `json:"children,omitempty"`
	Attributes     []string  `json:"attributes,omitempty"`
}

// GetDocument calls DOM.getDocument and returns the root document node.
// pierce=true descends into shadow DOM and iframes; depth=-1 returns the full
// tree (caller should bound this for very large pages).
func (c *Client) GetDocument(ctx context.Context, depth int, pierce bool) (*DOMNode, error) {
	raw, err := c.SendAndWait(ctx, "DOM.getDocument", map[string]any{
		"depth":  depth,
		"pierce": pierce,
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Root DOMNode `json:"root"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode DOM.getDocument: %w", err)
	}
	return &resp.Root, nil
}
