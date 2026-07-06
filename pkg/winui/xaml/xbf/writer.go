/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"fmt"
	"strings"
)

// RenderXAML walks a NodeTree and emits human-readable indented XAML. Round-
// trip is NOT byte-identical to the original source.
//
// Unknown opcodes are emitted as `<!-- xbf:opcode 0xNN unknown -->` comment
// nodes — the canonical placeholder format. This is testable per acceptance
// criterion (TestRenderXAML_UnknownPlaceholderFormat).
func RenderXAML(tree *NodeTree, _ *Tables) string {
	if tree == nil || tree.Root == nil {
		return ""
	}
	var sb strings.Builder
	renderNode(&sb, tree.Root, 0)
	if !strings.HasSuffix(sb.String(), "\n") {
		sb.WriteByte('\n')
	}
	return sb.String()
}

func renderNode(sb *strings.Builder, n *Node, depth int) {
	if n == nil {
		return
	}
	indent := strings.Repeat("  ", depth)
	if n.Unknown {
		sb.WriteString(indent)
		sb.WriteString(fmt.Sprintf("<!-- xbf:opcode 0x%02X unknown -->\n", n.UnknownByte))
		return
	}
	// Element name.
	name := n.Name
	if name == "" {
		name = fmt.Sprintf("xbf-opcode-0x%02X", byte(n.Op))
	}

	// Open tag.
	sb.WriteString(indent)
	sb.WriteByte('<')
	sb.WriteString(name)

	// Properties (attributes + namespace declarations).
	for _, p := range n.Properties {
		switch p.Op {
		case OpAddNamespace, OpNamespace:
			if p.NamespacePrefix == "" || p.NamespacePrefix == "xmlns" {
				sb.WriteString(fmt.Sprintf(` xmlns="%s"`, xmlEscape(p.NamespaceURI)))
			} else {
				sb.WriteString(fmt.Sprintf(` xmlns:%s="%s"`, xmlEscape(p.NamespacePrefix), xmlEscape(p.NamespaceURI)))
			}
		default:
			pname := p.Name
			if pname == "" {
				pname = fmt.Sprintf("opcode-0x%02X", byte(p.Op))
			}
			sb.WriteString(fmt.Sprintf(` %s="%s"`, pname, xmlEscape(p.Value)))
		}
	}

	// Children: filter Unknown nodes that bubbled up to be rendered as comments.
	hasChildren := len(n.Children) > 0

	if !hasChildren {
		sb.WriteString("/>\n")
		return
	}
	sb.WriteString(">\n")
	for _, c := range n.Children {
		renderNode(sb, c, depth+1)
	}
	sb.WriteString(indent)
	sb.WriteString("</")
	sb.WriteString(name)
	sb.WriteString(">\n")
}

// xmlEscape replaces XML special characters with entity references.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
