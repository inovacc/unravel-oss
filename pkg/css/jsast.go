// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/t14raptor/go-fast/ast"
	"github.com/t14raptor/go-fast/parser"
)

// CSSInJSResult holds all CSS entries extracted from a JavaScript file.
type CSSInJSResult struct {
	Entries []CSSInJSEntry `json:"entries"`
}

// CSSInJSEntry represents a single CSS extraction from JS source.
type CSSInJSEntry struct {
	CSS           string `json:"css"`
	ComponentName string `json:"component_name"`
	Kind          string `json:"kind"` // "tagged-template" or "object-style"
	SourceLine    int    `json:"source_line"`
}

// unitlessProperties are CSS properties that don't get "px" appended for numeric values.
var unitlessProperties = map[string]bool{
	"opacity":     true,
	"z-index":     true,
	"flex":        true,
	"flex-grow":   true,
	"flex-shrink": true,
	"order":       true,
	"line-height": true,
	"font-weight": true,
	"widows":      true,
	"orphans":     true,
	"tab-size":    true,
	"zoom":        true,
}

// cssTagFunctions are known CSS-in-JS tagged template function names.
var cssTagFunctions = map[string]bool{
	"css":          true,
	"keyframes":    true,
	"injectGlobal": true,
	"html":         true,
}

// ExtractCSSFromJS extracts CSS content from JavaScript source files.
// It handles tagged template literals (styled-components, emotion, lit)
// and object style patterns (css({...})) using AST walking via go-fAST.
func ExtractCSSFromJS(content []byte, sourcePath string) (*CSSInJSResult, error) {
	result := &CSSInJSResult{}
	src := string(content)

	program, err := parser.ParseFile(src)
	if err != nil {
		// Graceful fallback: return empty result for unparseable JS
		return result, nil
	}

	v := &cssVisitor{
		src:    src,
		result: result,
	}
	wrapper := &cssVisitorWrapper{v: v}
	wrapper.NoopVisitor.V = wrapper
	program.Body.VisitWith(wrapper)

	return result, nil
}

// cssVisitor collects CSS-in-JS entries from the AST.
type cssVisitor struct {
	src    string
	result *CSSInJSResult
}

// cssVisitorWrapper embeds NoopVisitor for the full Visitor interface,
// overriding only the nodes we care about.
type cssVisitorWrapper struct {
	ast.NoopVisitor
	v *cssVisitor
}

func (w *cssVisitorWrapper) VisitTemplateLiteral(n *ast.TemplateLiteral) {
	w.v.visitTemplateLiteral(n)
	// Continue walking children for nested templates
	n.VisitChildrenWith(w)
}

func (w *cssVisitorWrapper) VisitCallExpression(n *ast.CallExpression) {
	w.v.visitCallExpression(n)
	// Continue walking children
	n.VisitChildrenWith(w)
}

// visitTemplateLiteral handles tagged template literals like styled.button`...` or css`...`.
func (v *cssVisitor) visitTemplateLiteral(n *ast.TemplateLiteral) {
	if n.Tag == nil {
		return
	}

	// Check if the tag is a CSS-in-JS function
	tagName := v.resolveTagName(n.Tag)
	if tagName == "" {
		return
	}

	if !v.isCSSTag(tagName) {
		return
	}

	// Build CSS from template elements and expressions
	cssContent := v.buildTemplateCSS(n)
	if cssContent == "" {
		return
	}

	line := v.lineAt(n.OpenQuote)
	compName := v.extractComponentFromTag(tagName)

	v.result.Entries = append(v.result.Entries, CSSInJSEntry{
		CSS:           cssContent,
		ComponentName: compName,
		Kind:          "tagged-template",
		SourceLine:    line,
	})
}

// visitCallExpression handles css({...}) and styled.xxx({...}) calls with object arguments.
func (v *cssVisitor) visitCallExpression(n *ast.CallExpression) {
	if n.Callee == nil || n.Callee.Expr == nil {
		return
	}

	calleeName := v.resolveExprName(n.Callee)
	if !v.isCSSCallTarget(calleeName) {
		return
	}

	// Look for ObjectLiteral in arguments
	for _, arg := range n.ArgumentList {
		if arg.Expr == nil {
			continue
		}
		obj, ok := arg.Expr.(*ast.ObjectLiteral)
		if !ok {
			continue
		}

		css := v.objectLiteralToCSS(obj)
		if css == "" {
			continue
		}

		line := v.lineAt(n.LeftParenthesis)
		v.result.Entries = append(v.result.Entries, CSSInJSEntry{
			CSS:           css,
			ComponentName: "",
			Kind:          "object-style",
			SourceLine:    line,
		})
	}
}

// resolveTagName extracts the full name from a tagged template tag expression.
// Returns strings like "styled.button", "css", "keyframes", "styled(Component)".
func (v *cssVisitor) resolveTagName(expr *ast.Expression) string {
	if expr == nil || expr.Expr == nil {
		return ""
	}
	return v.resolveExprName(expr)
}

// resolveExprName recursively resolves an expression to a dotted name string.
func (v *cssVisitor) resolveExprName(expr *ast.Expression) string {
	if expr == nil || expr.Expr == nil {
		return ""
	}

	switch e := expr.Expr.(type) {
	case *ast.Identifier:
		return e.Name
	case *ast.MemberExpression:
		objName := v.resolveExprName(e.Object)
		if objName == "" {
			return ""
		}
		propName := v.resolveMemberPropName(e.Property)
		if propName == "" {
			return ""
		}
		return objName + "." + propName
	case *ast.CallExpression:
		// styled(Component) — resolve callee
		callee := v.resolveExprName(e.Callee)
		if callee == "" {
			return ""
		}
		// Get the argument for display: styled(Component) -> "styled(Component)"
		if len(e.ArgumentList) > 0 {
			argName := v.resolveExprName(&e.ArgumentList[0])
			if argName != "" {
				return callee + "(" + argName + ")"
			}
		}
		return callee + "()"
	default:
		return ""
	}
}

// resolveMemberPropName extracts the property name from a MemberProperty.
func (v *cssVisitor) resolveMemberPropName(mp *ast.MemberProperty) string {
	if mp == nil || mp.Prop == nil {
		return ""
	}
	switch p := mp.Prop.(type) {
	case *ast.Identifier:
		return p.Name
	default:
		return ""
	}
}

// isCSSTag returns true if the tag name represents a CSS-in-JS tagged template.
func (v *cssVisitor) isCSSTag(tag string) bool {
	// Direct function: css`...`, keyframes`...`, html`...`, injectGlobal`...`
	if cssTagFunctions[tag] {
		return true
	}
	// styled.xxx`...`
	if strings.HasPrefix(tag, "styled.") {
		return true
	}
	// styled(Component)`...`
	if strings.HasPrefix(tag, "styled(") {
		return true
	}
	return false
}

// isCSSCallTarget returns true if the callee name is a CSS-in-JS call target for object styles.
func (v *cssVisitor) isCSSCallTarget(name string) bool {
	if name == "css" {
		return true
	}
	if strings.HasPrefix(name, "styled.") {
		return true
	}
	if strings.HasPrefix(name, "styled(") {
		return true
	}
	return false
}

// buildTemplateCSS builds CSS content from a TemplateLiteral's elements and expressions.
// Expressions are replaced with var(--dynamic-N) placeholders.
func (v *cssVisitor) buildTemplateCSS(n *ast.TemplateLiteral) string {
	var b strings.Builder
	dynCount := 0

	for i, elem := range n.Elements {
		b.WriteString(elem.Parsed)
		// After each element (except the last), insert expression placeholder
		if i < len(n.Expressions) {
			dynCount++
			fmt.Fprintf(&b, "var(--dynamic-%d)", dynCount)
		}
	}

	return strings.TrimSpace(b.String())
}

// extractComponentFromTag extracts a component name from a tag string.
func (v *cssVisitor) extractComponentFromTag(tag string) string {
	// styled.button -> "button"
	if strings.HasPrefix(tag, "styled.") {
		return tag[7:]
	}
	// styled(Component) -> "Component"
	if strings.HasPrefix(tag, "styled(") {
		end := strings.Index(tag, ")")
		if end > 7 {
			return tag[7:end]
		}
	}
	// css, keyframes, etc. -> use as-is
	return tag
}

// objectLiteralToCSS converts an AST ObjectLiteral to CSS declarations.
func (v *cssVisitor) objectLiteralToCSS(obj *ast.ObjectLiteral) string {
	var decls []string
	for _, prop := range obj.Value {
		if prop.Prop == nil {
			continue
		}
		keyed, ok := prop.Prop.(*ast.PropertyKeyed)
		if !ok {
			continue
		}
		key := v.extractPropertyKey(keyed)
		if key == "" {
			continue
		}
		value := v.extractPropertyValue(keyed)
		if value == "" {
			continue
		}
		decls = append(decls, fmt.Sprintf("%s: %s;", camelToKebab(key), value))
	}
	return strings.Join(decls, " ")
}

// extractPropertyKey gets the key name from a PropertyKeyed node.
func (v *cssVisitor) extractPropertyKey(pk *ast.PropertyKeyed) string {
	if pk.Key == nil || pk.Key.Expr == nil {
		return ""
	}
	switch k := pk.Key.Expr.(type) {
	case *ast.Identifier:
		return k.Name
	case *ast.StringLiteral:
		return k.Value
	default:
		return ""
	}
}

// extractPropertyValue gets the value from a PropertyKeyed node.
func (v *cssVisitor) extractPropertyValue(pk *ast.PropertyKeyed) string {
	if pk.Value == nil || pk.Value.Expr == nil {
		return ""
	}
	switch val := pk.Value.Expr.(type) {
	case *ast.StringLiteral:
		return val.Value
	case *ast.NumberLiteral:
		key := v.extractPropertyKey(pk)
		kebab := camelToKebab(key)
		raw := fmt.Sprintf("%g", val.Value)
		if !unitlessProperties[kebab] {
			raw += "px"
		}
		return raw
	case *ast.TemplateLiteral:
		// Template literal value: `${...}` — extract parsed elements
		var b strings.Builder
		for _, elem := range val.Elements {
			b.WriteString(elem.Parsed)
		}
		return strings.TrimSpace(b.String())
	default:
		return ""
	}
}

// lineAt returns the 1-based line number for a given AST index position.
func (v *cssVisitor) lineAt(idx ast.Idx) int {
	pos := int(idx)
	if pos <= 0 || pos > len(v.src) {
		return 1
	}
	return strings.Count(v.src[:pos], "\n") + 1
}

// camelToKebab converts camelCase or PascalCase to kebab-case.
// Handles vendor prefixes: "WebkitAnimation" -> "-webkit-animation", "MozTransform" -> "-moz-transform".
func camelToKebab(s string) string {
	if s == "" {
		return s
	}

	var b strings.Builder

	// Check for vendor prefix (starts with uppercase and known prefix)
	vendorPrefixes := []string{"Webkit", "Moz", "Ms", "O"}
	isVendor := false
	for _, vp := range vendorPrefixes {
		if strings.HasPrefix(s, vp) {
			b.WriteByte('-')
			isVendor = true
			break
		}
	}
	_ = isVendor

	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// objectStyleToCSS converts a map of property->value to CSS declaration string.
func objectStyleToCSS(props map[string]string) string {
	var decls []string
	for k, v := range props {
		decls = append(decls, fmt.Sprintf("%s: %s;", camelToKebab(k), v))
	}
	return strings.Join(decls, " ")
}
