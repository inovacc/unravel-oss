/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// HTMLStyles holds all CSS-related content extracted from an HTML document.
type HTMLStyles struct {
	StyleBlocks  []StyleBlock  `json:"style_blocks"`
	InlineStyles []InlineStyle `json:"inline_styles"`
	LinkedSheets []string      `json:"linked_sheets"`
}

// StyleBlock represents a <style> block in HTML.
type StyleBlock struct {
	Content    string `json:"content"`
	Index      int    `json:"index"`
	SourceFile string `json:"source_file"`
}

// InlineStyle represents a style= attribute on an HTML element.
type InlineStyle struct {
	Style      string `json:"style"`
	Element    string `json:"element"`
	Classes    string `json:"classes"`
	ID         string `json:"id"`
	SourceFile string `json:"source_file"`
}

// extractFromHTML parses HTML content and extracts style blocks, inline styles,
// and linked stylesheet references using goquery.
func extractFromHTML(htmlContent []byte, sourcePath string) (*HTMLStyles, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("parse html %s: %w", sourcePath, err)
	}

	result := &HTMLStyles{}

	// Extract <style> blocks
	doc.Find("style").Each(func(i int, s *goquery.Selection) {
		content := strings.TrimSpace(s.Text())
		if content != "" {
			result.StyleBlocks = append(result.StyleBlocks, StyleBlock{
				Content:    content,
				Index:      i,
				SourceFile: sourcePath,
			})
		}
	})

	// Extract inline style= attributes
	doc.Find("[style]").Each(func(_ int, s *goquery.Selection) {
		style, exists := s.Attr("style")
		if !exists || strings.TrimSpace(style) == "" {
			return
		}
		tagName := goquery.NodeName(s)
		classes, _ := s.Attr("class")
		id, _ := s.Attr("id")
		result.InlineStyles = append(result.InlineStyles, InlineStyle{
			Style:      strings.TrimSpace(style),
			Element:    tagName,
			Classes:    strings.TrimSpace(classes),
			ID:         strings.TrimSpace(id),
			SourceFile: sourcePath,
		})
	})

	// Extract <link rel="stylesheet"> hrefs
	doc.Find("link[rel='stylesheet']").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && strings.TrimSpace(href) != "" {
			result.LinkedSheets = append(result.LinkedSheets, strings.TrimSpace(href))
		}
	})

	return result, nil
}

// htmlStylesToStylesheets converts extracted HTML styles into Stylesheet structs.
func htmlStylesToStylesheets(styles *HTMLStyles, sourcePath string) []Stylesheet {
	var sheets []Stylesheet

	for _, block := range styles.StyleBlocks {
		sheets = append(sheets, Stylesheet{
			Path:         fmt.Sprintf("%s#style[%d]", sourcePath, block.Index),
			Source:       SourceHTMLStyle,
			Content:      []byte(block.Content),
			OriginalSize: int64(len(block.Content)),
		})
	}

	for i, inline := range styles.InlineStyles {
		// Wrap inline style in a selector for context
		var selector strings.Builder
		selector.WriteString(inline.Element)
		if inline.ID != "" {
			selector.WriteString("#" + inline.ID)
		}
		if inline.Classes != "" {
			for c := range strings.FieldsSeq(inline.Classes) {
				selector.WriteString("." + c)
			}
		}
		content := fmt.Sprintf("%s { %s }", selector.String(), inline.Style)
		sheets = append(sheets, Stylesheet{
			Path:         fmt.Sprintf("%s#inline[%d]", sourcePath, i),
			Source:       SourceHTMLInline,
			Content:      []byte(content),
			OriginalSize: int64(len(content)),
		})
	}

	return sheets
}
