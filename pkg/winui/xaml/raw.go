/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// XmlnsXAML is the WinFX XAML namespace URI carrying x:Key, x:Bind, x:Name, etc.
const XmlnsXAML = "http://schemas.microsoft.com/winfx/2006/xaml"

// ParseRawXAML walks a raw .xaml file with encoding/xml, populating the
// returned entry's ResourceKeys (x:Key under the WinFX namespace),
// ControlTypes (deduped, document order), and Bindings (raw markup-extension
// strings starting with `{Binding` or `{x:Bind`). Malformed XML is recorded
// in entry.Errors; this function never panics on file content.
func ParseRawXAML(path string) (entry winui.XAMLEntry, err error) {
	entry.Kind = "raw"
	entry.Path = path

	defer func() {
		if r := recover(); r != nil {
			entry.Errors = append(entry.Errors, fmt.Sprintf("xaml parse panic: %v", r))
		}
	}()

	f, oerr := os.Open(path) //nolint:gosec // walker pre-validates path
	if oerr != nil {
		return entry, oerr
	}
	defer func() { _ = f.Close() }()

	dec := xml.NewDecoder(f)
	// Strict defaults — encoding/xml rejects DTDs by default; we don't enable
	// CharsetReader so non-UTF8/ASCII XAML returns an error rather than
	// crashing.
	seen := map[string]struct{}{}

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			entry.Errors = append(entry.Errors, fmt.Sprintf("xaml parse error: %v", terr))
			return entry, nil
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		local := se.Name.Local
		if _, dup := seen[local]; !dup && local != "" {
			seen[local] = struct{}{}
			entry.ControlTypes = append(entry.ControlTypes, local)
		}
		for _, attr := range se.Attr {
			// x:Key under the WinFX namespace -> resource key.
			if attr.Name.Local == "Key" && attr.Name.Space == XmlnsXAML {
				entry.ResourceKeys = append(entry.ResourceKeys, attr.Value)
			}
			// Markup extensions of interest: {Binding ...} or {x:Bind ...}.
			v := attr.Value
			if len(v) >= 2 && v[0] == '{' && v[len(v)-1] == '}' {
				if strings.Contains(v, "Binding") || strings.Contains(v, "x:Bind") {
					entry.Bindings = append(entry.Bindings, v)
				}
			}
		}
	}
	return entry, nil
}
