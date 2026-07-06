/*
Copyright (c) 2026 Security Research

Package uwp registers the Windows-MSIX package_id resolver — the Phase 29
canary for the per-platform resolver dispatch (blank-import pattern).
Resolves the AppxManifest.xml `<Identity Name="...">` attribute as the
package_id used by Fingerprint to derive a stable kb_id.

Other platform resolvers (Android, iOS, deb, rpm) ship in Phase 30.
*/
package uwp

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

// maxManifestBytes caps the AppxManifest.xml size we will decode — bounds
// untrusted-input memory cost (T-29-05 mitigation).
const maxManifestBytes = 1 << 20 // 1 MiB

func init() {
	identity.Register("windows-msix", resolve)
}

// appxIdentity mirrors the subset of AppxManifest.xml we need: the
// `<Identity Name="..." Publisher="..." />` element under the root
// `<Package>`.
type appxIdentity struct {
	XMLName  xml.Name `xml:"Package"`
	Identity struct {
		Name      string `xml:"Name,attr"`
		Publisher string `xml:"Publisher,attr"`
	} `xml:"Identity"`
}

// resolve opens AppxManifest.xml at ctx.Path (treating ctx.Path as either
// the manifest file directly or a directory containing it), parses the
// `<Identity Name="...">` attribute, and returns it as the package_id.
func resolve(ctx identity.ResolverContext) (string, error) {
	path := ctx.Path
	if path == "" {
		return "", fmt.Errorf("uwp resolver: path is required")
	}
	if filepath.Base(path) != "AppxManifest.xml" {
		path = filepath.Join(path, "AppxManifest.xml")
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open appxmanifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes))
	if err != nil {
		return "", fmt.Errorf("read appxmanifest: %w", err)
	}

	var pkg appxIdentity
	if err := xml.Unmarshal(data, &pkg); err != nil {
		return "", fmt.Errorf("parse appxmanifest: %w", err)
	}

	name := strings.TrimSpace(pkg.Identity.Name)
	if name == "" {
		return "", fmt.Errorf("appxmanifest identity name is empty")
	}
	return name, nil
}
