package npm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const registryURL = "https://registry.npmjs.org"

// maxRegistryBytes caps the registry metadata response body to avoid
// unbounded memory growth from a malicious or oversized response.
const maxRegistryBytes = 32 << 20 // 32 MiB

// RegistryPackage holds npm registry metadata for a package.
type RegistryPackage struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	DistTags    map[string]string         `json:"dist-tags"`
	Versions    map[string]PackageVersion `json:"versions"`
	Time        map[string]string         `json:"time"`
	License     any                       `json:"license"`
	Homepage    string                    `json:"homepage"`
	Repository  any                       `json:"repository"`
	Maintainers []Maintainer              `json:"maintainers"`
}

// Maintainer represents an npm package maintainer.
type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// PackageVersion holds metadata for a specific package version.
type PackageVersion struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	Main            string            `json:"main"`
	Bin             any               `json:"bin"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Dist            Dist              `json:"dist"`
	NpmUser         *Maintainer       `json:"_npmUser,omitempty"`
	Maintainers     []Maintainer      `json:"maintainers,omitempty"`
}

// Dist holds distribution information for a package version.
type Dist struct {
	Tarball   string `json:"tarball"`
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity"`
}

// FetchInfo fetches package metadata from the npm registry.
// pkg can be "name" or "name@version".
func FetchInfo(pkg string) (*RegistryPackage, error) {
	name := pkg
	if idx := strings.LastIndex(pkg, "@"); idx > 0 {
		name = pkg[:idx]
	}

	// Scope packages use encoded slash: @scope%2fname
	urlName := name
	if strings.HasPrefix(name, "@") {
		urlName = strings.Replace(name, "/", "%2f", 1)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(fmt.Sprintf("%s/%s", registryURL, urlName))
	if err != nil {
		return nil, fmt.Errorf("npm registry request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %q not found on npm registry", name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var result RegistryPackage
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing registry response: %w", err)
	}

	return &result, nil
}

// FetchVersion fetches a specific version's metadata.
// If version is empty, the latest dist-tag is used.
func FetchVersion(name, version string) (*PackageVersion, error) {
	reg, err := FetchInfo(name)
	if err != nil {
		return nil, err
	}

	if version == "" {
		latest, ok := reg.DistTags["latest"]
		if !ok {
			return nil, fmt.Errorf("no latest dist-tag for package %q", name)
		}
		version = latest
	}

	pv, ok := reg.Versions[version]
	if !ok {
		return nil, fmt.Errorf("version %q not found for package %q", version, name)
	}

	return &pv, nil
}
