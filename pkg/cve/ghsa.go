/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"time"
)

// cveIDRe is the strict allow-list for CVE identifiers passed to the gh CLI.
// Format: CVE-<4-digit-year>-<1..7 digits>
var cveIDRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{1,7}$`)

const ghsaShelloutTimeout = 5 * time.Second

// ghsaClient queries GitHub's GraphQL securityAdvisories via the gh CLI.
// We shell out so we inherit the user's existing gh authentication and
// avoid coding any direct API client.
type ghsaClient struct {
	ghPath string // empty = gh not installed
}

func newGHSAClient() *ghsaClient {
	p, err := exec.LookPath("gh")
	if err != nil {
		return &ghsaClient{}
	}
	return &ghsaClient{ghPath: p}
}

// ghsaRecord captures GHSA-only fields used by the merger.
type ghsaRecord struct {
	GHSAID      string
	WithdrawnAt *time.Time
	References  []string
	Aliases     []string
}

type ghsaGraphQLResp struct {
	Data struct {
		SecurityAdvisories struct {
			Nodes []struct {
				GHSAID      string `json:"ghsaId"`
				WithdrawnAt string `json:"withdrawnAt"`
				References  []struct {
					URL string `json:"url"`
				} `json:"references"`
				Identifiers []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"identifiers"`
			} `json:"nodes"`
		} `json:"securityAdvisories"`
	} `json:"data"`
}

// Lookup queries securityAdvisories for a given CVE-id alias. Returns nil
// gracefully when gh is missing or the query yields no hit.
func (c *ghsaClient) Lookup(ctx context.Context, cveID string) (*ghsaRecord, error) {
	if c == nil || c.ghPath == "" || cveID == "" {
		return nil, nil
	}
	// W5: validate cveID against strict allow-list before embedding in gh args.
	// Rejects any value that is not a well-formed CVE identifier, preventing
	// arg-injection via crafted package metadata (e.g. "x -H=Authorization:…").
	if !cveIDRe.MatchString(cveID) {
		return nil, fmt.Errorf("ghsa: invalid CVE ID %q (must match CVE-YYYY-NNNNNNN)", cveID)
	}
	cctx, cancel := context.WithTimeout(ctx, ghsaShelloutTimeout)
	defer cancel()

	const query = `query($cve:String!){securityAdvisories(identifier:{type:CVE,value:$cve}, first:1){nodes{ghsaId withdrawnAt references{url} identifiers{type value}}}}`

	cmd := exec.CommandContext(cctx, c.ghPath, "api", "graphql",
		"-f", "query="+query,
		"-f", "cve="+cveID)
	out, err := cmd.Output()
	if err != nil {
		// gh missing auth or no network — degrade silently.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, nil
		}
		return nil, fmt.Errorf("ghsa: gh exec: %w", err)
	}

	var parsed ghsaGraphQLResp
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("ghsa: decode: %w", err)
	}
	if len(parsed.Data.SecurityAdvisories.Nodes) == 0 {
		return nil, nil
	}
	n := parsed.Data.SecurityAdvisories.Nodes[0]
	rec := &ghsaRecord{GHSAID: n.GHSAID}
	if n.WithdrawnAt != "" {
		if t, err := time.Parse(time.RFC3339, n.WithdrawnAt); err == nil {
			rec.WithdrawnAt = &t
		}
	}
	for _, r := range n.References {
		rec.References = append(rec.References, r.URL)
	}
	for _, id := range n.Identifiers {
		rec.Aliases = append(rec.Aliases, id.Value)
	}
	return rec, nil
}
