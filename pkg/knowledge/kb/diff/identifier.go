/*
Copyright (c) 2026 Security Research
*/

package diff

import "fmt"

// Identifier returns the canonical kb_diffs.identifier value for the given
// (category, payload) pair, per D-30-DIFF-IDENTIFIER.
//
// The identifier convention is type-prefixed canonical form for index-friendly
// lookup:
//
//	dep        → name
//	capability → "<namespace>:<name>"  (empty namespace yields ":<name>")
//	url        → host
//	risk       → constant "risk-score"
//	cert       → fingerprint truncated to 16 chars (new wins; falls back to old)
//	fact       → "<category>/<key>"  (caller pre-composes into FactDiff.Key)
//	module     → body_sha256[:16]
//	component  → module_id (forward-compat; Phase 31)
//	file       → file_sha256[:16]
//
// Returns an error when category is unknown or payload type doesn't match the
// declared category.
func Identifier(category string, payload any) (string, error) {
	switch category {
	case CategoryDep:
		d, ok := payload.(DepDiff)
		if !ok {
			return "", fmt.Errorf("dep identifier requires DepDiff payload, got %T", payload)
		}
		return d.Name, nil
	case CategoryCapability:
		c, ok := payload.(CapabilityDiff)
		if !ok {
			return "", fmt.Errorf("capability identifier requires CapabilityDiff payload, got %T", payload)
		}
		return c.Namespace + ":" + c.Name, nil
	case CategoryURL:
		u, ok := payload.(URLDiff)
		if !ok {
			return "", fmt.Errorf("url identifier requires URLDiff payload, got %T", payload)
		}
		return u.Host, nil
	case CategoryRisk:
		return "risk-score", nil
	case CategoryCert:
		c, ok := payload.(CertDiff)
		if !ok {
			return "", fmt.Errorf("cert identifier requires CertDiff payload, got %T", payload)
		}
		fp := c.FingerprintNew
		if fp == "" {
			fp = c.FingerprintOld
		}
		if len(fp) > 16 {
			fp = fp[:16]
		}
		return fp, nil
	case CategoryFact:
		f, ok := payload.(FactDiff)
		if !ok {
			return "", fmt.Errorf("fact identifier requires FactDiff payload, got %T", payload)
		}
		return f.Key, nil
	case CategoryModule:
		m, ok := payload.(ModuleDiff)
		if !ok {
			return "", fmt.Errorf("module identifier requires ModuleDiff payload, got %T", payload)
		}
		s := m.BodySHA256
		if len(s) > 16 {
			s = s[:16]
		}
		return s, nil
	case CategoryComponent:
		c, ok := payload.(ComponentDiff)
		if !ok {
			return "", fmt.Errorf("component identifier requires ComponentDiff payload, got %T", payload)
		}
		return c.ModuleID, nil
	case CategoryFile:
		f, ok := payload.(FileDiff)
		if !ok {
			return "", fmt.Errorf("file identifier requires FileDiff payload, got %T", payload)
		}
		s := f.FileSHA256
		if len(s) > 16 {
			s = s[:16]
		}
		return s, nil
	default:
		return "", fmt.Errorf("unknown diff category %q", category)
	}
}
