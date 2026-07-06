/*
Copyright (c) 2026 Security Research

Package runtime wires the per-platform package_id resolvers into the binary
via blank-import (D-09 / D-CVE-LATESTPROBER pattern). Importers of this
package get every registered resolver without taking direct dependencies on
analyzer subpackages, breaking the import-cycle that would otherwise force
the kb/identity core to know about every analyzer.

Phase 29 ships only the UWP canary. Phase 30 adds Android / iOS / deb / rpm
resolvers as additional blank-imports here.
*/
package runtime

import (
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity/resolvers/uwp"
)
