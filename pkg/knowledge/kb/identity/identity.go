/*
Copyright (c) 2026 Security Research

Package identity ships the stable kb_id / ks_id derivation, identity-merge
primitive, alias resolver, and parallel-safe epoch allocator that anchor the
v2.5 KB versioned-store catalog. It is the cornerstone API consumed by the
Phase 30 ingest writer, the Phase 32 CLI read path, and the Day-1
`unravel kb merge` subcommand.

Decisions encoded here:

  - D-29-IDENTITY-INPUTS — kb_id = sha256("<package_id>|<platform>")[:16]
    when package_id present; canonical_name fallback otherwise. publisher_cn
    is NEVER part of the hash (mitigates PITFALLS-CRIT-1 cert-rotation fork).
  - D-29-HASH-IMPL       — crypto/sha256 Go-side; pgcrypto digest() reserved
    for the legacy Phase-34 backfill UPDATE.
  - D-29-EPOCH-ALLOC     — pg_advisory_xact_lock(hashtext('kb_epoch:'||kb_id))
    plus COALESCE(MAX(epoch),0)+1 in the same tx. Lock auto-released on
    commit/rollback.
  - D-29-MERGE-SQL       — INSERT kb_aliases + UPDATE knowledge_sources +
    DELETE kb_apps in a single tx; no merge chains.
  - D-29-MERGE-RESOLVER  — ResolveAlias coalesces a kb_aliases lookup so
    analysts can pass either form to read commands.

Per-platform package_id resolvers register via init() (blank-import pattern,
mirrors D-09 / D-CVE-LATESTPROBER). The UWP resolver ships in this phase as
the canary; Android / iOS / deb / rpm resolvers land in Phase 30.
*/
package identity
