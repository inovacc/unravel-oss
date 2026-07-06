# Migrations

golang-migrate `NNNNNN_name.up.sql` / `.down.sql` pairs, embedded into
`pkg/knowledge/kb/db/db.go` via `//go:embed migrations/*.sql` and applied
in order by `db.Migrate` (`migrate` + `iofs` driver).

## Numbering gap: 000016 is intentionally missing

The sequence jumps `000015_enrich_human_review` -> `000017_drift_detection`.
`000016` was never assigned/committed — it is not a lost or reverted
migration, just a skipped sequence number during development. golang-migrate
only requires strictly increasing version numbers, not contiguous ones, so
this is safe and does not affect `Migrate`, `ForceVersion`, or the
`schema_migrations` version ledger. Do not reuse `000016` for a new
migration; the next new migration goes after the current head.

Reversibility (every `.up.sql` has a working `.down.sql`, and the full
chain round-trips up -> down -> up cleanly) is covered by the
`integration`-tagged test `TestMigrationsReversible` in
`pkg/knowledge/kb/db/migrations_reversible_integration_test.go`.
