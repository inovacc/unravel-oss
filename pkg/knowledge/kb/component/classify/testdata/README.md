# classify testdata

## v1_baseline_buckets.json

Golden bucket counts for the rule-only classifier path, captured against
the canonical minimal corpus (3 modules: AuthService / AesGcmCipher / Foo)
seeded by `pkg/knowledge/kb/component/classify/classify_integration_test.go`
and `cmd/kb_classify_auto_integration_test.go`.

**Purpose (D-45-INTEGRATION-RUNS-RULE-PATH):** lock the v1 rule path
output so that turning on `--classifier=auto` against a host *without*
sampling capability produces byte-identical bucket counts. Any drift
forces a deliberate re-capture.

### How to re-capture (only when rule registry intentionally changes)

```
# Run the auto-mode integration test once with EXPECTED_BASELINE_REWRITE=1
# (exit code 0 + writes the new buckets back to this file). Then commit.
EXPECTED_BASELINE_REWRITE=1 \
  go test -tags=integration -run TestKBClassify_AutoMode_NoSession_UsesRulePath ./cmd/...
```

The rewrite flag is intentionally undocumented in CI; only humans should
flip the baseline, and only with a SUMMARY-level deviation note.

### Schema

- `buckets` — `map[bucket-name]count`. Bucket names match the taxonomy
  enforced by `pkg/knowledge/kb/component/runtime`.
- Underscored keys (`_comment`, `_classifier`, ...) are documentation-only;
  test code reads only the `buckets` field.
