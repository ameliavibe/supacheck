# @supacheck/semgrep-rules

A subset of supacheck's rules expressed as Semgrep YAML, for users who want a
quick Semgrep rulepack to drop into an existing Semgrep CI. **The CLI is the
canonical implementation.** This Semgrep pack is intentionally approximate, for
three reasons:

1. Semgrep's generic / regex-based matchers cannot fully reproduce the
   chain-walker (R02) or the migration-history state machine (R06).
2. Cross-file consistency rules (R06, R07) are not expressible as single-file
   Semgrep patterns.
3. The CLI ships fixtures and deterministic auto-fix; Semgrep does not.

What this pack contains:

| Rule | Status |
|------|--------|
| R01 (DAL cookie-form bypass) | Full coverage. Identical semantics to the CLI. |
| R03 (bare auth.uid in policy) | Approximate. Catches the common cases; the CLI's lookback is stricter. |
| R04a (SECURITY DEFINER hygiene) | Approximate. Three sub-checks merged into one rule; the CLI breaks them apart for more actionable diagnostics. |

For the full 7-rule rulepack with deterministic fixes, baseline mode, and
SARIF output, use the CLI:

```
npm install -g supacheck
supacheck init
supacheck scan
```

## Running this pack

```
semgrep --config packages/semgrep-rules/rules
```

Or, once published, via Semgrep's registry namespace:

```
semgrep --config p/supacheck
```

## License

Apache 2.0. See the [root LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
