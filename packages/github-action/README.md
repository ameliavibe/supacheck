# supacheck GitHub Action

Runs supacheck against every pull request and emits findings as PR
annotations in the diff view. Optional SARIF output for GitHub Code Scanning.

## Quick start

Drop this into `.github/workflows/supacheck.yml`:

```yaml
name: supacheck

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - uses: ameliavibe/supacheck/packages/github-action@v1
```

Findings show up directly on changed lines in the PR diff view.

## SARIF + GitHub Code Scanning

To also push results into the GitHub Security tab:

```yaml
      - uses: ameliavibe/supacheck/packages/github-action@v1
        with:
          sarif-file: supacheck.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: supacheck.sarif
```

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `config` | (auto-discover) | Path to `.supacheck.yml`. |
| `format` | `github-actions` | Output format. |
| `baseline` | `true` | Honor `.supacheck-baseline.json` if present. |
| `sarif-file` | (none) | Path to write SARIF report. Combine with `github/codeql-action/upload-sarif`. |
| `version` | `latest` | npm version of supacheck to invoke. Pin for reproducible CI. |

## Behavior

- Runs `npx supacheck@<version> scan` against the checked-out tree.
- Emits one annotation per finding (GitHub renders them on the changed line).
- Exits non-zero if any *new* finding is reported (existing findings recorded
  in the baseline file do not fail the build).
- If `sarif-file` is set, runs a second scan in SARIF mode and writes the
  file. The SARIF step uses `|| true` so a scan failure does not block the
  upload of partial results.

## License

Apache 2.0. See the [root LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
