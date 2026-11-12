# Security policy

## Reporting a vulnerability

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. That creates a private advisory only the maintainers can see. Please do not open a public issue for a vulnerability.

Include what you can of:

- the package and version (`supacheck` or `@supacheck/safe-fetch`)
- what an attacker can do, and what they need to do it
- a minimal reproduction: a URL, a migration file, or a few lines of code

You should hear back within a week. If the report is confirmed, a fix is released first and the advisory is published after, with credit to you unless you ask otherwise.

## What counts

**`@supacheck/safe-fetch`.** Any way to make `safeFetch` or `assertSafeFetchUrl` send a request to, or approve, a private, loopback, link-local or metadata address is a vulnerability. The limits the package documents are not: DNS rebinding and headers being forwarded on redirects are described in its README.

**`supacheck` (the CLI and rules).** A vulnerability is something that harms the person running it: code execution or file writes caused by a crafted repository, config file or migration, or output that leaks file contents it should not. The CLI reads your files and writes only its own config and baseline files, a report file when you ask for one, and, with `fix`, the files it reports.

A rule that misses a real problem (a false negative) is a bug that matters, but it is not a vulnerability in supacheck. Open a normal issue with the smallest input that shows it.

## Supported versions

Only the latest published version of each package receives fixes.
