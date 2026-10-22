---
name: php2shell
description: Check whether PHP on a website or server is vulnerable to PHP2Shell (CVE-2026-109618, CVE-2026-109619), find PHP workers that need a restart, and look for signs of compromise. Use when the user asks about PHP2Shell, those CVEs, or whether their PHP is patched.
---

# PHP2Shell check

Use the `php2shell` CLI (https://github.com/0xgitpushpray/php2shell). Pick the cheapest command that answers the question:

| You have | Run |
|---|---|
| A PHP version string (e.g. from `php -v`) | `php2shell classify 8.3.12 --json` |
| Only a website URL | `php2shell check https://example.com --deep --json` |
| A shell on the server | `sudo php2shell local --json` |
| A server that may already be compromised | `sudo php2shell hunt --json` (optionally pass web roots) |

If the binary is missing: `go install github.com/0xgitpushpray/php2shell/cmd/php2shell@latest`.

## Reading results

Each result has `status`, `confidence`, `reason` and `remediation`.

- `patched`, `vendor-patched`: safe for PHP2Shell. Exit code 0.
- `vulnerable`, `eol`, `restart-required`: at risk. Exit code 1. Relay the `remediation` text.
- `unknown`: not determined. Exit code 3. **Never report unknown as safe.** For URLs, suggest running `local` on the server.

A `vulnerable` result with `low` confidence is a vendor build (e.g. `8.3.6-0ubuntu0.24.04.2`) that may carry a backported fix; only `php2shell local` on that server can confirm it via the package changelog.

`hunt` findings are heuristics: `high` severity deserves immediate review, `low` ones (recently modified files) are usually legitimate deploys. Never delete files on the user's behalf; recommend preserving evidence first.

Only check systems the user owns or is authorized to test.
