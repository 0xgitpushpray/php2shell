# Security policy

## Reporting a vulnerability in php2shell

Please report security problems in php2shell itself (for example, a crafted
response header or file that crashes the scanner or makes it run code) through
[GitHub private vulnerability reporting](https://github.com/0xgitpushpray/php2shell/security/advisories/new).
Do not open a public issue.

You can expect an acknowledgement within a few days. Fixes are released as a
new tagged version.

## Wrong results

A wrong verdict (for example, a patched build reported as vulnerable, or the
reverse) is a bug, not a security vulnerability, unless it hides a vulnerable
system. Open a regular issue with the PHP version string, the package name and
version, and the `--json` output.

## PHP2Shell itself

php2shell does not handle reports about PHP. Report PHP vulnerabilities to the
PHP project: https://github.com/php/php-src/security
