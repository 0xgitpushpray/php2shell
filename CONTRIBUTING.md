# Contributing

Contributions are welcome: code, advisory data, distro knowledge and bug reports.

## Development

You need Go 1.24 or newer. There are no other dependencies.

```sh
go build ./cmd/php2shell
go vet ./...
go test ./...
```

Tests use local HTTP servers, fake PHP binaries and stubbed package managers,
so they need neither PHP nor network access.

## Updating the advisory data

The vulnerability data lives in [`internal/advisory/advisory.json`](internal/advisory/advisory.json).
It is compiled into the binary, and `php2shell update` downloads the copy on
`main`, so a merged data fix reaches users without a new release.

When you change it:

1. Bump `revision` to today's date (`YYYY-MM-DD`). Clients only take data with a newer revision.
2. Link the official source (php.net, a GHSA, or the vendor advisory) in the pull request.
3. Run `go test ./...`. The loader validates the file, and the tests pin the expected fixed releases.

## Hunt rules

Content rules live in [`internal/hunt/hunt.go`](internal/hunt/hunt.go). Each rule
needs a sample in `TestContentRules` and must not match the clean samples there.

Never commit working web shells or exploit code, not even as test fixtures.
Build samples from fragments at runtime, as the existing tests do. Antivirus
software quarantines files that contain real web-shell patterns, which breaks
checkouts on Windows.

## Scope

php2shell detects and reports. It does not exploit, and it does not modify the
systems it inspects. Pull requests that add exploit payloads or automatic
"cleanup" will not be merged.
