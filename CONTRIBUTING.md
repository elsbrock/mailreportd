# Contributing

Contributions are welcome: bug reports, report samples that fail to parse,
documentation fixes, and code.

## Before you start

- For a bug, open an issue with the mailreportd version (`mailreportd -version`),
  the relevant log lines, and, if a report fails to parse, the error from
  `GET /api/v1/quarantine`.
- For a new feature or a larger change, open an issue first so that we can agree
  on the approach before you write code.
- Read [`PRODUCT.md`](PRODUCT.md) for the scope and non-goals. Changes that add a
  web UI or depend on a specific MTA or mail provider are out of scope.

## Report samples

Real reports from new receivers are the most useful test data. Before you attach
one to an issue or add it as a fixture, remove personal data:

- Replace your domains with `example.org` or `example.com`.
- Replace IP addresses with documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
- Don't share DMARC failure reports. They contain recipient addresses and
  message content.

## Development

You need the Go version listed in `go.mod`. Nix is optional.

```console
$ go test ./...
$ go test -race ./...
$ go vet ./...
$ gofmt -l .        # must print nothing
$ nix build         # optional; builds and runs the test suite
```

CI runs the same checks on every pull request.

## Guidelines

- Don't add source IP addresses, DKIM signing domains, or other values that a
  sender chooses as Prometheus labels. Expose them through the JSON API instead.
- Add a test for every parser change, with a fixture that reproduces the
  problem.
- Update `README.md` when you change configuration, metrics, or endpoints.
- Write commit messages in the
  [Conventional Commits](https://www.conventionalcommits.org/) format, for
  example `fix(report): accept ISO timestamps in date_range`.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE). There is no contributor license agreement.
