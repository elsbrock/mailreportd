# mailreportd

[![CI](https://github.com/elsbrock/mailreportd/actions/workflows/ci.yml/badge.svg)](https://github.com/elsbrock/mailreportd/actions/workflows/ci.yml)

mailreportd reads DMARC and SMTP TLS reports from a mailbox, checks the SPF,
DKIM, DMARC, and MTA-STS records that your domains publish, and exports the
results as Prometheus metrics and a JSON API.

Website: <https://mailreportd.iodev.org>

## Features

- Parses DMARC aggregate reports ([RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)),
  DMARC failure reports ([RFC 6591](https://www.rfc-editor.org/rfc/rfc6591)), and
  SMTP TLS reports ([RFC 8460](https://www.rfc-editor.org/rfc/rfc8460)).
- Reads reports from an IMAP mailbox or a maildir. Accepts TLS reports over
  HTTPS (`POST /tlsrpt`) if you enable it.
- Checks published records every 15 minutes by default:
  - SPF: number of DNS lookups against the limit of 10.
  - DKIM: selector state (`ok`, `missing`, `revoked`, `malformed`, `weak`) and
    key size.
  - DMARC: policy, subdomain policy, `pct`, and authorization of external
    `rua` addresses.
  - MTA-STS: mode, `max_age`, whether `mx` covers all MX hosts, and whether the
    policy changed without a new `id`.
- Classifies each sending server as `self`, `forwarder`, or `unknown` based on
  your SPF record.
- Encrypts failure report content at rest.
- Never modifies the mailbox.

mailreportd doesn't include a web UI. It doesn't check DANE, which requires a
validating DNS resolver, or BIMI, which doesn't affect delivery.

## Install

Choose one of the following:

```sh
# Go 1.25 or later
go install github.com/elsbrock/mailreportd@latest

# Container image
docker pull ghcr.io/elsbrock/mailreportd

# Nix
nix run github:elsbrock/mailreportd -- -config config.yaml
```

Binaries for Linux and macOS are on the
[releases page](https://github.com/elsbrock/mailreportd/releases). The flake
also provides a NixOS module (`nixosModules.default`).

## Quick start

1. Set the `rua` tag of your DMARC record, and of your TLS-RPT record, to an
   address that delivers to an IMAP mailbox.
1. Copy [`config.example.yaml`](config.example.yaml) to `config.yaml` and set
   your domains, DKIM selectors, and mailbox.
1. Validate the configuration:

   ```sh
   mailreportd -config config.yaml -check
   ```

1. Start mailreportd:

   ```sh
   MAILREPORTD_IMAP_PASSWORD=... mailreportd -config config.yaml
   ```

   With Docker:

   ```sh
   docker run -d \
     -v ./config.yaml:/etc/mailreportd/config.yaml:ro \
     -v mailreportd:/var/lib/mailreportd \
     -e MAILREPORTD_IMAP_PASSWORD \
     -p 127.0.0.1:9188:9188 \
     ghcr.io/elsbrock/mailreportd
   ```

1. Add `localhost:9188` to your Prometheus scrape targets.

## Configuration

All options are documented in [`config.example.yaml`](config.example.yaml).
Things to know:

- **Passwords.** Set the IMAP password with `password_env` or `password_file`.
  The configuration file never contains it.
- **Folders.** The IMAP feeder reads `INBOX` and the folder that the server marks
  as `\Junk` (RFC 6154), because spam filters often file reports there. To read
  other folders, set `mailboxes`. To skip Junk, set `include_junk: false`. If a
  folder can't be read, the run counts as failed, even if other folders were
  read.
- **Maildir.** To read a local maildir instead of IMAP, use `type: maildir` and
  set `path`.
- **DKIM selectors.** List them under `policy.selectors`. DNS doesn't provide a
  way to discover selectors.
- **Failure reports.** To store their content, set `storage.failure_key_file`
  to a file that contains a 32-byte hex key (`openssl rand -hex 32`). Without a
  key, mailreportd stores only the report metadata.
- **TLS report submission.** `POST /tlsrpt` is off by default. Enable it with
  `http.tlsrpt_submission: true`. mailreportd serves plain HTTP, so put a
  TLS-terminating proxy in front of it.

### Source classification

mailreportd checks each sending server against your domain's SPF record:

| Class | Meaning |
|---|---|
| `self` | Your SPF record authorizes the server, or it's listed in `classification.trusted_sources`. |
| `forwarder` | Your SPF record doesn't authorize the server, but the mail has an aligned DKIM signature. |
| `unknown` | Neither. This includes spoofed mail. |

`self` means "authorized by your SPF record", not "sent by you". If your SPF
record includes a shared provider such as `include:_spf.google.com`, mail from
other customers of that provider also counts as `self`. A service that signs
with your domain but uses its own bounce domain counts as `forwarder`. To count
it as `self`, add its addresses to `classification.trusted_sources`.

## Endpoints

mailreportd has two listeners.

The public listener (`http.listen`, default `:8088`):

| Endpoint | Description |
|---|---|
| `GET /healthz` | Health check. |
| `POST /tlsrpt` | TLS report submission. Only if `http.tlsrpt_submission` is `true`. |

The private listener (`http.metrics_listen`, default `:9188`). Keep it on an
internal interface, because it exposes your sending infrastructure:

| Endpoint | Description |
|---|---|
| `GET /metrics` | Prometheus metrics. |
| `GET /api/v1/domains` | Summary per domain. |
| `GET /api/v1/sources` | Results per sending server, most failures first. |
| `GET /api/v1/signers` | DKIM signing domains and selectors, with daily counts. |
| `GET /api/v1/reporters` | Results per receiver and domain. |
| `GET /api/v1/failures` | Failure report metadata. `?include=content` returns the decrypted content and logs the access. |
| `GET /api/v1/quarantine` | Messages that failed to parse. |

Query parameters:

| Parameter | Endpoints | Description |
|---|---|---|
| `tenant` | All | Required if you configure more than one tenant. |
| `window` | All except `/quarantine` | How far back to look, as a Go duration. Default `720h`. |
| `limit` | All except `/domains` | Maximum number of entries. |
| `domain` | `/sources`, `/signers`, `/reporters` | Filter by domain. |
| `reporter` | `/sources`, `/signers` | Filter by receiver, for example `outlook.com`. |

### Find DKIM failures hidden by SPF

Mail passes DMARC if either DKIM or SPF passes and aligns. The `passing` field
counts DMARC passes. The `dkim_pass` and `spf_pass` fields count each mechanism
separately. If `dkim_pass` is lower than `passing`, some mail passes on SPF
only. To find it:

```sh
curl localhost:9188/api/v1/domains
curl 'localhost:9188/api/v1/reporters?domain=example.org'
curl 'localhost:9188/api/v1/sources?domain=example.org&reporter=outlook.com&limit=1000'
curl 'localhost:9188/api/v1/signers?domain=example.org&reporter=outlook.com'
```

In `/signers`, `signature_pass` counts valid signatures and
`evaluated_dkim_pass` counts signatures that the receiver accepted for DMARC. A
signer with a high `signature_pass` and a low `evaluated_dkim_pass` signs with
a domain that doesn't align with yours, for example a relay that signs with its
own domain.

## Metrics

Report metrics:

| Metric | Labels |
|---|---|
| `mailreport_dmarc_messages` | `tenant`, `domain`, `disposition`, `dkim`, `spf`, `source_class`, `reporter` |
| `mailreport_dmarc_policy` | `tenant`, `domain`, `p` |
| `mailreport_tlsrpt_sessions` | `tenant`, `domain`, `policy_type`, `result` |
| `mailreport_tlsrpt_failures` | `tenant`, `domain`, `result_type` |
| `mailreport_report_last_received_timestamp_seconds` | `tenant`, `domain`, `format` |
| `mailreport_raw_messages` | `tenant`, `state` |
| `mailreport_ingest_messages_total`, `mailreport_ingest_reports_total`, `mailreport_ingest_errors_total` | `tenant`, `feeder`, ... |
| `mailreport_ingest_last_success_timestamp_seconds` | `tenant`, `feeder` |

Published record metrics:

| Metric | Labels |
|---|---|
| `mailreport_spf_lookups`, `mailreport_spf_lookup_limit_exceeded`, `mailreport_spf_resolvable` | `tenant`, `domain` |
| `mailreport_dkim_record_state` | `tenant`, `domain`, `selector`, `state` |
| `mailreport_dkim_key_bits`, `mailreport_dkim_record_testing` | `tenant`, `domain`, `selector` |
| `mailreport_dmarc_record_valid`, `mailreport_dmarc_record_pct` | `tenant`, `domain` |
| `mailreport_dmarc_record_policy` | `tenant`, `domain`, `p`, `sp` |
| `mailreport_dmarc_rua_authorized` | `tenant`, `domain`, `rua_domain` |
| `mailreport_mtasts_record_valid`, `mailreport_mtasts_mx_covered`, `mailreport_mtasts_stale_id`, `mailreport_mtasts_max_age_seconds` | `tenant`, `domain` |
| `mailreport_mtasts_policy` | `tenant`, `domain`, `mode` |
| `mailreport_policy_check_timestamp_seconds` | `tenant`, `domain` |
| `mailreport_policy_check_errors_total` | `tenant`, `domain`, `check` |

Notes:

- Report metrics are gauges over the last `metrics.window` (default 30 days),
  not counters. Reports arrive late and out of order, so mailreportd recomputes
  them from stored data. Use ratios, not `rate()`.
- Source IP addresses and DKIM signing domains are never labels. Senders choose
  these values, so they would create unbounded series. Use the JSON API for
  them.
- `reporter` is the receiver's organization name, for example `google.com`. Only
  the `metrics.reporter_limit` (default 20) receivers with the most reports keep
  their name. Others are reported as `other`.
- `mailreport_dmarc_policy` is the policy that receivers saw.
  `mailreport_dmarc_record_policy` is the policy that you publish now.
- If a check can't complete, for example because of a DNS timeout,
  mailreportd increments `mailreport_policy_check_errors_total` and doesn't
  report the record as broken.
- mailreportd rebuilds metrics every `metrics.refresh_interval` (default 1m).
  Scrapes return the cached result.

## Alerts and dashboards

- [`contrib/prometheus/alerts.yaml`](contrib/prometheus/alerts.yaml): alerting
  rules.
- [`contrib/grafana/mailreportd.json`](contrib/grafana/mailreportd.json): a
  Grafana dashboard.

Don't alert on DKIM selectors in the `revoked` state. Many providers publish
empty selectors for key rotation. Don't alert on report volume either:
receivers send reports late or not at all.

## Retention

mailreportd deletes old data every `storage.sweep_interval` (default 6h). Set
the retention periods under `storage.retention`:

| Data | Key | Default |
|---|---|---|
| Aggregate and TLS report data | `aggregate` | 365 days |
| Failure report content, including quarantined failure reports | `forensic` | 7 days |
| Raw message content | `raw` | 7 days |

Other quarantined messages are kept until you delete them, so that you can
reprocess them after a parser fix.

## Operations

- **Mailbox access is read-only.** mailreportd doesn't flag, move, or delete
  messages. It stores its position for each folder in the database.
- **Ingestion is idempotent.** mailreportd skips messages it already processed
  and reports it already stored.
- **Reprocess the mailbox.** Stop mailreportd, delete the feeder's rows from the
  `feeder_cursor` table, and start mailreportd again. The `feeder` column has
  the format `<name>/<folder>`. The default name is `imap-<index>`.
- **Renaming a feeder** also makes mailreportd read the mailbox from the start.
- **Quarantine.** Messages that fail to parse are stored with the error.
  Autoreplies and spam are recorded as ignored, not quarantined.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
nix build    # builds and runs the tests
```

The end-to-end tests run a real IMAP server and check the output of `/metrics`
and the JSON API.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a security issue, see
[`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
