# mailreportd

Ingests DMARC aggregate and SMTP TLS reports from a mailbox, stores them, and
exposes bounded aggregates for Prometheus plus per-source detail over JSON.

It knows protocols, not products. Inputs are RFC-defined report formats reached
over IMAP; outputs are Prometheus text and a JSON API. No MTA admin API, no
delivery-provider API, no log tailing, no assumption that you run Grafana, Nix,
or any particular mail server. A working install is one binary, one config file,
and one mailbox.

See `docs/specs/report-ingest.md` for the design and the reasoning behind it.

## What it does

Two things, and they answer different questions. Reports tell you what
receivers made of your mail yesterday. Policy checks tell you what your DNS
says right now.

### Report ingest

- **DMARC aggregate reports** (RFC 7489) — parsed into per-source authentication
  results, tolerant of the ways real reporters deviate from the schema.
- **SMTP TLS reports** (RFC 8460) — parsed into session and failure counts.
- **Source classification** — each reporting source is resolved against the
  domain's own published SPF record and bucketed as `self`, `forwarder` or
  `unknown`. Nothing about your infrastructure is hardcoded, so this stays
  correct when your infrastructure changes.

### Published policy health

Reports arrive a day late and only if a receiver bothers. A broken policy is
knowable now, from a lookup. Every check reads public DNS and public HTTPS and
nothing else — no MTA API, no provider API, no privileged access.

- **SPF health** (RFC 7208) — how many of the ten DNS lookups the record
  consumes. Above ten it permerrors at real receivers, so SPF stops passing
  entirely rather than degrading.
- **DKIM selectors** (RFC 6376) — missing, revoked, malformed, weak or valid,
  told apart. An empty `p=` is a revocation, not a typo, and needs a different
  fix from a selector that was never published. Selectors must be listed in
  config: DNS offers no way to enumerate names under `_domainkey`.
- **DMARC record** (RFC 7489) — the published policy, the resolved subdomain
  policy, and `pct=`. Below 100 reads as enforcement while enforcing on a
  sample.
- **External destination authorisation** (RFC 7489 §7.1) — when `rua=` points
  off-domain, that domain must authorise it. Without the record most large
  receivers send nothing, and an empty mailbox looks like a quiet week.
- **MTA-STS** (RFC 8461) — mode, `max_age`, whether `mx:` still covers your live
  MX, and whether the policy body changed without its `id` being bumped. A
  drifted `mx:` makes enforcing senders refuse delivery outright.

DANE and BIMI are deliberately absent; `docs/specs/policy-health.md` says why.

A check that cannot complete is not a check that failed. A DNS timeout leaves
the verdict series absent and moves `mailreport_policy_check_errors_total`
instead, so "we could not tell" never reads as "it is broken".

## Quick start

```console
$ mailreportd -config config.yaml -check     # validate configuration
$ mailreportd -config config.yaml
```

Copy `config.example.yaml` and point it at the mailbox your `rua=` address
delivers to. The IMAP password is named by environment variable, never written
in the file, so the file stays committable.

## Endpoints

Two listeners, because they carry different things.

**Public** (`http.listen`) — safe to expose:

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | liveness |

**Private** (`http.metrics_listen`) — keep on an internal interface:

| Endpoint | Purpose |
|---|---|
| `GET /metrics` | Prometheus exposition |
| `GET /api/v1/domains` | per-domain summary |
| `GET /api/v1/sources` | per-source detail, worst offenders first |
| `GET /api/v1/quarantine` | messages that failed to parse |

The read API exposes source addresses and reporter identities — together, your
whole sending topology. That is why it is not on the public listener.

Query parameters: `window` (Go duration, default `720h`), `domain`, `limit`,
`tenant`.

## Metrics

Source addresses are **never** labels. A month of reports contains tens of
thousands of distinct sources, most seen once; exporting them would destroy the
time series database. The store keeps full detail, Prometheus gets bounded
series, and the read API bridges the gap.

| Metric | Labels |
|---|---|
| `mailreport_dmarc_messages` | `tenant`, `domain`, `disposition`, `dkim`, `spf`, `source_class` |
| `mailreport_tlsrpt_sessions` | `tenant`, `domain`, `policy_type`, `result` |
| `mailreport_tlsrpt_failures` | `tenant`, `domain`, `result_type` |
| `mailreport_report_last_received_timestamp_seconds` | `tenant`, `domain`, `format` |
| `mailreport_raw_messages` | `tenant`, `state` |
| `mailreport_spf_lookups`, `_spf_lookup_limit_exceeded`, `_spf_resolvable` | `tenant`, `domain` |
| `mailreport_dmarc_policy` | `tenant`, `domain`, `p` |
| `mailreport_ingest_messages_total`, `_ingest_reports_total`, `_ingest_errors_total` | `tenant`, `feeder`, … |
| `mailreport_ingest_last_success_timestamp_seconds` | `tenant`, `feeder` |

Published-policy series, from the checks rather than from reports:

| Metric | Labels |
|---|---|
| `mailreport_dkim_record_state` | `tenant`, `domain`, `selector`, `state` |
| `mailreport_dkim_key_bits`, `_dkim_record_testing` | `tenant`, `domain`, `selector` |
| `mailreport_dmarc_record_valid`, `_dmarc_record_pct` | `tenant`, `domain` |
| `mailreport_dmarc_record_policy` | `tenant`, `domain`, `p`, `sp` |
| `mailreport_dmarc_rua_authorized` | `tenant`, `domain`, `rua_domain` |
| `mailreport_mtasts_record_valid`, `_mtasts_mx_covered`, `_mtasts_stale_id`, `_mtasts_max_age_seconds` | `tenant`, `domain` |
| `mailreport_mtasts_policy` | `tenant`, `domain`, `mode` |
| `mailreport_policy_check_timestamp_seconds` | `tenant`, `domain` |
| `mailreport_policy_check_errors_total` | `tenant`, `domain`, `check` |

`mailreport_dmarc_policy` and `mailreport_dmarc_record_policy` are not the same
thing. The first is the policy a reporter observed when it evaluated your mail;
the second is what you publish today. When they disagree, either a change has
not propagated or somebody's resolver sees a different answer than yours.

Report volumes are **gauges over a rolling window**, not counters: they are
recomputed from stored reports that arrive late and out of order, so a counter
would lie about rates. Alert on ratios within the window.

`_report_last_received_timestamp_seconds` exists so staleness is expressible.
A zero failure rate because nothing was ingested looks identical to a zero
failure rate because nothing failed — that distinction is the whole point.

Metrics are rebuilt on `metrics.refresh_interval` and scrapes serve the cached
snapshot, so a scrape never blocks on SQLite or DNS. That interval, not the
scrape interval, bounds staleness.

## Suggested alerts

Two signals are worth waking someone for, and one explicitly is not.

- **Authentication regression** — the pass rate for `source_class="self"` drops
  over a sustained window. Your own mail is failing somewhere.
- **TLS failures** — `mailreport_tlsrpt_failures` above zero. There is no
  acceptable baseline for senders failing to negotiate TLS with you.
- **Not report volume.** Aggregate reports arriving late or not at all is
  normal and not actionable.

## Operational notes

- **Nothing in the mailbox is modified.** The feeder opens it read-only, peeks
  rather than marking read, and tracks its own position. The mailbox stays
  usable by a human or another tool.
- **Ingest is idempotent** at two levels: identical message bytes by checksum,
  and the same report arriving under different envelopes by report identity.
  Reprocessing the whole mailbox is safe and is the supported recovery path —
  clear the feeder's cursor row and restart.
- **Nothing is deleted because it failed to parse.** Unparseable reports go to
  quarantine with the error and the original bytes, and survive retention
  sweeps. Autoreplies and spam are recorded as ignored, not as failures, so
  quarantine stays a signal worth alerting on.
- **Renaming a feeder makes it rescan** from the beginning, because the name is
  its cursor key. Harmless, but it will re-download the mailbox.

## Development

```console
$ go test ./...          # unit and end-to-end
$ go test -race ./...
$ nix build              # builds and runs the suite
```

The end-to-end tests run a real IMAP server over a real socket and drive the
assembled daemon through to `/metrics` and the JSON API. The feeder's
correctness lives in protocol details, and a hand-rolled fake would only agree
with whatever the feeder happens to do.
