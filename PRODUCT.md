# Product

## Who it is for

People who run mail for their own domains, whether their own MTA (Postfix,
Stalwart, mailcow, docker-mailserver, Mail-in-a-Box) or a hosted provider, and
who already run Prometheus and Alertmanager. They want to be paged when mail
authentication breaks, not to open a dashboard every morning.

## Job to be done

Tell me, through the alerting I already have, when:

- my published mail policy is broken right now: DKIM selector missing or weak,
  SPF over its ten-lookup budget, MTA-STS `mx:` no longer covering my MX,
  DMARC reports addressed somewhere that is not authorised to receive them;
- receivers report that my mail failed DMARC, or that senders could not reach
  me over TLS.

## What makes it different

- Policy health checks exported continuously as metrics, beside the reports.
  The report tools surveyed are report viewers or parsers.
- Bounded Prometheus labels: no source IPs, no sender-chosen `d=` values.
- The mailbox is read-only: nothing is moved, flagged or deleted.

## Non-goals

- A web UI or dashboard of its own. Grafana or the JSON API covers that.
- Hosted service, accounts, billing.
- DANE and BIMI checks.
- Integrations with specific MTAs or delivery providers.

## Alternatives a user will weigh

- **parsedmarc**: the mature parser for aggregate, failure and TLS reports, but
  its output goes to Elasticsearch, OpenSearch or Splunk, and it has no
  Prometheus output.
- **dmarc-metrics-exporter**: a Prometheus exporter, DMARC aggregate only, and
  it moves processed mail into other folders.
- **dmarc-report-viewer**: a single binary with a web UI, DMARC and TLS-RPT,
  no metrics.
- **URIports, dmarcian, EasyDMARC, Postmark**: hosted services. Cheap or free,
  but your report data goes to a third party.
