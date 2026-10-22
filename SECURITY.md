# Security policy

mailreportd stores data that can identify your mail infrastructure and, for
DMARC failure reports, recipient addresses and message content. Report security
issues privately.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/elsbrock/mailreportd/security/advisories/new).
Don't open a public issue.

Include the affected version, the configuration that is needed to reproduce the
issue, and the impact. You can expect an initial response within seven days.

## Supported versions

Only the latest release receives security fixes.

## Deployment notes

- Keep `http.metrics_listen` on an internal interface. The metrics endpoint and
  the JSON API expose your sending infrastructure, and
  `/api/v1/failures?include=content` returns decrypted failure report content.
- Store `storage.failure_key_file` outside the database directory, with
  permissions that only the mailreportd user can read.
