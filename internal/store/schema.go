package store

// migrations are applied in order and never edited once released. Each entry's
// index is its version.
//
// Every table carries tenant_id from the first migration. A single-tenant
// install pins it to a constant and never thinks about it; adding the column
// later would mean rewriting every query in the daemon.
var migrations = []string{
	`
CREATE TABLE raw_report (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id   TEXT    NOT NULL,
	checksum    TEXT    NOT NULL,
	feeder      TEXT    NOT NULL,
	source_ref  TEXT    NOT NULL DEFAULT '',
	message_id  TEXT    NOT NULL DEFAULT '',
	filename    TEXT    NOT NULL DEFAULT '',
	received_at INTEGER NOT NULL,
	state       TEXT    NOT NULL,
	error       TEXT    NOT NULL DEFAULT '',
	body        BLOB,
	UNIQUE (tenant_id, checksum)
);

CREATE INDEX idx_raw_report_state ON raw_report (tenant_id, state, received_at);

CREATE TABLE report (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id     TEXT    NOT NULL,
	identity      TEXT    NOT NULL,
	format        TEXT    NOT NULL,
	reporter      TEXT    NOT NULL,
	reporter_mail TEXT    NOT NULL DEFAULT '',
	report_ref    TEXT    NOT NULL DEFAULT '',
	domain        TEXT    NOT NULL,
	begin_at      INTEGER NOT NULL,
	end_at        INTEGER NOT NULL,
	ingested_at   INTEGER NOT NULL,
	raw_report_id INTEGER REFERENCES raw_report (id) ON DELETE SET NULL,
	policy_p      TEXT    NOT NULL DEFAULT '',
	policy_sp     TEXT    NOT NULL DEFAULT '',
	policy_adkim  TEXT    NOT NULL DEFAULT '',
	policy_aspf   TEXT    NOT NULL DEFAULT '',
	policy_pct    INTEGER NOT NULL DEFAULT 100,
	UNIQUE (tenant_id, identity)
);

CREATE INDEX idx_report_window ON report (tenant_id, format, end_at);
CREATE INDEX idx_report_domain ON report (tenant_id, domain, end_at);

CREATE TABLE dmarc_row (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id     TEXT    NOT NULL,
	report_id     INTEGER NOT NULL REFERENCES report (id) ON DELETE CASCADE,
	domain        TEXT    NOT NULL,
	end_at        INTEGER NOT NULL,
	source_ip     TEXT    NOT NULL,
	message_count INTEGER NOT NULL,
	disposition   TEXT    NOT NULL,
	dkim          TEXT    NOT NULL,
	spf           TEXT    NOT NULL,
	header_from   TEXT    NOT NULL DEFAULT '',
	envelope_from TEXT    NOT NULL DEFAULT '',
	reasons       TEXT    NOT NULL DEFAULT '[]',
	dkim_auth     TEXT    NOT NULL DEFAULT '[]',
	spf_auth      TEXT    NOT NULL DEFAULT '[]'
);

-- The exporter scans by window and groups by outcome; the source address is
-- carried along for classification but is never a Prometheus label.
CREATE INDEX idx_dmarc_row_window ON dmarc_row (tenant_id, end_at, domain);
CREATE INDEX idx_dmarc_row_source ON dmarc_row (tenant_id, source_ip, end_at);
CREATE INDEX idx_dmarc_row_report ON dmarc_row (report_id);

CREATE TABLE tlsrpt_policy (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id     TEXT    NOT NULL,
	report_id     INTEGER NOT NULL REFERENCES report (id) ON DELETE CASCADE,
	domain        TEXT    NOT NULL,
	end_at        INTEGER NOT NULL,
	policy_type   TEXT    NOT NULL,
	mx_hosts      TEXT    NOT NULL DEFAULT '[]',
	successful    INTEGER NOT NULL,
	failed        INTEGER NOT NULL,
	failures      TEXT    NOT NULL DEFAULT '[]'
);

CREATE INDEX idx_tlsrpt_window ON tlsrpt_policy (tenant_id, end_at, domain);
CREATE INDEX idx_tlsrpt_report ON tlsrpt_policy (report_id);

-- Feeders track their own position rather than flagging or moving messages.
-- The mailbox may be shared with a human and with other tools, so mutating it
-- would be a side effect the operator never asked for.
CREATE TABLE feeder_cursor (
	tenant_id    TEXT    NOT NULL,
	feeder       TEXT    NOT NULL,
	uid_validity INTEGER NOT NULL DEFAULT 0,
	last_uid     INTEGER NOT NULL DEFAULT 0,
	updated_at   INTEGER NOT NULL,
	PRIMARY KEY (tenant_id, feeder)
);

CREATE TABLE ingest_usage (
	tenant_id  TEXT    NOT NULL,
	day        TEXT    NOT NULL,
	format     TEXT    NOT NULL,
	reports    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (tenant_id, day, format)
);
`,
	`
-- Failure reports (RFC 6591). The clear columns are envelope facts no more
-- sensitive than what aggregate reports carry; everything naming a recipient
-- or containing message content lives in the sealed content blob. A NULL
-- content with encrypted = 0 means no key was configured at ingest time and
-- the PII was deliberately dropped.
CREATE TABLE failure_report (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id     TEXT    NOT NULL,
	report_id     INTEGER NOT NULL REFERENCES report (id) ON DELETE CASCADE,
	domain        TEXT    NOT NULL,
	end_at        INTEGER NOT NULL,
	auth_failure  TEXT    NOT NULL DEFAULT '',
	source_ip     TEXT    NOT NULL DEFAULT '',
	reporting_mta TEXT    NOT NULL DEFAULT '',
	delivery      TEXT    NOT NULL DEFAULT '',
	arrival_at    INTEGER NOT NULL,
	encrypted     INTEGER NOT NULL DEFAULT 0,
	content       BLOB
);

CREATE INDEX idx_failure_window ON failure_report (tenant_id, end_at, domain);
CREATE INDEX idx_failure_report ON failure_report (report_id);

-- Every read of decrypted failure content leaves a row here. The metadata
-- view is not logged; it contains nothing the aggregate path does not.
CREATE TABLE failure_access_log (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id  TEXT    NOT NULL,
	at         INTEGER NOT NULL,
	peer       TEXT    NOT NULL DEFAULT '',
	report_ids TEXT    NOT NULL DEFAULT '[]'
);
`,
	`
-- A quarantined failure report is still recipient PII. sensitive = 1 marks a
-- body that is sealed (or was dropped for want of a key) and ages out on the
-- failure-report retention rather than being kept until someone looks.
ALTER TABLE raw_report ADD COLUMN sensitive INTEGER NOT NULL DEFAULT 0;
`,
}
