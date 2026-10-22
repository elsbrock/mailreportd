package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimal = `
tenants:
  - id: default
    domains: [example.org]
`

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if cfg.Log.Level != "info" || cfg.Log.Format != "text" {
		t.Errorf("log = %+v", cfg.Log)
	}
	if cfg.HTTP.Listen == "" || cfg.HTTP.MetricsListen == "" {
		t.Errorf("http = %+v", cfg.HTTP)
	}
	if cfg.HTTP.Listen == cfg.HTTP.MetricsListen {
		t.Error("the public and private listeners must not default to the same address")
	}
	if cfg.Metrics.Window != 30*24*time.Hour {
		t.Errorf("metrics window = %v", cfg.Metrics.Window)
	}
	if cfg.Metrics.ReporterLimit != 20 {
		t.Errorf("metrics reporter_limit = %d, want 20", cfg.Metrics.ReporterLimit)
	}
	if cfg.Storage.Retention.Forensic >= cfg.Storage.Retention.Aggregate {
		t.Error("failure reports carry recipient data and must not be kept as long as aggregates")
	}
}

func TestFeederDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal + `
feeders:
  - type: imap
    host: mail.example.org
    username: dmarc@example.org
    password_env: PW
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	f := cfg.Feeders[0]
	if f.Port != 993 || f.Interval != 5*time.Minute {
		t.Errorf("feeder = %+v", f)
	}
	if len(f.Mailboxes) != 1 || f.Mailboxes[0] != "INBOX" {
		t.Errorf("mailboxes = %v, want [INBOX]", f.Mailboxes)
	}
	// Spam filters file reports under Junk; reading it must not depend on the
	// operator knowing that.
	if f.IncludeJunk == nil || !*f.IncludeJunk {
		t.Error("the \\Junk folder should be read by default")
	}
	// A single tenant should not have to be named on every feeder.
	if f.Tenant != "default" {
		t.Errorf("tenant = %q, want the only configured tenant", f.Tenant)
	}
	if f.Name == "" {
		t.Error("feeder should get a generated name")
	}
	if f.Insecure {
		t.Error("TLS must never be off by default")
	}
}

func TestFeederMailboxes(t *testing.T) {
	cfg, err := Parse([]byte(minimal + `
feeders:
  - type: imap
    name: legacy
    host: mail.example.org
    username: dmarc@example.org
    password_env: PW
    mailbox: Reports
  - type: imap
    name: listed
    host: mail.example.org
    username: dmarc@example.org
    password_env: PW
    mailboxes: [INBOX, Reports]
    include_junk: false
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	legacy, listed := cfg.Feeders[0], cfg.Feeders[1]
	if len(legacy.Mailboxes) != 1 || legacy.Mailboxes[0] != "Reports" {
		t.Errorf("legacy mailboxes = %v, want [Reports]: mailbox must keep working", legacy.Mailboxes)
	}
	if len(listed.Mailboxes) != 2 || listed.Mailboxes[1] != "Reports" {
		t.Errorf("listed mailboxes = %v", listed.Mailboxes)
	}
	if listed.IncludeJunk == nil || *listed.IncludeJunk {
		t.Error("include_junk: false must opt out")
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no tenants",
			yaml: "log:\n  level: info\n",
			want: "at least one tenant",
		},
		{
			name: "tenant without domains",
			yaml: "tenants:\n  - id: default\n",
			want: "at least one domain",
		},
		{
			name: "duplicate tenant",
			yaml: "tenants:\n  - id: a\n    domains: [x.example]\n  - id: a\n    domains: [y.example]\n",
			want: "duplicate id",
		},
		{
			name: "negative reporter limit",
			yaml: minimal + "metrics:\n  reporter_limit: -1\n",
			want: "reporter_limit",
		},
		{
			name: "unknown log level",
			yaml: minimal + "log:\n  level: chatty\n",
			want: "unknown level",
		},
		{
			name: "feeder without host",
			yaml: minimal + "feeders:\n  - type: imap\n    username: u\n    password_env: PW\n",
			want: "host is required",
		},
		{
			name: "feeder without any credential",
			yaml: minimal + "feeders:\n  - type: imap\n    host: h\n    username: u\n",
			want: "password_env or password_file",
		},
		{
			name: "feeder with mailbox and mailboxes",
			yaml: minimal + "feeders:\n  - type: imap\n    host: h\n    username: u\n    password_env: PW\n    mailbox: INBOX\n    mailboxes: [Reports]\n",
			want: "not both",
		},
		{
			name: "feeder with duplicate mailbox",
			yaml: minimal + "feeders:\n  - type: imap\n    host: h\n    username: u\n    password_env: PW\n    mailboxes: [INBOX, INBOX]\n",
			want: "duplicate mailbox",
		},
		{
			name: "unknown feeder type",
			yaml: minimal + "feeders:\n  - type: pigeon\n",
			want: "unknown type",
		},
		{
			name: "maildir feeder without path",
			yaml: minimal + "feeders:\n  - type: maildir\n",
			want: "path is required",
		},
		{
			name: "feeder naming an unknown tenant",
			yaml: minimal + "feeders:\n  - type: imap\n    tenant: other\n    host: h\n    username: u\n    password_env: PW\n",
			want: "unknown tenant",
		},
		{
			// Two feeders sharing a name would share a cursor and silently skip
			// each other's messages.
			name: "duplicate feeder name",
			yaml: minimal + `
feeders:
  - name: box
    type: imap
    host: a
    username: u
    password_env: PW
  - name: box
    type: imap
    host: b
    username: u
    password_env: PW
`,
			want: "duplicate name",
		},
		{
			name: "ambiguous tenant with several configured",
			yaml: `
tenants:
  - id: a
    domains: [a.example]
  - id: b
    domains: [b.example]
feeders:
  - type: imap
    host: h
    username: u
    password_env: PW
`,
			want: "tenant is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestPasswordComesFromEnvironment(t *testing.T) {
	t.Setenv("MAILREPORTD_TEST_PW", "s3cret")

	cfg, err := Parse([]byte(minimal + `
feeders:
  - type: imap
    host: h
    username: u
    password_env: MAILREPORTD_TEST_PW
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := cfg.Feeders[0].Password()
	if err != nil {
		t.Fatalf("password: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("password = %q", got)
	}

	// The secret must never be a field of the config file itself, so that the
	// file stays committable.
	if strings.Contains(strings.ToLower(string(mustMarshal(t, cfg))), "s3cret") {
		t.Error("the resolved secret must not round-trip into the config struct")
	}
}

func mustMarshal(t *testing.T, cfg *Config) []byte {
	t.Helper()
	// A trivial rendering is enough: the point is that no field holds the
	// plaintext.
	return []byte(strings.Join([]string{
		cfg.Feeders[0].Name,
		cfg.Feeders[0].Host,
		cfg.Feeders[0].Username,
		cfg.Feeders[0].PasswordEnv,
	}, " "))
}

func TestPasswordFromFile(t *testing.T) {
	// systemd's LoadCredential hands the secret over as a file, which is the
	// shape this deployment actually uses.
	path := filepath.Join(t.TempDir(), "imap-password")
	if err := os.WriteFile(path, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Parse([]byte(minimal + `
feeders:
  - type: imap
    host: h
    username: u
    password_file: ` + path + `
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, err := cfg.Feeders[0].Password()
	if err != nil {
		t.Fatalf("password: %v", err)
	}
	// The trailing newline must be stripped, or authentication fails in a way
	// that looks like a wrong password.
	if got != "from-a-file" {
		t.Errorf("password = %q, want the trimmed file contents", got)
	}
}

func TestPasswordFileWinsOverEnvironment(t *testing.T) {
	t.Setenv("MAILREPORTD_TEST_PW", "from-env")

	path := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(path, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Parse([]byte(minimal + `
feeders:
  - type: imap
    host: h
    username: u
    password_env: MAILREPORTD_TEST_PW
    password_file: ` + path + `
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, _ := cfg.Feeders[0].Password()
	if got != "from-file" {
		t.Errorf("password = %q: a stale environment variable must not shadow a rotated file", got)
	}
}

func TestPasswordFileMissingIsAnError(t *testing.T) {
	cfg, err := Parse([]byte(minimal + `
feeders:
  - type: imap
    host: h
    username: u
    password_file: /nonexistent/credential
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := cfg.Feeders[0].Password(); err == nil {
		t.Fatal("expected an error for a missing credential file")
	}
}
