// Package config loads and validates the daemon configuration.
//
// The configuration deliberately describes protocols and mailboxes, never a
// particular MTA or delivery provider. A working install is one binary, one
// config file, and one mailbox.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole of the daemon's runtime configuration.
type Config struct {
	Log            Log            `yaml:"log"`
	HTTP           HTTP           `yaml:"http"`
	Storage        Storage        `yaml:"storage"`
	Metrics        Metrics        `yaml:"metrics"`
	Classification Classification `yaml:"classification"`
	Tenants        []Tenant       `yaml:"tenants"`
	Feeders        []Feeder       `yaml:"feeders"`
}

// Log controls the structured logging handler.
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text or json
}

// HTTP describes the two listeners.
//
// They are separate because they carry different things. The public listener
// serves only liveness today and TLS-RPT submission later. The private one
// serves metrics and the read API, both of which expose a domain's sending
// topology and must not be published.
type HTTP struct {
	Listen        string `yaml:"listen"`
	MetricsListen string `yaml:"metrics_listen"`
}

// Storage describes the embedded database and how long each class of report is
// kept.
type Storage struct {
	Path          string        `yaml:"path"`
	Retention     Retention     `yaml:"retention"`
	SweepInterval time.Duration `yaml:"sweep_interval"`
}

// Retention holds per-class retention windows. Failure reports carry recipient
// addresses and message content, so their window is separate and short.
type Retention struct {
	Raw       time.Duration `yaml:"raw"`
	Aggregate time.Duration `yaml:"aggregate"`
	Forensic  time.Duration `yaml:"forensic"`
}

// Metrics controls the exported aggregation.
type Metrics struct {
	// Window is how far back the exported aggregates reach. Thirty days
	// comfortably spans the reporting lag of every large receiver.
	Window time.Duration `yaml:"window"`
	// RefreshInterval is how often the snapshot is rebuilt. Scrapes serve the
	// cached snapshot, so this is what bounds metric staleness, not the scrape
	// interval.
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

// Classification controls how report sources are attributed.
type Classification struct {
	// TrustedSources are addresses or prefixes always treated as our own.
	//
	// This exists for senders that legitimately cannot appear in SPF, such as a
	// relay that only signs with DKIM. It is an override, not the mechanism:
	// the default answer comes from the domain's own SPF record, so the daemon
	// stays correct when the infrastructure changes.
	TrustedSources []string `yaml:"trusted_sources"`
	// CacheTTL is how long an SPF expansion is reused.
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// Tenant scopes stored data. Single-tenant installs declare exactly one and
// never think about it again; the field exists from the first migration so that
// adding a second tenant later is configuration rather than a schema rewrite.
type Tenant struct {
	ID      string   `yaml:"id"`
	Domains []string `yaml:"domains"`
}

// Feeder is a source of report bytes. Feeders are interchangeable: each yields
// opaque bytes plus a locator, and nothing below this layer knows how a report
// arrived.
type Feeder struct {
	// Name identifies the feeder in logs, metrics, and its stored cursor. It
	// must stay stable across restarts: changing it makes the feeder rescan the
	// mailbox from the beginning.
	Name   string `yaml:"name"`
	Type   string `yaml:"type"` // imap
	Tenant string `yaml:"tenant"`

	// IMAP
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
	// PasswordFile reads the credential from a file, which is how systemd
	// delivers it via LoadCredential. Preferred over the environment: a
	// process environment is readable from /proc and tends to end up in crash
	// dumps and child processes.
	PasswordFile string        `yaml:"password_file"`
	Mailbox      string        `yaml:"mailbox"`
	Interval     time.Duration `yaml:"interval"`
	Insecure     bool          `yaml:"insecure"`
}

// Password resolves the feeder credential. Credentials are never read from the
// config file itself so that the file stays committable and secrets arrive
// through sops, systemd credentials, or whatever the operator already uses.
//
// A file wins over the environment when both are set, because the file is the
// more specific instruction and silently preferring the environment would make
// a stale variable shadow a rotated credential.
func (f Feeder) Password() (string, error) {
	if f.PasswordFile != "" {
		data, err := os.ReadFile(f.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("read password_file %q: %w", f.PasswordFile, err)
		}
		// Trailing newlines are near-universal in files written by humans and
		// by sops; an unstripped one turns into a baffling auth failure.
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if f.PasswordEnv != "" {
		return os.Getenv(f.PasswordEnv), nil
	}
	return "", nil
}

// Load reads, defaults, and validates the configuration at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse defaults and validates configuration bytes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = ":8088"
	}
	if c.HTTP.MetricsListen == "" {
		c.HTTP.MetricsListen = ":9188"
	}
	if c.Storage.Path == "" {
		c.Storage.Path = "/var/lib/mailreportd/reports.db"
	}
	if c.Storage.Retention.Raw == 0 {
		c.Storage.Retention.Raw = 7 * 24 * time.Hour
	}
	if c.Storage.Retention.Aggregate == 0 {
		c.Storage.Retention.Aggregate = 365 * 24 * time.Hour
	}
	if c.Storage.Retention.Forensic == 0 {
		c.Storage.Retention.Forensic = 30 * 24 * time.Hour
	}
	if c.Storage.SweepInterval == 0 {
		c.Storage.SweepInterval = 6 * time.Hour
	}
	if c.Metrics.Window == 0 {
		c.Metrics.Window = 30 * 24 * time.Hour
	}
	if c.Metrics.RefreshInterval == 0 {
		c.Metrics.RefreshInterval = time.Minute
	}
	if c.Classification.CacheTTL == 0 {
		c.Classification.CacheTTL = 15 * time.Minute
	}

	for i := range c.Feeders {
		f := &c.Feeders[i]
		if f.Tenant == "" && len(c.Tenants) == 1 {
			f.Tenant = c.Tenants[0].ID
		}
		if f.Name == "" {
			f.Name = fmt.Sprintf("%s-%d", f.Type, i)
		}
		if f.Type == "imap" {
			if f.Port == 0 {
				f.Port = 993
			}
			if f.Mailbox == "" {
				f.Mailbox = "INBOX"
			}
			if f.Interval == 0 {
				f.Interval = 5 * time.Minute
			}
		}
	}
}

func (c *Config) validate() error {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: unknown level %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format: unknown format %q", c.Log.Format)
	}

	if len(c.Tenants) == 0 {
		return fmt.Errorf("tenants: at least one tenant is required")
	}
	seen := make(map[string]bool, len(c.Tenants))
	for i, t := range c.Tenants {
		if t.ID == "" {
			return fmt.Errorf("tenants[%d]: id is required", i)
		}
		if seen[t.ID] {
			return fmt.Errorf("tenants[%d]: duplicate id %q", i, t.ID)
		}
		seen[t.ID] = true
		if len(t.Domains) == 0 {
			return fmt.Errorf("tenants[%d]: at least one domain is required", i)
		}
	}

	names := make(map[string]bool, len(c.Feeders))
	for i, f := range c.Feeders {
		if f.Tenant == "" {
			return fmt.Errorf("feeders[%d]: tenant is required when more than one tenant is declared", i)
		}
		if !seen[f.Tenant] {
			return fmt.Errorf("feeders[%d]: unknown tenant %q", i, f.Tenant)
		}
		// Two feeders sharing a name would share a cursor and silently skip
		// each other's messages.
		if names[f.Name] {
			return fmt.Errorf("feeders[%d]: duplicate name %q", i, f.Name)
		}
		names[f.Name] = true

		switch f.Type {
		case "imap":
			if f.Host == "" {
				return fmt.Errorf("feeders[%d]: host is required", i)
			}
			if f.Username == "" {
				return fmt.Errorf("feeders[%d]: username is required", i)
			}
			if f.PasswordEnv == "" && f.PasswordFile == "" {
				return fmt.Errorf("feeders[%d]: one of password_env or password_file is required", i)
			}
		case "":
			return fmt.Errorf("feeders[%d]: type is required", i)
		default:
			return fmt.Errorf("feeders[%d]: unknown type %q", i, f.Type)
		}
	}

	return nil
}
