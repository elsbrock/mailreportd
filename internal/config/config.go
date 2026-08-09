// Package config loads and validates the daemon configuration.
//
// The configuration deliberately describes protocols and mailboxes, never a
// particular MTA or delivery provider. A working install is one binary, one
// config file, and one mailbox.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole of the daemon's runtime configuration.
type Config struct {
	Log     Log      `yaml:"log"`
	HTTP    HTTP     `yaml:"http"`
	Storage Storage  `yaml:"storage"`
	Tenants []Tenant `yaml:"tenants"`
	Feeders []Feeder `yaml:"feeders"`
}

// Log controls the structured logging handler.
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text or json
}

// HTTP describes the two listeners. They are separate so that the metrics
// endpoint can stay on a private interface while report submission is exposed.
type HTTP struct {
	Listen        string `yaml:"listen"`
	MetricsListen string `yaml:"metrics_listen"`
}

// Storage describes the embedded database and how long each class of report is
// kept. Forensic reports carry recipient addresses and message content, so
// their retention is separate and expected to be much shorter.
type Storage struct {
	Path      string    `yaml:"path"`
	Retention Retention `yaml:"retention"`
}

// Retention holds per-class retention windows.
type Retention struct {
	Raw       time.Duration `yaml:"raw"`
	Aggregate time.Duration `yaml:"aggregate"`
	Forensic  time.Duration `yaml:"forensic"`
}

// Tenant scopes stored data. Single-tenant installs declare exactly one and
// never think about it again; the field exists from the first migration so that
// adding a second tenant later is configuration rather than a schema rewrite.
type Tenant struct {
	ID      string   `yaml:"id"`
	Domains []string `yaml:"domains"`
}

// Feeder is a source of report bytes. Feeders are interchangeable: each yields
// opaque bytes plus a hint, and nothing below this layer knows how a report
// arrived.
type Feeder struct {
	Type   string `yaml:"type"` // imap
	Tenant string `yaml:"tenant"`

	// IMAP
	Host        string        `yaml:"host"`
	Port        int           `yaml:"port"`
	Username    string        `yaml:"username"`
	PasswordEnv string        `yaml:"password_env"`
	Mailbox     string        `yaml:"mailbox"`
	Interval    time.Duration `yaml:"interval"`
}

// Password resolves the feeder credential from the environment. Credentials are
// never read from the config file itself so that the file stays committable and
// secrets arrive through sops, systemd credentials, or whatever the operator
// already uses.
func (f Feeder) Password() string {
	if f.PasswordEnv == "" {
		return ""
	}
	return os.Getenv(f.PasswordEnv)
}

// Load reads, defaults, and validates the configuration at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

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

	for i := range c.Feeders {
		f := &c.Feeders[i]
		if f.Tenant == "" && len(c.Tenants) == 1 {
			f.Tenant = c.Tenants[0].ID
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

	for i, f := range c.Feeders {
		if f.Tenant == "" {
			return fmt.Errorf("feeders[%d]: tenant is required when more than one tenant is declared", i)
		}
		if !seen[f.Tenant] {
			return fmt.Errorf("feeders[%d]: unknown tenant %q", i, f.Tenant)
		}
		switch f.Type {
		case "imap":
			if f.Host == "" {
				return fmt.Errorf("feeders[%d]: host is required", i)
			}
			if f.Username == "" {
				return fmt.Errorf("feeders[%d]: username is required", i)
			}
			if f.PasswordEnv == "" {
				return fmt.Errorf("feeders[%d]: password_env is required", i)
			}
		case "":
			return fmt.Errorf("feeders[%d]: type is required", i)
		default:
			return fmt.Errorf("feeders[%d]: unknown type %q", i, f.Type)
		}
	}

	return nil
}
