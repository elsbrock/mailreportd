package feeder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elsbrock/mailreportd/internal/store"
)

// MaildirConfig describes one maildir to scan.
type MaildirConfig struct {
	Name     string
	Tenant   string
	Path     string
	Interval time.Duration
}

// Maildir scans a local maildir, for deployments where the report address
// delivers locally and there is no IMAP server to poll.
//
// It reads new/ and cur/ and treats both as input: which directory a message
// sits in is MUA state, not ingest state. The read-only guarantee holds exactly
// as it does for IMAP — no rename, no move, no delete. Deliberately absent is
// the conventional new/ → cur/ move, which would destroy the unseen state of
// any MUA sharing the maildir.
//
// Maildir has no UIDs, so there is no cheap "everything after X" query. Each
// pass enumerates both directories and asks the store, by checksum, whether the
// bytes are already known before decoding anything. Correctness never rests on
// the skip: ingest is idempotent regardless.
type Maildir struct {
	cfg   MaildirConfig
	store *store.Store
	log   *slog.Logger
}

// NewMaildir returns a feeder for one maildir.
func NewMaildir(cfg MaildirConfig, s *store.Store, log *slog.Logger) *Maildir {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Maildir{cfg: cfg, store: s, log: log.With("feeder", cfg.Name)}
}

func (f *Maildir) Name() string            { return f.cfg.Name }
func (f *Maildir) Tenant() string          { return f.cfg.Tenant }
func (f *Maildir) Interval() time.Duration { return f.cfg.Interval }

// Run performs one scan. tmp/ is skipped because the maildir contract says
// files there are still being written.
func (f *Maildir) Run(ctx context.Context) (Stats, error) {
	var stats Stats
	for _, sub := range []string{"new", "cur"} {
		if err := f.scanDir(ctx, filepath.Join(f.cfg.Path, sub), &stats); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func (f *Maildir) scanDir(ctx context.Context, dir string, stats *Stats) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// A missing new/ or cur/ means the path is not a maildir. That is a
		// configuration fault and must be loud: silently scanning nothing looks
		// exactly like a healthy quiet mailbox.
		return fmt.Errorf("read maildir: %w", err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Directories do not belong inside new/ or cur/, and dotfiles are
		// metadata by convention (dovecot keeps several).
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			// Vanished between enumeration and read: another process collected
			// it. Anything else is logged and retried next pass rather than
			// wedging the whole scan on one unreadable file.
			if !errors.Is(err, fs.ErrNotExist) {
				f.log.Warn("skipping unreadable message", "path", path, "err", err)
			}
			continue
		}
		if len(body) == 0 {
			continue
		}

		sum := sha256.Sum256(body)
		seen, err := f.store.SeenChecksum(ctx, hex.EncodeToString(sum[:]))
		if err != nil {
			return err
		}
		if seen {
			continue
		}

		received := time.Now()
		if info, err := entry.Info(); err == nil {
			received = info.ModTime()
		}

		res, err := f.store.Ingest(ctx, store.RawMessage{
			Feeder:    f.cfg.Name,
			SourceRef: "maildir:" + entry.Name(),
			Received:  received,
			Body:      body,
		})
		if err != nil {
			return fmt.Errorf("ingest %s: %w", path, err)
		}
		record(f.cfg.Tenant, f.cfg.Name, res, stats)
	}
	return nil
}
