package feeder

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elsbrock/mailreportd/internal/store"
)

// fetchBatch bounds how many messages are held in memory at once. Reports are
// small, but a mailbox that has gone unread for a year is not.
const fetchBatch = 32

// IMAPConfig describes one mailbox to poll.
type IMAPConfig struct {
	Name     string
	Tenant   string
	Host     string
	Port     int
	Username string
	Password string
	Mailbox  string
	Interval time.Duration
	// Insecure disables TLS, for a local mailbox reached over a trusted
	// transport. It is never the default.
	Insecure bool
}

// IMAP polls a mailbox over IMAP.
//
// It opens the mailbox read-only and tracks its own position rather than
// flagging, moving or deleting messages. The mailbox commonly belongs to a
// human or is shared with another tool, and silently mutating it is a side
// effect nobody asked for. The cost is one small row of state per feeder.
type IMAP struct {
	cfg   IMAPConfig
	store *store.Store
	log   *slog.Logger
}

// NewIMAP returns a feeder for one mailbox.
func NewIMAP(cfg IMAPConfig, s *store.Store, log *slog.Logger) *IMAP {
	if cfg.Port == 0 {
		cfg.Port = 993
	}
	if cfg.Mailbox == "" {
		cfg.Mailbox = "INBOX"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &IMAP{cfg: cfg, store: s, log: log.With("feeder", cfg.Name)}
}

func (f *IMAP) Name() string            { return f.cfg.Name }
func (f *IMAP) Tenant() string          { return f.cfg.Tenant }
func (f *IMAP) Interval() time.Duration { return f.cfg.Interval }

// Run performs one poll.
func (f *IMAP) Run(ctx context.Context) (Stats, error) {
	var stats Stats

	client, err := f.dial()
	if err != nil {
		return stats, err
	}
	defer client.Close()

	if err := client.Login(f.cfg.Username, f.cfg.Password).Wait(); err != nil {
		return stats, fmt.Errorf("imap login as %q: %w", f.cfg.Username, err)
	}
	// The closure matters: `defer client.Logout().Wait()` would evaluate
	// Logout() now and send the command immediately, ending the session before
	// any work happens.
	defer func() { client.Logout().Wait() }()

	selected, err := client.Select(f.cfg.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return stats, fmt.Errorf("select mailbox %q: %w", f.cfg.Mailbox, err)
	}

	cursor, err := f.store.Cursor(ctx, f.cfg.Name)
	if err != nil {
		return stats, err
	}

	// A changed UIDVALIDITY means the server renumbered the mailbox and every
	// stored UID is meaningless. Rescanning from the start is correct and safe:
	// ingest deduplicates on message bytes, so nothing is counted twice.
	if cursor.UIDValidity != selected.UIDValidity {
		if cursor.UIDValidity != 0 {
			f.log.Warn("mailbox uidvalidity changed, rescanning",
				"was", cursor.UIDValidity, "now", selected.UIDValidity)
		}
		cursor = store.Cursor{UIDValidity: selected.UIDValidity}
	}

	uids, err := f.search(client, cursor.LastUID)
	if err != nil {
		return stats, err
	}
	if len(uids) == 0 {
		// Persist the cursor anyway: on a first run this records UIDVALIDITY so
		// a later change is detectable.
		return stats, f.store.SetCursor(ctx, f.cfg.Name, cursor)
	}

	f.log.Debug("fetching messages", "count", len(uids), "from_uid", cursor.LastUID+1)

	for start := 0; start < len(uids); start += fetchBatch {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		end := min(start+fetchBatch, len(uids))

		highest, err := f.fetchBatch(ctx, client, uids[start:end], &stats)
		if highest > cursor.LastUID {
			cursor.LastUID = highest
		}
		if err != nil {
			// Persist progress before returning: a mid-batch failure must not
			// re-download everything on the next pass.
			if cerr := f.store.SetCursor(ctx, f.cfg.Name, cursor); cerr != nil {
				f.log.Error("persist cursor after fetch failure", "err", cerr)
			}
			return stats, err
		}
	}

	return stats, f.store.SetCursor(ctx, f.cfg.Name, cursor)
}

func (f *IMAP) dial() (*imapclient.Client, error) {
	addr := net.JoinHostPort(f.cfg.Host, strconv.Itoa(f.cfg.Port))
	options := &imapclient.Options{}

	if f.cfg.Insecure {
		client, err := imapclient.DialInsecure(addr, options)
		if err != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
		return client, nil
	}

	client, err := imapclient.DialTLS(addr, &imapclient.Options{
		TLSConfig: &tls.Config{ServerName: f.cfg.Host, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return client, nil
}

// search returns the UIDs above the cursor.
//
// UIDs are strictly increasing within a UIDVALIDITY, so "everything above the
// last one processed" is both complete and cheap. It also means a message the
// operator moves into the mailbox by hand after the fact is picked up, because
// it gets a fresh UID.
func (f *IMAP) search(client *imapclient.Client, lastUID uint32) ([]imap.UID, error) {
	var set imap.UIDSet
	set.AddRange(imap.UID(lastUID+1), 0) // 0 means "*"

	data, err := client.UIDSearch(&imap.SearchCriteria{UID: []imap.UIDSet{set}}, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("search mailbox: %w", err)
	}

	// A range ending in "*" always matches the highest UID in the mailbox, even
	// when that UID is below the start of the range: the server normalizes
	// "5:*" to "highest:5" when the highest is 3. Without this filter the last
	// message is refetched on every single poll, forever.
	uids := data.AllUIDs()
	filtered := uids[:0]
	for _, uid := range uids {
		if uint32(uid) > lastUID {
			filtered = append(filtered, uid)
		}
	}
	return filtered, nil
}

// fetchBatch downloads and ingests one batch, returning the highest UID it got
// through even when it later fails.
func (f *IMAP) fetchBatch(ctx context.Context, client *imapclient.Client, uids []imap.UID, stats *Stats) (uint32, error) {
	set := imap.UIDSetNum(uids...)
	options := &imap.FetchOptions{
		UID:          true,
		InternalDate: true,
		// Peek, so that opening a report never marks it read for the human who
		// also uses this mailbox.
		BodySection: []*imap.FetchItemBodySection{{Peek: true}},
	}

	messages, err := client.Fetch(set, options).Collect()
	if err != nil {
		return 0, fmt.Errorf("fetch messages: %w", err)
	}

	var highest uint32
	for _, msg := range messages {
		body := bodyOf(msg)
		if len(body) == 0 {
			// Nothing to parse, but the UID is still processed: leaving it
			// below the cursor would refetch it forever.
			if uid := uint32(msg.UID); uid > highest {
				highest = uid
			}
			continue
		}

		received := msg.InternalDate
		if received.IsZero() {
			received = time.Now()
		}

		res, err := f.store.Ingest(ctx, store.RawMessage{
			Feeder:    f.cfg.Name,
			SourceRef: fmt.Sprintf("uid:%d", msg.UID),
			Received:  received,
			Body:      body,
		})
		if err != nil {
			return highest, fmt.Errorf("ingest uid %d: %w", msg.UID, err)
		}
		record(f.cfg.Tenant, f.cfg.Name, res, stats)

		if uid := uint32(msg.UID); uid > highest {
			highest = uid
		}
	}
	return highest, nil
}

func bodyOf(msg *imapclient.FetchMessageBuffer) []byte {
	for _, section := range msg.BodySection {
		if len(section.Bytes) > 0 {
			return section.Bytes
		}
	}
	return nil
}
