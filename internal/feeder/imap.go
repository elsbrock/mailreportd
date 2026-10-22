package feeder

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/elsbrock/mailreportd/internal/store"
)

// fetchBatch bounds how many messages are held in memory at once. Reports are
// small, but a mailbox that has gone unread for a year is not.
const fetchBatch = 32

// IMAPConfig describes one IMAP account to poll.
type IMAPConfig struct {
	Name     string
	Tenant   string
	Host     string
	Port     int
	Username string
	Password string
	// Mailboxes are read in order. The first one keeps the cursor of the
	// former single-mailbox feeder, so upgrading does not rescan it.
	Mailboxes []string
	// IncludeJunk also reads the folder the server marks \Junk (RFC 6154),
	// found by attribute rather than by name.
	IncludeJunk bool
	Interval    time.Duration
	// Insecure disables TLS, for a local mailbox reached over a trusted
	// transport. It is never the default.
	Insecure bool
}

// IMAP polls one or more mailboxes of an account over IMAP.
//
// It opens each mailbox read-only and tracks its own position rather than
// flagging, moving or deleting messages. The mailbox commonly belongs to a
// human or is shared with another tool, and silently mutating it is a side
// effect nobody asked for. The cost is one small row of state per mailbox.
type IMAP struct {
	cfg   IMAPConfig
	store *store.Store
	log   *slog.Logger
}

// NewIMAP returns a feeder for one account.
func NewIMAP(cfg IMAPConfig, s *store.Store, log *slog.Logger) *IMAP {
	if cfg.Port == 0 {
		cfg.Port = 993
	}
	if len(cfg.Mailboxes) == 0 {
		cfg.Mailboxes = []string{"INBOX"}
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

// Run performs one poll of every mailbox.
//
// A failing mailbox does not stop the others: a Junk folder that cannot be
// selected must not cost the reports sitting in INBOX.
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

	var errs []error
	mailboxes := f.cfg.Mailboxes
	if f.cfg.IncludeJunk {
		junk, err := junkMailbox(client)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("find junk mailbox: %w", err))
		case junk != "" && !slices.Contains(mailboxes, junk):
			mailboxes = append(slices.Clip(mailboxes), junk)
		}
	}

	for _, mailbox := range mailboxes {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if err := f.runMailbox(ctx, client, mailbox, &stats); err != nil {
			errs = append(errs, fmt.Errorf("mailbox %q: %w", mailbox, err))
		}
	}
	return stats, errors.Join(errs...)
}

// junkMailbox returns the name of the mailbox carrying the \Junk attribute, or
// "" when the server marks none.
func junkMailbox(client *imapclient.Client) (string, error) {
	var options *imap.ListOptions
	// Without the extension the attribute may still be returned, but asking
	// for it is an error.
	if client.Caps().Has(imap.CapSpecialUse) {
		options = &imap.ListOptions{ReturnSpecialUse: true}
	}
	list, err := client.List("", "*", options).Collect()
	if err != nil {
		return "", err
	}
	for _, data := range list {
		if slices.Contains(data.Attrs, imap.MailboxAttrJunk) {
			return data.Mailbox, nil
		}
	}
	return "", nil
}

// cursorKey names the stored cursor of one mailbox. The first configured
// mailbox is the one a single-mailbox feeder used to read, keyed by the bare
// feeder name; that row moves to the new key on first read.
func (f *IMAP) cursorKey(mailbox string) string {
	return f.cfg.Name + "/" + mailbox
}

func (f *IMAP) cursor(ctx context.Context, mailbox string) (store.Cursor, error) {
	cursor, err := f.store.Cursor(ctx, f.cursorKey(mailbox))
	if err != nil || cursor != (store.Cursor{}) || mailbox != f.cfg.Mailboxes[0] {
		return cursor, err
	}
	// Adopted only for the first mailbox, which is where the old `mailbox`
	// setting lands. If an upgrade also changed which folder that is, the
	// UIDVALIDITY check below discards the cursor and rescans instead.
	legacy, err := f.store.Cursor(ctx, f.cfg.Name)
	if err != nil || legacy == (store.Cursor{}) {
		return legacy, err
	}
	// Move it rather than copy it: a legacy row left behind would be adopted
	// again after an operator clears the new one to force a rescan.
	if err := f.store.SetCursor(ctx, f.cursorKey(mailbox), legacy); err != nil {
		return store.Cursor{}, err
	}
	return legacy, f.store.DeleteCursor(ctx, f.cfg.Name)
}

// runMailbox polls one mailbox from its cursor.
func (f *IMAP) runMailbox(ctx context.Context, client *imapclient.Client, mailbox string, stats *Stats) error {
	log := f.log.With("mailbox", mailbox)
	key := f.cursorKey(mailbox)

	selected, err := client.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("select: %w", err)
	}

	cursor, err := f.cursor(ctx, mailbox)
	if err != nil {
		return err
	}

	// A changed UIDVALIDITY means the server renumbered the mailbox and every
	// stored UID is meaningless. Rescanning from the start is correct and safe:
	// ingest deduplicates on message bytes, so nothing is counted twice.
	if cursor.UIDValidity != selected.UIDValidity {
		if cursor.UIDValidity != 0 {
			log.Warn("mailbox uidvalidity changed, rescanning",
				"was", cursor.UIDValidity, "now", selected.UIDValidity)
		}
		cursor = store.Cursor{UIDValidity: selected.UIDValidity}
	}

	uids, err := f.search(client, cursor.LastUID)
	if err != nil {
		return err
	}
	if len(uids) == 0 {
		// Persist the cursor anyway: on a first run this records UIDVALIDITY so
		// a later change is detectable.
		return f.store.SetCursor(ctx, key, cursor)
	}

	log.Debug("fetching messages", "count", len(uids), "from_uid", cursor.LastUID+1)

	for start := 0; start < len(uids); start += fetchBatch {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+fetchBatch, len(uids))

		highest, err := f.fetchBatch(ctx, client, mailbox, uids[start:end], stats)
		if highest > cursor.LastUID {
			cursor.LastUID = highest
		}
		if err != nil {
			// Persist progress before returning: a mid-batch failure must not
			// re-download everything on the next pass.
			if cerr := f.store.SetCursor(ctx, key, cursor); cerr != nil {
				log.Error("persist cursor after fetch failure", "err", cerr)
			}
			return err
		}
	}

	return f.store.SetCursor(ctx, key, cursor)
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
func (f *IMAP) fetchBatch(ctx context.Context, client *imapclient.Client, mailbox string, uids []imap.UID, stats *Stats) (uint32, error) {
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
			SourceRef: fmt.Sprintf("%s uid:%d", mailbox, msg.UID),
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
