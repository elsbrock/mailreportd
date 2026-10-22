// Package feeder moves report bytes from wherever they arrive into the store.
//
// Feeders are interchangeable by design: each yields opaque bytes plus a
// locator, and nothing below this layer knows how a report arrived. That is
// what lets a self-hosted deployment poll IMAP while a hosted one accepts LMTP,
// with no divergence in the parsing or storage path.
package feeder

import (
	"context"
	"log/slog"
	"time"

	"github.com/elsbrock/mailreportd/internal/metrics"
	"github.com/elsbrock/mailreportd/internal/store"
)

// Feeder is one source of report messages.
type Feeder interface {
	// Name identifies the feeder in logs, metrics and its stored cursor. It
	// must be stable across restarts.
	Name() string
	// Tenant is the tenant whose store the feeder writes to.
	Tenant() string
	// Interval is how often Run should be called.
	Interval() time.Duration
	// Run performs one pass. It must be safe to call again after any failure.
	Run(ctx context.Context) (Stats, error)
}

// Stats summarizes one pass.
type Stats struct {
	Messages   int
	Reports    int
	Duplicate  int
	Ignored    int
	Quarantine int
}

// Run drives one feeder on its interval until the context is cancelled.
//
// A failing pass is logged and retried on the next tick rather than killing the
// daemon: a mailbox being briefly unreachable is an operational event, not a
// reason to stop exporting the reports already collected.
func Run(ctx context.Context, f Feeder, log *slog.Logger) {
	log = log.With("feeder", f.Name(), "tenant", f.Tenant())

	runOnce := func() {
		started := time.Now()
		stats, err := f.Run(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			metrics.IngestErrors.WithLabelValues(f.Tenant(), f.Name()).Inc()
			log.Error("feeder run failed", "err", err, "elapsed", time.Since(started))
			return
		}

		metrics.IngestLastSuccess.WithLabelValues(f.Tenant(), f.Name()).Set(float64(time.Now().Unix()))
		if stats.Messages > 0 || stats.Reports > 0 {
			log.Info("feeder run complete",
				"messages", stats.Messages,
				"reports", stats.Reports,
				"duplicate", stats.Duplicate,
				"ignored", stats.Ignored,
				"quarantined", stats.Quarantine,
				"elapsed", time.Since(started))
		} else {
			log.Debug("feeder run complete: nothing new", "elapsed", time.Since(started))
		}
	}

	// Run immediately so a restart does not wait a full interval before the
	// first poll.
	runOnce()

	ticker := time.NewTicker(f.Interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

// record folds one ingest result into stats and the ingest counters.
func record(tenant, name string, res store.IngestResult, stats *Stats) {
	stats.Messages++
	stats.Reports += res.Stored

	result := res.State
	switch {
	case res.Redundant():
		result = "duplicate"
		stats.Duplicate++
	case res.State == store.StateIgnored:
		stats.Ignored++
	case res.State == store.StateQuarantined:
		stats.Quarantine++
	}

	metrics.IngestMessages.WithLabelValues(tenant, name, result).Inc()
	if res.Stored > 0 {
		metrics.IngestReports.WithLabelValues(tenant, name).Add(float64(res.Stored))
	}
}
