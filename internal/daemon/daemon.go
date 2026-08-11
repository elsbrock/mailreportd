// Package daemon wires the components together and runs them.
//
// The wiring lives here rather than in main so that tests can exercise the
// real assembly — the same mux, the same collector, the same feeders — instead
// of a reimplementation that agrees with itself.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/elsbrock/mailreportd/internal/api"
	"github.com/elsbrock/mailreportd/internal/classify"
	"github.com/elsbrock/mailreportd/internal/config"
	"github.com/elsbrock/mailreportd/internal/feeder"
	"github.com/elsbrock/mailreportd/internal/metrics"
	"github.com/elsbrock/mailreportd/internal/policy"
	"github.com/elsbrock/mailreportd/internal/store"
)

// Options are injection points for tests. Every field is optional and the zero
// value is what production uses.
type Options struct {
	// Resolver overrides DNS for SPF expansion and the policy checks.
	Resolver classify.Resolver
	// HTTPClient overrides the client used to fetch MTA-STS policies, which is
	// the only outbound request in the daemon that is not DNS.
	HTTPClient *http.Client
	// Version is reported in build info.
	Version string
}

// Daemon is an assembled but not yet running instance.
type Daemon struct {
	cfg       *config.Config
	log       *slog.Logger
	db        *store.DB
	stores    map[string]*store.Store
	collector *metrics.Collector
	registry  *prometheus.Registry
	feeders   []feeder.Feeder
}

// New assembles a daemon from configuration.
func New(cfg *config.Config, log *slog.Logger, opts Options) (*Daemon, error) {
	if log == nil {
		log = slog.Default()
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}

	db, err := store.Open(cfg.Storage.Path)
	if err != nil {
		return nil, err
	}

	stores := make(map[string]*store.Store, len(cfg.Tenants))
	tenants := make([]metrics.Tenant, 0, len(cfg.Tenants))
	for _, t := range cfg.Tenants {
		s := db.Tenant(t.ID)
		stores[t.ID] = s
		tenants = append(tenants, metrics.Tenant{ID: t.ID, Store: s, Domains: t.Domains})
	}

	overrides, err := parsePrefixes(cfg.Classification.TrustedSources)
	if err != nil {
		db.Close()
		return nil, err
	}
	classifier := classify.New(opts.Resolver, cfg.Classification.CacheTTL, overrides)

	// The checker shares the injected resolver with the classifier, so one fake
	// drives both in tests. classify.Resolver is a superset of what the policy
	// checks need, and a nil value stays nil through the conversion.
	var policyResolver policy.Resolver
	if opts.Resolver != nil {
		policyResolver = opts.Resolver
	}
	checker := policy.New(policyResolver, opts.HTTPClient, cfg.Policy.CacheTTL, cfg.Policy.Selectors)

	collector := metrics.NewCollector(tenants, classifier, checker, cfg.Metrics.Window, log)
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	if err := metrics.Register(registry, collector); err != nil {
		db.Close()
		return nil, fmt.Errorf("register metrics: %w", err)
	}
	metrics.BuildInfo.WithLabelValues(opts.Version).Set(1)

	feeders, err := buildFeeders(cfg, stores, log)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Daemon{
		cfg:       cfg,
		log:       log,
		db:        db,
		stores:    stores,
		collector: collector,
		registry:  registry,
		feeders:   feeders,
	}, nil
}

// Close releases the database handle.
func (d *Daemon) Close() error { return d.db.Close() }

// Stores exposes the tenant stores, for tests and for future feeders.
func (d *Daemon) Stores() map[string]*store.Store { return d.stores }

// Feeders exposes the configured feeders.
func (d *Daemon) Feeders() []feeder.Feeder { return d.feeders }

// Refresh rebuilds the metric snapshot.
func (d *Daemon) Refresh(ctx context.Context) { d.collector.Refresh(ctx) }

// PublicMux carries anything an outside party may reach. Today that is only the
// liveness probe; TLS-RPT HTTPS submission lands here later.
func (d *Daemon) PublicMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// PrivateMux carries metrics and the read API, both of which expose a domain's
// sending topology and belong on an internal interface.
func (d *Daemon) PrivateMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(d.registry, promhttp.HandlerOpts{}))
	api.New(d.stores, d.log).Register(mux)
	return mux
}

// Run starts the feeders, the refresh loop, the retention sweep and both
// listeners, and blocks until ctx is cancelled or a listener fails.
func (d *Daemon) Run(ctx context.Context) error {
	d.log.Info("starting",
		"tenants", len(d.cfg.Tenants),
		"feeders", len(d.feeders),
		"storage", d.cfg.Storage.Path,
	)
	if len(d.feeders) == 0 {
		// Worth saying out loud: the daemon will run happily and ingest
		// nothing, which looks identical to a healthy quiet mailbox.
		d.log.Warn("no feeders configured; no reports will be ingested")
	}

	// Populate metrics before the first scrape, so a freshly started daemon
	// does not report an empty stack.
	d.collector.Refresh(ctx)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	spawn := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	for _, f := range d.feeders {
		spawn(func() { feeder.Run(ctx, f, d.log) })
	}
	spawn(func() { d.refreshLoop(ctx) })
	spawn(func() { d.sweepLoop(ctx) })

	errc := make(chan error, 2)
	public := d.serve(ctx, errc, "public", d.cfg.HTTP.Listen, d.PublicMux())
	private := d.serve(ctx, errc, "private", d.cfg.HTTP.MetricsListen, d.PrivateMux())

	var runErr error
	select {
	case <-ctx.Done():
		d.log.Info("shutting down")
	case err := <-errc:
		runErr = err
	}

	cancel()
	shutdown(d.log, public, private)
	wg.Wait()
	return runErr
}

func (d *Daemon) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.Metrics.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.collector.Refresh(ctx)
		}
	}
}

func (d *Daemon) sweepLoop(ctx context.Context) {
	r := d.cfg.Storage.Retention
	retention := store.Retention{Raw: r.Raw, Aggregate: r.Aggregate, Forensic: r.Forensic}

	ticker := time.NewTicker(d.cfg.Storage.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for id, s := range d.stores {
				res, err := s.Sweep(ctx, retention, time.Now())
				if err != nil {
					d.log.Error("retention sweep failed", "tenant", id, "err", err)
					continue
				}
				if res.Reports > 0 || res.RawBodies > 0 {
					d.log.Info("retention sweep", "tenant", id,
						"reports_deleted", res.Reports, "bodies_cleared", res.RawBodies)
				}
			}
		}
	}
}

func (d *Daemon) serve(ctx context.Context, errc chan<- error, name, addr string, mux *http.ServeMux) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		d.log.Info("listening", "server", name, "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("%s server: %w", name, err)
		}
	}()
	return srv
}

func shutdown(log *slog.Logger, servers ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Warn("shutdown", "addr", srv.Addr, "err", err)
		}
	}
}

func buildFeeders(cfg *config.Config, stores map[string]*store.Store, log *slog.Logger) ([]feeder.Feeder, error) {
	out := make([]feeder.Feeder, 0, len(cfg.Feeders))
	for i, f := range cfg.Feeders {
		s, ok := stores[f.Tenant]
		if !ok {
			return nil, fmt.Errorf("feeders[%d]: unknown tenant %q", i, f.Tenant)
		}

		switch f.Type {
		case "imap":
			password, err := f.Password()
			if err != nil {
				return nil, fmt.Errorf("feeders[%d]: %w", i, err)
			}
			if password == "" {
				return nil, fmt.Errorf("feeders[%d]: credential is empty", i)
			}
			out = append(out, feeder.NewIMAP(feeder.IMAPConfig{
				Name:     f.Name,
				Tenant:   f.Tenant,
				Host:     f.Host,
				Port:     f.Port,
				Username: f.Username,
				Password: password,
				Mailbox:  f.Mailbox,
				Interval: f.Interval,
				Insecure: f.Insecure,
			}, s, log))
		case "maildir":
			out = append(out, feeder.NewMaildir(feeder.MaildirConfig{
				Name:     f.Name,
				Tenant:   f.Tenant,
				Path:     f.Path,
				Interval: f.Interval,
			}, s, log))
		default:
			return nil, fmt.Errorf("feeders[%d]: unknown type %q", i, f.Type)
		}
	}
	return out, nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		if addr, err := netip.ParseAddr(raw); err == nil {
			addr = addr.Unmap()
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("classification.trusted_sources: %q is neither an address nor a prefix", raw)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}
