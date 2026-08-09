// Command mailreportd ingests DMARC aggregate and SMTP TLS reports and exposes
// bounded aggregates for scraping.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/elsbrock/mailreportd/internal/api"
	"github.com/elsbrock/mailreportd/internal/classify"
	"github.com/elsbrock/mailreportd/internal/config"
	"github.com/elsbrock/mailreportd/internal/feeder"
	"github.com/elsbrock/mailreportd/internal/metrics"
	"github.com/elsbrock/mailreportd/internal/store"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mailreportd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/mailreportd/config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check", false, "validate the config file and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *checkConfig {
		fmt.Println("config ok")
		return nil
	}

	log := newLogger(cfg.Log)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(cfg.Storage.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	stores := make(map[string]*store.Store, len(cfg.Tenants))
	tenants := make([]metrics.Tenant, 0, len(cfg.Tenants))
	for _, t := range cfg.Tenants {
		s := db.Tenant(t.ID)
		stores[t.ID] = s
		tenants = append(tenants, metrics.Tenant{ID: t.ID, Store: s, Domains: t.Domains})
	}

	overrides, err := parsePrefixes(cfg.Classification.TrustedSources)
	if err != nil {
		return err
	}
	classifier := classify.New(nil, cfg.Classification.CacheTTL, overrides)

	collector := metrics.NewCollector(tenants, classifier, cfg.Metrics.Window, log)
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err := metrics.Register(registry, collector); err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}
	metrics.BuildInfo.WithLabelValues(version).Set(1)

	feeders, err := buildFeeders(cfg, stores, log)
	if err != nil {
		return err
	}

	log.Info("starting",
		"version", version,
		"tenants", len(cfg.Tenants),
		"feeders", len(feeders),
		"storage", cfg.Storage.Path,
	)
	if len(feeders) == 0 {
		// Worth saying out loud: the daemon will run happily and ingest
		// nothing, which looks identical to a healthy quiet mailbox.
		log.Warn("no feeders configured; no reports will be ingested")
	}

	// Populate metrics before the first scrape so a freshly started daemon does
	// not report an empty stack.
	collector.Refresh(ctx)

	var wg sync.WaitGroup
	for _, f := range feeders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			feeder.Run(ctx, f, log)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		refreshLoop(ctx, collector, cfg.Metrics.RefreshInterval, log)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sweepLoop(ctx, stores, cfg.Storage.Retention, cfg.Storage.SweepInterval, log)
	}()

	errc := make(chan error, 2)
	public := serve(ctx, errc, "public", cfg.HTTP.Listen, publicMux())
	private := serve(ctx, errc, "private", cfg.HTTP.MetricsListen, privateMux(registry, stores, log))

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		runErr = err
		stop()
	}

	shutdown(public, private)
	wg.Wait()
	return runErr
}

func buildFeeders(cfg *config.Config, stores map[string]*store.Store, log *slog.Logger) ([]feeder.Feeder, error) {
	out := make([]feeder.Feeder, 0, len(cfg.Feeders))
	for i, f := range cfg.Feeders {
		s, ok := stores[f.Tenant]
		if !ok {
			return nil, fmt.Errorf("feeders[%d]: unknown tenant %q", i, f.Tenant)
		}

		name := f.Name
		if name == "" {
			name = fmt.Sprintf("%s-%d", f.Type, i)
		}

		switch f.Type {
		case "imap":
			password := f.Password()
			if password == "" {
				return nil, fmt.Errorf("feeders[%d]: environment variable %q is empty", i, f.PasswordEnv)
			}
			out = append(out, feeder.NewIMAP(feeder.IMAPConfig{
				Name:     name,
				Tenant:   f.Tenant,
				Host:     f.Host,
				Port:     f.Port,
				Username: f.Username,
				Password: password,
				Mailbox:  f.Mailbox,
				Interval: f.Interval,
				Insecure: f.Insecure,
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
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
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

func refreshLoop(ctx context.Context, c *metrics.Collector, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Refresh(ctx)
		}
	}
}

func sweepLoop(ctx context.Context, stores map[string]*store.Store, r config.Retention, interval time.Duration, log *slog.Logger) {
	retention := store.Retention{Raw: r.Raw, Aggregate: r.Aggregate, Forensic: r.Forensic}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for id, s := range stores {
				res, err := s.Sweep(ctx, retention, time.Now())
				if err != nil {
					log.Error("retention sweep failed", "tenant", id, "err", err)
					continue
				}
				if res.Reports > 0 || res.RawBodies > 0 {
					log.Info("retention sweep",
						"tenant", id, "reports_deleted", res.Reports, "bodies_cleared", res.RawBodies)
				}
			}
		}
	}
}

func newLogger(cfg config.Log) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// publicMux carries anything an outside party may reach. Today that is only the
// liveness probe; TLS-RPT HTTPS submission lands here later.
func publicMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// privateMux carries metrics and the read API, both of which expose operator
// data and belong on an internal interface.
func privateMux(registry *prometheus.Registry, stores map[string]*store.Store, log *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	api.New(stores, log).Register(mux)
	return mux
}

func serve(ctx context.Context, errc chan<- error, name, addr string, mux *http.ServeMux) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		slog.Info("listening", "server", name, "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("%s server: %w", name, err)
		}
	}()
	return srv
}

func shutdown(servers ...*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			slog.Warn("shutdown", "addr", srv.Addr, "err", err)
		}
	}
}
