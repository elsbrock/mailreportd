// Command mailreportd ingests DMARC aggregate, DMARC failure, and SMTP TLS
// reports, and exposes bounded aggregates for scraping.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/elsbrock/mailreportd/internal/config"
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

	log.Info("starting",
		"version", version,
		"tenants", len(cfg.Tenants),
		"feeders", len(cfg.Feeders),
		"storage", cfg.Storage.Path,
	)

	errc := make(chan error, 2)
	public := serve(ctx, errc, "public", cfg.HTTP.Listen, publicMux())
	metrics := serve(ctx, errc, "metrics", cfg.HTTP.MetricsListen, metricsMux())

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		stop()
		shutdown(public, metrics)
		return err
	}

	shutdown(public, metrics)
	return nil
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
// liveness probe; the TLS-RPT HTTPS submission endpoint lands here later.
func publicMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// metricsMux is expected to stay on a private interface.
func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	return mux
}

func serve(ctx context.Context, errc chan<- error, name, addr string, mux *http.ServeMux) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
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
