// Command mailreportd ingests DMARC aggregate and SMTP TLS reports and exposes
// bounded aggregates for scraping.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/elsbrock/mailreportd/internal/config"
	"github.com/elsbrock/mailreportd/internal/daemon"
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

	d, err := daemon.New(cfg, log, daemon.Options{Version: version})
	if err != nil {
		return err
	}
	defer d.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return d.Run(ctx)
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
