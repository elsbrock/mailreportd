// Package metrics exports aggregated report data to Prometheus.
//
// The cardinality rule is absolute: source addresses never become labels. A
// month of aggregate reports for a handful of domains contains tens of
// thousands of distinct source addresses, most seen once, most of them
// forwarders and spoofers. Exporting them would destroy the time series
// database it is meant to feed. Sources are classified into a three-value
// bucket here and served in full over the read API instead.
package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/elsbrock/mailreportd/internal/classify"
	"github.com/elsbrock/mailreportd/internal/store"
)

const namespace = "mailreport"

var (
	descMessages = prometheus.NewDesc(
		namespace+"_dmarc_messages",
		"Messages reported in the aggregation window, by evaluation outcome and source class.",
		[]string{"tenant", "domain", "disposition", "dkim", "spf", "source_class"}, nil)

	descTLSSessions = prometheus.NewDesc(
		namespace+"_tlsrpt_sessions",
		"SMTP TLS sessions reported in the aggregation window.",
		[]string{"tenant", "domain", "policy_type", "result"}, nil)

	descTLSFailures = prometheus.NewDesc(
		namespace+"_tlsrpt_failures",
		"SMTP TLS session failures in the aggregation window, by RFC 8460 result type.",
		[]string{"tenant", "domain", "result_type"}, nil)

	// The staleness series. Without it, a zero failure rate because nothing was
	// ingested is indistinguishable from a zero failure rate because nothing
	// failed, which is precisely how a broken mail stack stays invisible.
	descLastReport = prometheus.NewDesc(
		namespace+"_report_last_received_timestamp_seconds",
		"Unix timestamp of the most recently ingested report, by domain and format.",
		[]string{"tenant", "domain", "format"}, nil)

	descRawMessages = prometheus.NewDesc(
		namespace+"_raw_messages",
		"Messages seen by the ingest pipeline, by outcome state.",
		[]string{"tenant", "state"}, nil)

	descPolicy = prometheus.NewDesc(
		namespace+"_dmarc_policy",
		"Published DMARC policy last observed by a reporter, as a label set with value 1.",
		[]string{"tenant", "domain", "p"}, nil)

	descSPFLookups = prometheus.NewDesc(
		namespace+"_spf_lookups",
		"DNS-querying mechanisms consumed by the domain's SPF record.",
		[]string{"tenant", "domain"}, nil)

	// Over ten lookups is a permerror at real receivers, not a style problem.
	descSPFExceeded = prometheus.NewDesc(
		namespace+"_spf_lookup_limit_exceeded",
		"1 when the domain's SPF record needs more than the RFC 7208 limit of ten DNS lookups.",
		[]string{"tenant", "domain"}, nil)

	descSPFResolvable = prometheus.NewDesc(
		namespace+"_spf_resolvable",
		"1 when the domain's SPF record could be resolved.",
		[]string{"tenant", "domain"}, nil)

	descRefresh = prometheus.NewDesc(
		namespace+"_refresh_timestamp_seconds",
		"Unix timestamp of the last successful metric refresh.",
		nil, nil)

	descRefreshDuration = prometheus.NewDesc(
		namespace+"_refresh_duration_seconds",
		"Duration of the last metric refresh.",
		nil, nil)
)

// Ingest counters are updated by feeders as messages arrive, rather than being
// derived from the store, so that a feeder failing loudly is visible even when
// nothing reaches the database.
var (
	IngestMessages = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: namespace + "_ingest_messages_total",
		Help: "Messages processed by a feeder, by outcome.",
	}, []string{"tenant", "feeder", "result"})

	IngestReports = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: namespace + "_ingest_reports_total",
		Help: "Reports stored by a feeder.",
	}, []string{"tenant", "feeder"})

	IngestErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: namespace + "_ingest_errors_total",
		Help: "Feeder run failures, which mean reports are not arriving at all.",
	}, []string{"tenant", "feeder"})

	IngestLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: namespace + "_ingest_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful feeder run.",
	}, []string{"tenant", "feeder"})

	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: namespace + "_build_info",
		Help: "Build information, always 1.",
	}, []string{"version"})
)

// Tenant binds a store to the domains that should be reported for it.
type Tenant struct {
	ID      string
	Store   *store.Store
	Domains []string
}

// Collector serves a cached snapshot.
//
// Metrics are built on a schedule rather than at scrape time because building
// them touches SQLite and, for the SPF classification, DNS. A scrape must never
// be able to block on either.
type Collector struct {
	tenants    []Tenant
	classifier *classify.Classifier
	window     time.Duration
	log        *slog.Logger

	mu       sync.RWMutex
	snapshot []prometheus.Metric
}

// NewCollector returns a collector over the given tenants. A zero window
// defaults to thirty days, which comfortably spans the reporting lag of every
// large receiver.
func NewCollector(tenants []Tenant, classifier *classify.Classifier, window time.Duration, log *slog.Logger) *Collector {
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		tenants:    tenants,
		classifier: classifier,
		window:     window,
		log:        log,
	}
}

// Describe implements prometheus.Collector. It is intentionally unchecked: the
// snapshot is built dynamically and sending descriptors here would require
// duplicating that logic.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()

	for _, m := range snapshot {
		ch <- m
	}
}

// Refresh rebuilds the snapshot.
//
// A failure for one tenant must not blank the metrics for the others, so errors
// are logged and that tenant is skipped rather than aborting the refresh.
func (c *Collector) Refresh(ctx context.Context) {
	started := time.Now()
	since := started.Add(-c.window)

	var metrics []prometheus.Metric
	add := func(desc *prometheus.Desc, kind prometheus.ValueType, value float64, labels ...string) {
		m, err := prometheus.NewConstMetric(desc, kind, value, labels...)
		if err != nil {
			c.log.Warn("build metric", "err", err)
			return
		}
		metrics = append(metrics, m)
	}

	for _, tenant := range c.tenants {
		c.collectDMARC(ctx, tenant, since, add)
		c.collectTLS(ctx, tenant, since, add)
		c.collectIngestState(ctx, tenant, add)
		c.collectSPF(ctx, tenant, add)
	}

	add(descRefresh, prometheus.GaugeValue, float64(started.Unix()))
	add(descRefreshDuration, prometheus.GaugeValue, time.Since(started).Seconds())

	c.mu.Lock()
	c.snapshot = metrics
	c.mu.Unlock()
}

type addFunc func(*prometheus.Desc, prometheus.ValueType, float64, ...string)

func (c *Collector) collectDMARC(ctx context.Context, tenant Tenant, since time.Time, add addFunc) {
	sources, err := tenant.Store.DMARCSources(ctx, since)
	if err != nil {
		c.log.Error("collect dmarc sources", "tenant", tenant.ID, "err", err)
		return
	}

	// Fold per-source rows into the bounded label set. This is the step that
	// keeps Prometheus safe: the map key can never contain an address.
	type key struct {
		domain, disposition, dkim, spf string
		class                          classify.Class
	}
	totals := map[key]float64{}

	for _, src := range sources {
		class := classify.ClassUnknown
		if src.SourceIP.IsValid() {
			class = c.classifier.Classify(ctx, src.Domain, src.SourceIP, src.DKIM == "pass", src.SPF == "pass")
		}
		totals[key{src.Domain, src.Disposition, src.DKIM, src.SPF, class}] += float64(src.Count)
	}

	for k, count := range totals {
		add(descMessages, prometheus.GaugeValue, count,
			tenant.ID, k.domain, k.disposition, k.dkim, k.spf, string(k.class))
	}

	last, err := tenant.Store.LastReports(ctx)
	if err != nil {
		c.log.Error("collect last reports", "tenant", tenant.ID, "err", err)
		return
	}
	for _, l := range last {
		add(descLastReport, prometheus.GaugeValue, float64(l.Received.Unix()), tenant.ID, l.Domain, l.Format)
	}

	summaries, err := tenant.Store.DomainSummaries(ctx, since)
	if err != nil {
		c.log.Error("collect domain summaries", "tenant", tenant.ID, "err", err)
		return
	}
	for _, s := range summaries {
		if s.Policy != "" {
			add(descPolicy, prometheus.GaugeValue, 1, tenant.ID, s.Domain, s.Policy)
		}
	}
}

func (c *Collector) collectTLS(ctx context.Context, tenant Tenant, since time.Time, add addFunc) {
	summaries, err := tenant.Store.TLSSummaries(ctx, since)
	if err != nil {
		c.log.Error("collect tls summaries", "tenant", tenant.ID, "err", err)
		return
	}
	for _, s := range summaries {
		add(descTLSSessions, prometheus.GaugeValue, float64(s.Successful), tenant.ID, s.Domain, s.PolicyType, "successful")
		add(descTLSSessions, prometheus.GaugeValue, float64(s.Failed), tenant.ID, s.Domain, s.PolicyType, "failed")
	}

	failures, err := tenant.Store.TLSFailures(ctx, since)
	if err != nil {
		c.log.Error("collect tls failures", "tenant", tenant.ID, "err", err)
		return
	}
	for _, f := range failures {
		add(descTLSFailures, prometheus.GaugeValue, float64(f.Count), tenant.ID, f.Domain, f.ResultType)
	}
}

func (c *Collector) collectIngestState(ctx context.Context, tenant Tenant, add addFunc) {
	counts, err := tenant.Store.StateCounts(ctx)
	if err != nil {
		c.log.Error("collect state counts", "tenant", tenant.ID, "err", err)
		return
	}
	// Emit every state explicitly, including the zeroes. An absent series
	// cannot be alerted on, and quarantine going from absent to present is the
	// exact transition worth noticing.
	for _, state := range []string{store.StateParsed, store.StateQuarantined, store.StateIgnored} {
		add(descRawMessages, prometheus.GaugeValue, float64(counts[state]), tenant.ID, state)
	}
}

func (c *Collector) collectSPF(ctx context.Context, tenant Tenant, add addFunc) {
	for _, domain := range tenant.Domains {
		exp := c.classifier.Expand(ctx, domain)

		resolvable := 1.0
		if exp.Err != nil {
			resolvable = 0
		}
		add(descSPFResolvable, prometheus.GaugeValue, resolvable, tenant.ID, domain)

		if exp.Err != nil {
			continue
		}
		add(descSPFLookups, prometheus.GaugeValue, float64(exp.Lookups), tenant.ID, domain)

		exceeded := 0.0
		if exp.Exceeded {
			exceeded = 1
		}
		add(descSPFExceeded, prometheus.GaugeValue, exceeded, tenant.ID, domain)
	}
}

// Register adds the collector and the ingest counters to a registry.
func Register(reg prometheus.Registerer, c *Collector) error {
	for _, collector := range []prometheus.Collector{
		c, IngestMessages, IngestReports, IngestErrors, IngestLastSuccess, BuildInfo,
	} {
		if err := reg.Register(collector); err != nil {
			return err
		}
	}
	return nil
}
