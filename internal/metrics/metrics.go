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
	"cmp"
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/elsbrock/mailreportd/internal/classify"
	"github.com/elsbrock/mailreportd/internal/policy"
	"github.com/elsbrock/mailreportd/internal/store"
)

const namespace = "mailreport"

var (
	descMessages = prometheus.NewDesc(
		namespace+"_dmarc_messages",
		"Messages reported in the aggregation window, by evaluation outcome, source class and reporting organization.",
		[]string{"tenant", "domain", "disposition", "dkim", "spf", "source_class", "reporter"}, nil)

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

	// Published-policy series. These describe what the domain publishes, which
	// is a different observation from what reporters saw when they evaluated
	// our mail -- see descPolicy above, which carries the latter. The
	// divergence between the two is itself a signal, so the names must not be
	// conflated.
	//
	// A check that could not complete emits no verdict at all. The series goes
	// stale and the error counter moves instead, because a DNS timeout is not
	// a missing record and the two must not share a value.
	descDKIMState = prometheus.NewDesc(
		namespace+"_dkim_record_state",
		"Published DKIM selector state as a label set with value 1: missing, revoked, malformed, weak or ok.",
		[]string{"tenant", "domain", "selector", "state"}, nil)

	descDKIMKeyBits = prometheus.NewDesc(
		namespace+"_dkim_key_bits",
		"RSA modulus size of the published DKIM key. Receivers reject keys below 1024 bits.",
		[]string{"tenant", "domain", "selector"}, nil)

	descDKIMTesting = prometheus.NewDesc(
		namespace+"_dkim_record_testing",
		"1 when the selector publishes t=y, which asks receivers to treat a failure as unsigned.",
		[]string{"tenant", "domain", "selector"}, nil)

	descDMARCRecordValid = prometheus.NewDesc(
		namespace+"_dmarc_record_valid",
		"1 when the domain publishes a parseable DMARC record.",
		[]string{"tenant", "domain"}, nil)

	descDMARCRecordPolicy = prometheus.NewDesc(
		namespace+"_dmarc_record_policy",
		"Currently published DMARC policy, as a label set with value 1. sp is resolved, so it reflects the policy that actually applies to subdomains.",
		[]string{"tenant", "domain", "p", "sp"}, nil)

	// Below 100 enforces on a sample while reading as full enforcement, which
	// is the most common way a domain believes it is at p=reject when most of
	// its mail is not.
	descDMARCRecordPct = prometheus.NewDesc(
		namespace+"_dmarc_record_pct",
		"Published DMARC pct=, defaulting to 100.",
		[]string{"tenant", "domain"}, nil)

	// Without the RFC 7489 §7.1 record most large receivers send nothing at
	// all, which presents as an empty mailbox rather than as an error.
	descDMARCRUAAuthorized = prometheus.NewDesc(
		namespace+"_dmarc_rua_authorized",
		"1 when an external rua destination publishes the RFC 7489 §7.1 authorization record.",
		[]string{"tenant", "domain", "rua_domain"}, nil)

	descMTASTSValid = prometheus.NewDesc(
		namespace+"_mtasts_record_valid",
		"1 when the domain publishes a parseable MTA-STS policy reachable over HTTPS.",
		[]string{"tenant", "domain"}, nil)

	descMTASTSPolicy = prometheus.NewDesc(
		namespace+"_mtasts_policy",
		"Published MTA-STS mode as a label set with value 1. testing generates reports and enforces nothing.",
		[]string{"tenant", "domain", "mode"}, nil)

	descMTASTSMXCovered = prometheus.NewDesc(
		namespace+"_mtasts_mx_covered",
		"1 when every live MX host matches an mx: pattern in the policy. Drift makes enforcing senders refuse delivery.",
		[]string{"tenant", "domain"}, nil)

	descMTASTSMaxAge = prometheus.NewDesc(
		namespace+"_mtasts_max_age_seconds",
		"Published MTA-STS max_age, which is how long senders cache the policy.",
		[]string{"tenant", "domain"}, nil)

	descMTASTSStaleID = prometheus.NewDesc(
		namespace+"_mtasts_stale_id",
		"1 when the policy body changed while its id did not, so senders keep the old policy until max_age expires.",
		[]string{"tenant", "domain"}, nil)

	descPolicyChecked = prometheus.NewDesc(
		namespace+"_policy_check_timestamp_seconds",
		"Unix timestamp of the last completed policy check for the domain.",
		[]string{"tenant", "domain"}, nil)

	descPolicyErrors = prometheus.NewDesc(
		namespace+"_policy_check_errors_total",
		"Checks that could not be completed, which is not the same as a check that failed.",
		[]string{"tenant", "domain", "check"}, nil)

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
	tenants       []Tenant
	classifier    *classify.Classifier
	checker       *policy.Checker
	window        time.Duration
	reporterLimit int
	log           *slog.Logger

	mu       sync.RWMutex
	snapshot []prometheus.Metric
}

// NewCollector returns a collector over the given tenants. A zero window
// defaults to thirty days, which comfortably spans the reporting lag of every
// large receiver.
// A nil checker disables the published-policy series entirely, which is what
// tests that care only about report aggregation pass. reporterLimit bounds the
// distinct reporter label values per tenant; zero means DefaultReporterLimit.
func NewCollector(tenants []Tenant, classifier *classify.Classifier, checker *policy.Checker, window time.Duration, reporterLimit int, log *slog.Logger) *Collector {
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	if reporterLimit <= 0 {
		reporterLimit = DefaultReporterLimit
	}
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		tenants:       tenants,
		classifier:    classifier,
		checker:       checker,
		window:        window,
		reporterLimit: reporterLimit,
		log:           log,
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
		c.collectPolicy(ctx, tenant, add)
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
	// keeps Prometheus safe: the map key can never contain an address, and the
	// reporter only one of a capped set of values.
	type key struct {
		domain, disposition, dkim, spf, reporter string
		class                                    classify.Class
	}
	totals := map[key]float64{}
	reporter := reporterLabels(sources, c.reporterLimit)

	for _, src := range sources {
		class := classify.ClassUnknown
		if src.SourceIP.IsValid() {
			class = c.classifier.Classify(ctx, src.Domain, src.SourceIP, src.DKIM == "pass", src.SPF == "pass")
		}
		totals[key{src.Domain, src.Disposition, src.DKIM, src.SPF, reporter(src.Reporter), class}] += float64(src.Count)
	}

	for k, count := range totals {
		add(descMessages, prometheus.GaugeValue, count,
			tenant.ID, k.domain, k.disposition, k.dkim, k.spf, string(k.class), k.reporter)
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

// collectPolicy exports what each domain publishes.
//
// The governing rule is that a check which could not complete emits nothing.
// Where the report-derived series distinguish "no data" from "healthy" by
// their absence, these distinguish "we could not tell" from "it is broken" the
// same way: the verdict series goes stale and only the error counter moves.
// Emitting a zero on a DNS timeout would page someone about a policy that is
// very likely fine.
func (c *Collector) collectPolicy(ctx context.Context, tenant Tenant, add addFunc) {
	if c.checker == nil {
		return
	}

	owned := make(map[string]bool, len(tenant.Domains))
	for _, domain := range tenant.Domains {
		owned[domain] = true
		res := c.checker.Check(ctx, domain)

		add(descPolicyChecked, prometheus.GaugeValue, float64(res.CheckedAt.Unix()), tenant.ID, domain)

		for _, d := range res.DKIM {
			if d.Err != nil {
				continue
			}
			add(descDKIMState, prometheus.GaugeValue, 1, tenant.ID, domain, d.Selector, dkimState(d))
			add(descDKIMTesting, prometheus.GaugeValue, boolValue(d.Testing), tenant.ID, domain, d.Selector)
			if d.KeyBits > 0 {
				add(descDKIMKeyBits, prometheus.GaugeValue, float64(d.KeyBits), tenant.ID, domain, d.Selector)
			}
		}

		if res.DMARC.Err == nil {
			add(descDMARCRecordValid, prometheus.GaugeValue, boolValue(res.DMARC.Valid), tenant.ID, domain)
			if res.DMARC.Valid {
				add(descDMARCRecordPolicy, prometheus.GaugeValue, 1,
					tenant.ID, domain, res.DMARC.Policy, res.DMARC.SubdomainPolicy)
				add(descDMARCRecordPct, prometheus.GaugeValue, float64(res.DMARC.Pct), tenant.ID, domain)
			}
			for ruaDomain, authorized := range res.DMARC.RUAAuthorized {
				add(descDMARCRUAAuthorized, prometheus.GaugeValue, boolValue(authorized),
					tenant.ID, domain, ruaDomain)
			}
		}

		if res.MTASTS.Err == nil {
			add(descMTASTSValid, prometheus.GaugeValue, boolValue(res.MTASTS.Valid), tenant.ID, domain)
			if res.MTASTS.Valid {
				add(descMTASTSPolicy, prometheus.GaugeValue, 1, tenant.ID, domain, res.MTASTS.Mode)
				add(descMTASTSMaxAge, prometheus.GaugeValue, float64(res.MTASTS.MaxAge), tenant.ID, domain)
				add(descMTASTSMXCovered, prometheus.GaugeValue, boolValue(res.MTASTS.MXCovered), tenant.ID, domain)
				add(descMTASTSStaleID, prometheus.GaugeValue, boolValue(res.MTASTS.StaleID), tenant.ID, domain)
			}
		}
	}

	// Error counts are cumulative and owned by the checker, because results are
	// cached: counting them here would re-count the same failure on every
	// refresh for as long as the cache holds it.
	for _, e := range c.checker.ErrorCounts() {
		if !owned[e.Domain] {
			continue
		}
		add(descPolicyErrors, prometheus.CounterValue, float64(e.Count), tenant.ID, e.Domain, e.Check)
	}
}

// dkimState collapses one selector into a single bounded label.
//
// The states are ordered by what the operator has to do about them: a missing
// record was never published, a revoked one was published and withdrawn, and
// those have different fixes.
func dkimState(d policy.DKIMResult) string {
	switch {
	case !d.Found:
		return "missing"
	case d.Revoked:
		return "revoked"
	case d.KeyBits == 0:
		return "malformed"
	case !d.Valid:
		return "weak"
	default:
		return "ok"
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
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

// DefaultReporterLimit is how many reporting organizations get their own
// label value per tenant. The handful of large receivers that send reports
// fit with room to spare.
const DefaultReporterLimit = 20

// Reporter label values that are not a reporting organization.
const (
	ReporterOther   = "other"
	ReporterUnknown = "unknown"
)

// maxReporterLabel bounds the length of one label value.
const maxReporterLabel = 64

// reporterLabels returns the label value for each reporter: the busiest limit
// reporters by message volume keep their name, everyone else is "other".
//
// The reporter is whatever org_name a report claims, and anyone can mail the
// rua address. Without the cap a stream of forged reports would mint one
// series per invented name, which is the failure the source_class label
// exists to avoid. With it, a forger can at most displace a real receiver
// into "other".
func reporterLabels(sources []store.DMARCSource, limit int) func(string) string {
	volume := map[string]int64{}
	for _, src := range sources {
		if src.Reporter != "" {
			volume[src.Reporter] += src.Count
		}
	}

	names := make([]string, 0, len(volume))
	for name := range volume {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		if c := cmp.Compare(volume[b], volume[a]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})

	kept := make(map[string]bool, limit)
	for _, name := range names[:min(limit, len(names))] {
		kept[name] = true
	}

	return func(name string) string {
		switch {
		case name == "":
			return ReporterUnknown
		case !kept[name]:
			return ReporterOther
		}
		if r := []rune(name); len(r) > maxReporterLabel {
			return string(r[:maxReporterLabel])
		}
		return name
	}
}
