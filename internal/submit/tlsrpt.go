// Package submit carries the write endpoints a reporter may reach over HTTPS,
// as opposed to the read API on the private listener.
//
// Quarantine is deliberately not used here. Quarantine exists because a mail
// sender is gone by the time parsing fails; an HTTP client is still on the
// wire and is told 400 directly. Storing every garbage POST would hand
// strangers a disk-filling primitive.
package submit

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/elsbrock/mailreportd/internal/metrics"
	"github.com/elsbrock/mailreportd/internal/report"
	"github.com/elsbrock/mailreportd/internal/store"
)

// FeederName is how HTTPS submissions appear in logs, metrics and raw rows.
const FeederName = "tlsrpt-https"

// TLSRPT accepts RFC 8460 §5.3 report submissions.
type TLSRPT struct {
	stores map[string]*store.Store
	// domains maps a policy domain to the tenant that owns it. Attribution is
	// always against domains the operator declared; nothing inside a report is
	// trusted to name a tenant.
	domains map[string]string
	log     *slog.Logger
}

// NewTLSRPT returns a submission handler over the given tenant stores.
func NewTLSRPT(stores map[string]*store.Store, domains map[string]string, log *slog.Logger) *TLSRPT {
	if log == nil {
		log = slog.Default()
	}
	normalized := make(map[string]string, len(domains))
	for d, tenant := range domains {
		normalized[strings.ToLower(strings.TrimSuffix(d, "."))] = tenant
	}
	return &TLSRPT{stores: stores, domains: normalized, log: log}
}

// Register mounts the endpoint on a mux.
func (h *TLSRPT) Register(mux *http.ServeMux) {
	mux.Handle("POST /tlsrpt", h)
}

func (h *TLSRPT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, report.MaxMessageSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	rep, err := report.ParseTLSRPTSubmission(body)
	if err != nil {
		http.Error(w, "unparseable report", http.StatusBadRequest)
		return
	}

	tenant := ""
	for _, d := range rep.Domains() {
		if id, ok := h.domains[d]; ok {
			tenant = id
			break
		}
	}
	if tenant == "" {
		http.Error(w, "report names no domain served here", http.StatusForbidden)
		return
	}

	res, err := h.stores[tenant].IngestReport(r.Context(), store.RawMessage{
		Feeder:    FeederName,
		SourceRef: r.RemoteAddr,
		Received:  time.Now(),
		Body:      body,
	}, rep)
	if err != nil {
		h.log.Error("tlsrpt submission failed", "tenant", tenant, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result := res.State
	if res.Duplicate {
		result = "duplicate"
	}
	metrics.IngestMessages.WithLabelValues(tenant, FeederName, result).Inc()
	if res.Stored > 0 {
		metrics.IngestReports.WithLabelValues(tenant, FeederName).Add(float64(res.Stored))
	}

	h.log.Info("tlsrpt submission",
		"tenant", tenant, "reporter", rep.Reporter, "domain", rep.Domain,
		"stored", res.Stored, "duplicate", res.Duplicate, "peer", r.RemoteAddr)

	// Idempotent by design, so a resend answers exactly like the original.
	w.WriteHeader(http.StatusCreated)
}
