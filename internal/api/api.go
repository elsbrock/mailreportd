// Package api serves the per-source detail that Prometheus deliberately does
// not carry.
//
// These endpoints are mounted on the private listener alongside /metrics rather
// than the public one. They expose source addresses and reporter identities,
// which describe a domain's whole sending topology; that is operator data, not
// something to publish and then bolt authentication onto later.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/elsbrock/mailreportd/internal/store"
)

// DefaultWindow is the lookback applied when a request does not specify one.
const DefaultWindow = 30 * 24 * time.Hour

// API serves read endpoints over a set of tenant stores.
type API struct {
	stores map[string]*store.Store
	// defaultTenant is used when a single tenant is configured, so the common
	// self-hosted case never has to name it.
	defaultTenant string
	log           *slog.Logger
}

// New returns an API over the given tenant stores.
func New(stores map[string]*store.Store, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	a := &API{stores: stores, log: log}
	if len(stores) == 1 {
		for id := range stores {
			a.defaultTenant = id
		}
	}
	return a
}

// Register mounts the endpoints on a mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/domains", a.handle(a.domains))
	mux.HandleFunc("GET /api/v1/sources", a.handle(a.sources))
	mux.HandleFunc("GET /api/v1/signers", a.handle(a.signers))
	mux.HandleFunc("GET /api/v1/quarantine", a.handle(a.quarantine))
}

// badRequest marks an error as the caller's fault. Without an explicit type the
// handler cannot tell a malformed query parameter from a failing database, and
// would answer 500 to both.
type badRequest struct{ err error }

func (b badRequest) Error() string { return b.err.Error() }
func (b badRequest) Unwrap() error { return b.err }

func invalid(format string, args ...any) error {
	return badRequest{fmt.Errorf(format, args...)}
}

type handlerFunc func(*http.Request, *store.Store) (any, error)

func (a *API) handle(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := a.tenant(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		payload, err := fn(r, s)
		if err != nil {
			var bad badRequest
			if errors.As(err, &bad) {
				writeError(w, http.StatusBadRequest, bad)
				return
			}
			a.log.Error("api request failed", "path", r.URL.Path, "err", err)
			// The underlying error can name tables and columns; the caller gets
			// a stable message and the detail goes to the log.
			writeError(w, http.StatusInternalServerError, fmt.Errorf("internal error"))
			return
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

func (a *API) tenant(r *http.Request) (*store.Store, error) {
	id := r.URL.Query().Get("tenant")
	if id == "" {
		id = a.defaultTenant
	}
	if id == "" {
		return nil, fmt.Errorf("tenant is required when more than one is configured")
	}
	s, ok := a.stores[id]
	if !ok {
		return nil, fmt.Errorf("unknown tenant")
	}
	return s, nil
}

func (a *API) domains(r *http.Request, s *store.Store) (any, error) {
	since, err := window(r)
	if err != nil {
		return nil, err
	}
	domains, err := s.DomainSummaries(r.Context(), since)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"window_start": since.UTC().Format(time.RFC3339),
		"tenant":       s.Tenant(),
		"domains":      nonNil(domains),
	}, nil
}

func (a *API) sources(r *http.Request, s *store.Store) (any, error) {
	since, err := window(r)
	if err != nil {
		return nil, err
	}
	limit, err := intParam(r, "limit", 100, 1000)
	if err != nil {
		return nil, err
	}

	sources, err := s.Sources(r.Context(), since, r.URL.Query().Get("domain"), limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"window_start": since.UTC().Format(time.RFC3339),
		"tenant":       s.Tenant(),
		"sources":      nonNil(sources),
	}, nil
}

// signers answers who is signing mail for a domain, which is not the same
// question as whether that mail passes. A signature can verify and still
// contribute nothing, because DMARC scores alignment rather than validity.
func (a *API) signers(r *http.Request, s *store.Store) (any, error) {
	since, err := window(r)
	if err != nil {
		return nil, err
	}
	limit, err := intParam(r, "limit", 100, 1000)
	if err != nil {
		return nil, err
	}

	signers, omitted, err := s.Signers(r.Context(), since, r.URL.Query().Get("domain"), limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"window_start": since.UTC().Format(time.RFC3339),
		"tenant":       s.Tenant(),
		"signers":      nonNil(signers),
		// Always present, so a truncated answer cannot be mistaken for a
		// complete one by a client that forgot to look.
		"omitted": omitted,
	}, nil
}

func (a *API) quarantine(r *http.Request, s *store.Store) (any, error) {
	limit, err := intParam(r, "limit", 50, 500)
	if err != nil {
		return nil, err
	}
	entries, err := s.Quarantine(r.Context(), limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"tenant":  s.Tenant(),
		"entries": nonNil(entries),
	}, nil
}

// window resolves the lookback for a request.
func window(r *http.Request) (time.Time, error) {
	raw := r.URL.Query().Get("window")
	if raw == "" {
		return time.Now().Add(-DefaultWindow), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return time.Time{}, invalid("window: %v", err)
	}
	if d <= 0 {
		return time.Time{}, invalid("window must be positive")
	}
	return time.Now().Add(-d), nil
}

func intParam(r *http.Request, name string, fallback, max int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, invalid("%s: %v", name, err)
	}
	if n < 1 {
		return 0, invalid("%s must be positive", name)
	}
	if n > max {
		n = max
	}
	return n, nil
}

// nonNil turns a nil slice into an empty one so the JSON carries [] rather than
// null. Clients should not have to special-case "no results".
func nonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
