package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// This file wires this binary's own operational stats into Prometheus client_golang, following
// the EXACT same shape already established for cmd/netmap-p2p-responder (see that package's
// metrics.go, added in the prior commit this one continues from, per BRIEF5.md): metric names
// network-scoped (netmap_mainnet_... / netmap_testnet_..., since both networks' deployments of
// EVERY binary in this repo get scraped into a single shared Prometheus backend -- Alex's exact
// instruction), a *responderMetrics-equivalent struct (netmapMetrics here) built once in run()
// after the required -network flag is parsed (never a package-level var/init(), for the same
// init-order reason as the responder), registered onto its OWN dedicated *prometheus.Registry
// rather than prometheus.DefaultRegisterer, and served via newMetricsServer's /metrics +
// /healthz on a SEPARATE, internal-only listener bound to -metrics-addr.
//
// CORRECTED GUIDANCE this binary's metrics wiring specifically follows (see BRIEF5.md's Change
// 2): this binary's existing listener (-addr, e.g. 192.168.40.51:8080/:8081) is PROXIED --
// Caddy sits in front of it to serve the public dashboard -- so /metrics must NEVER share that
// port/mux. -metrics-addr is a second, independent net.Listener/http.Server, exactly mirroring
// cmd/netmap-p2p-responder's own -metrics-addr (see that package's main.go doc comments on the
// same "internal-only, never the public interface" warning).
//
// What's instrumented here (see netmapMetrics' field doc comments for each):
//   - netmap_<network>_collector_poll_result_total{probe_source,result} -- per-probe-source
//     (grpc|p2p) poll outcome counts, fed from collector.Collector.OnPollResult (see
//     internal/collector/collector.go's PollResultFunc).
//   - netmap_<network>_collector_poll_queue_backlog{queue} -- current size of each of the
//     collector's five poll queues (confirmed_owned|confirmed_generic|unconfirmed_active|
//     unconfirmed_likely_dead|never_contacted), mirroring PollOwnedConfirmed/
//     PollGenericConfirmed/PollUnconfirmed/PollNeverContacted's own NodeFilter split, with the
//     unconfirmed queue further split into unconfirmed_active vs unconfirmed_likely_dead (see
//     queueBacklog's own doc comment below for why: at real network scale the single old
//     "unconfirmed" number was ~99.4% likely-dead nodes already backed off to a weekly poll
//     cadence, wildly overstating near-term collector workload). The previous single
//     "confirmed" label (pre-owned/generic split) and the previous single "unconfirmed" label
//     (pre-active/likely-dead split) were checked against every known Grafana dashboard/docs/
//     internal/web consumer before being replaced outright here -- nothing in this repo
//     referenced either, so there was no additive-compat requirement to preserve them alongside
//     their respective new labels. BREAKING CHANGE for any existing Grafana panel keyed on
//     queue="confirmed" or queue="unconfirmed" -- those label values no longer exist; see
//     queueBacklog's doc comment.
//   - netmap_<network>_collector_known_nodes{discovery_source} -- whole-population known-node
//     counts by discovery_source (p2p|registry|both), reusing api.FetchNodeCounts -- the exact
//     same query/computation GET /api/v1/stats and the HTML dashboard's summary cards already
//     use, per BRIEF5.md's "reuse that logic/those queries rather than writing new ones".
//   - netmap_<network>_collector_db_up -- 1/0 store.Ping reachability gauge.
//   - netmap_<network>_api_http_requests_total{method,route,status} /
//     netmap_<network>_api_http_request_duration_seconds{method,route} -- a small manual
//     middleware (instrumentHTTP below) wrapping this binary's existing top-level mux, rather
//     than pulling in a heavier routing framework just for this -- see httpRouteLabel's doc
//     comment for why "route" is a small, bounded label set, not the raw URL path.

// validNetmapNetworks is this binary's own copy of cmd/netmap-p2p-responder/metrics.go's
// validMainnetOrTestnet -- kept as a separate copy (not a shared internal package) since these
// are two independent main packages and this is the only piece of logic they'd otherwise need
// to share; duplicating ~10 lines is simpler than introducing a new internal/ package for it.
var validNetmapNetworks = map[string]bool{"mainnet": true, "testnet": true}

// validateNetmapNetwork validates the -network flag's value for this binary: it must be exactly
// "mainnet" or "testnet", with no default -- mirrors cmd/netmap-p2p-responder's
// validateNetwork/BRIEF5.md's fail-fast requirement exactly.
func validateNetmapNetwork(network string) error {
	if network == "" {
		return fmt.Errorf("-network is required (must be %q or %q)", "mainnet", "testnet")
	}
	if !validNetmapNetworks[network] {
		return fmt.Errorf("-network %q is invalid: must be %q or %q", network, "mainnet", "testnet")
	}
	return nil
}

// metricsQueryTimeout bounds every individual storage.Store query netmapMetrics.refresh makes
// (CountNodes x3, plus api.FetchNodeCounts' own ListNodes/ListNodeAddressesForNodes round
// trip) -- refresh runs on its own periodic background ticker (see run()), completely
// independent of any live HTTP request, so a slow/wedged Postgres pool here must never hang
// that goroutine indefinitely.
const metricsQueryTimeout = 10 * time.Second

// metricsRefreshInterval is how often run()'s background ticker calls netmapMetrics.refresh to
// update the DB-derived gauges (queueBacklog, knownNodes, dbUp). These are deliberately NOT
// computed live inside the /metrics handler itself (unlike cmd/netmap-p2p-responder's
// /healthz, which does call store.Ping live on every request) -- a Prometheus scrape hitting
// this endpoint must never block on a handful of ListNodes/CountNodes queries against
// potentially tens of thousands of tracked nodes; polling on a fixed cadence in the background
// instead means a scrape only ever reads already-computed gauge values.
const metricsRefreshInterval = 30 * time.Second

// netmapMetrics holds this process' own dedicated Prometheus metrics -- see this file's own
// doc comment for the full list and rationale, and cmd/netmap-p2p-responder/metrics.go's
// responderMetrics doc comment for why a dedicated *prometheus.Registry (network-scoped names
// are a runtime value, and this package's own tests build more than one instance per process).
type netmapMetrics struct {
	network  string
	registry *prometheus.Registry

	// pollResult counts every individual probe attempt made by this process' own Collector
	// (via Collector.OnPollResult, see internal/collector/collector.go's PollResultFunc),
	// labeled by probe_source (grpc|p2p) and result (success|failure) -- success means the
	// probe transport itself got a response (client.GetInfo returned no error), independent
	// of any subsequent storage write outcome.
	pollResult *prometheus.CounterVec

	// queueBacklog is the current size of each of the collector's five disjoint poll queues
	// (see internal/collector/collector.go's PollOwnedConfirmed/PollGenericConfirmed/
	// PollUnconfirmed/PollNeverContacted doc comments for the exact NodeFilter each
	// corresponds to), labeled by queue (confirmed_owned|confirmed_generic|unconfirmed_active|
	// unconfirmed_likely_dead|never_contacted). Updated periodically by refresh, not live
	// per-scrape -- see metricsRefreshInterval's doc comment.
	//
	// BREAKING CHANGE (semver/dashboard-relevant, flag to Alex): this used to be two single
	// values -- queue="confirmed" (now split into confirmed_owned/confirmed_generic, mirroring
	// PollOwnedConfirmed/PollGenericConfirmed's own NodeFilter split) and queue="unconfirmed"
	// (every node with public_key IS NULL that has at least one health-check row
	// (storage.NodeFilter{Confirmed: &unconfirmed, HasHealthChecks: &hasHistory}), matching
	// internal/collector's PollUnconfirmed filter exactly). A live production check found that
	// the unconfirmed number wildly overstates near-term collector workload: of 50,420 nodes in
	// that bucket, 50,115 (~99.4%) were already "likely dead" per collectorLikelyDead's
	// heuristic (3+ of their most recent 3 probes failed, zero successes) -- i.e. already
	// backed off to the weekly PollIntervalLikelyDead cadence, not nodes under active
	// near-term dial pressure. Only ~305 were genuinely "active unconfirmed" (still on the
	// normal PollIntervalUnconfirmed/checkpoint cadence). This splits that one label into two
	// so the metric distinguishes cadence tiers instead of conflating them:
	//   - queue="unconfirmed_active": unconfirmed nodes NOT currently classified likely-dead
	//     (storage.IsLikelyDead on their most recent 3 health checks returns false) -- still
	//     on the normal/checkpoint cadence.
	//   - queue="unconfirmed_likely_dead": unconfirmed nodes that ARE currently classified
	//     likely-dead by that exact same storage.IsLikelyDead heuristic internal/collector's
	//     own pollInterval uses to back a node off to PollIntervalLikelyDead -- reused here
	//     rather than reimplemented, via GetNodeHistoryForNodes' batch classification (see
	//     refresh below).
	// The old queue="confirmed" and queue="unconfirmed" label values no longer exist at all --
	// any existing Grafana panel keyed on either will show no data and needs updating to
	// sum/select the respective new label values instead. never_contacted is unchanged.
	queueBacklog *prometheus.GaugeVec

	// knownNodes is the whole-population known-node count by discovery_source
	// (p2p|registry|both), reusing api.FetchNodeCounts/api.NodeCounts -- the exact same
	// numbers already shown on the HTML dashboard and GET /api/v1/stats. Updated
	// periodically by refresh, not live per-scrape.
	knownNodes *prometheus.GaugeVec

	// dbUp is a 1/0 gauge reflecting the most recent store.Ping(ctx) result, updated
	// periodically by refresh -- the /metrics-endpoint equivalent of cmd/netmap-p2p-
	// responder's own /healthz check, but as a gauge rather than a live per-request check
	// (see metricsRefreshInterval's doc comment for why this binary's /metrics handler
	// itself never touches storage).
	dbUp prometheus.Gauge

	// httpRequestsTotal/httpRequestDuration instrument this binary's existing top-level mux
	// (the dashboard + /api/ routes, see main.go) via instrumentHTTP below, labeled by
	// method, a small bounded route label (see httpRouteLabel), and (requestsTotal only)
	// status code.
	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec
}

// newNetmapMetrics validates network (see validateNetmapNetwork) and builds + registers every
// metric this binary exposes, each named netmap_<network>_collector_... /
// netmap_<network>_api_..., on its own dedicated registry -- mirrors
// cmd/netmap-p2p-responder/metrics.go's newResponderMetrics exactly (see that function's doc
// comment for the full "why network-scoped, why its own registry" rationale, which applies
// identically here).
func newNetmapMetrics(network string) (*netmapMetrics, error) {
	if err := validateNetmapNetwork(network); err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("netmap_%s_", network)
	m := &netmapMetrics{network: network, registry: prometheus.NewRegistry()}

	m.pollResult = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "collector_poll_result_total",
		Help: "Total number of individual probe attempts made by this process' collector, labeled by probe_source (grpc|p2p) and result (success|failure).",
	}, []string{"probe_source", "result"})

	m.queueBacklog = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: prefix + "collector_poll_queue_backlog",
		Help: "Current size of each of the collector's five poll queues, labeled by queue (confirmed_owned|confirmed_generic|unconfirmed_active|unconfirmed_likely_dead|never_contacted). Updated periodically, not live per-scrape.",
	}, []string{"queue"})

	m.knownNodes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: prefix + "collector_known_nodes",
		Help: "Whole-population known-node count, labeled by discovery_source (p2p|registry|both). Mirrors GET /api/v1/stats' own numbers. Updated periodically, not live per-scrape.",
	}, []string{"discovery_source"})

	m.dbUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: prefix + "collector_db_up",
		Help: "1 if the most recent periodic store.Ping succeeded, 0 otherwise.",
	})

	m.httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: prefix + "api_http_requests_total",
		Help: "Total number of HTTP requests served by this binary's dashboard+API mux, labeled by method, route, and status.",
	}, []string{"method", "route", "status"})

	m.httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    prefix + "api_http_request_duration_seconds",
		Help:    "HTTP request latency, in seconds, labeled by method and route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	m.registry.MustRegister(
		m.pollResult,
		m.queueBacklog,
		m.knownNodes,
		m.dbUp,
		m.httpRequestsTotal,
		m.httpRequestDuration,
		// See newResponderMetrics' identical registration in cmd/netmap-p2p-responder/
		// metrics.go for why these are registered explicitly here rather than relying on
		// prometheus.DefaultRegisterer's own implicit package-init registration.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	return m, nil
}

// onPollResult implements collector.PollResultFunc -- wired as Collector.OnPollResult in
// run(), so every probe attempt this process' own scheduled poll loops make increments
// pollResult.
func (m *netmapMetrics) onPollResult(probeSource storage.ProbeSource, success bool) {
	m.pollResult.WithLabelValues(string(probeSource), metricsResultLabel(success)).Inc()
}

// metricsResultLabel returns the Prometheus "result" label value for success, mirroring
// cmd/netmap-p2p-responder/metrics.go's resultLabel exactly (same fleet-wide success|failure
// label convention).
func metricsResultLabel(success bool) string {
	if success {
		return "success"
	}
	return "failure"
}

// refresh updates every DB-derived gauge (queueBacklog, knownNodes, dbUp) via fresh
// storage.Store queries. Called periodically from run()'s own background ticker (see
// metricsRefreshInterval) -- never from the /metrics handler itself, so a Prometheus scrape
// only ever reads already-computed values, regardless of how slow/large these queries are
// against a real production node population.
//
// A store.Ping failure sets dbUp to 0 and returns early WITHOUT attempting the remaining
// queries (they would almost certainly fail too, against the same wedged/unreachable pool) --
// the other gauges simply keep their last-known-good values until the next successful refresh,
// rather than being zeroed out and misreported as "genuinely empty".
func (m *netmapMetrics) refresh(ctx context.Context, store storage.Store) {
	pingCtx, cancel := context.WithTimeout(ctx, metricsQueryTimeout)
	defer cancel()
	if err := store.Ping(pingCtx); err != nil {
		m.dbUp.Set(0)
		log.Printf("netmap: metrics refresh: store.Ping: %v", err)
		return
	}
	m.dbUp.Set(1)

	queryCtx, cancel2 := context.WithTimeout(ctx, metricsQueryTimeout)
	defer cancel2()

	// The CountNodes filters below are deliberately identical to
	// collector.PollOwnedConfirmed/PollGenericConfirmed's own NodeFilter construction (see
	// internal/collector/collector.go) -- these ARE the collector's owned/generic confirmed
	// poll queues, just counted rather than listed-and-dialed. unconfirmed's backlog (split
	// into unconfirmed_active/unconfirmed_likely_dead below) and never_contacted's CountNodes
	// are likewise deliberately identical to collector.PollUnconfirmed/PollNeverContacted's own
	// NodeFilter construction.
	confirmed := true
	owned := true
	if n, err := store.CountNodes(queryCtx, storage.NodeFilter{Confirmed: &confirmed, Owned: &owned}); err != nil {
		log.Printf("netmap: metrics refresh: count owned-confirmed nodes: %v", err)
	} else {
		m.queueBacklog.WithLabelValues("confirmed_owned").Set(float64(n))
	}

	notOwned := false
	if n, err := store.CountNodes(queryCtx, storage.NodeFilter{Confirmed: &confirmed, Owned: &notOwned}); err != nil {
		log.Printf("netmap: metrics refresh: count generic-confirmed nodes: %v", err)
	} else {
		m.queueBacklog.WithLabelValues("confirmed_generic").Set(float64(n))
	}

	// The two blocks below (unconfirmed's backlog split + never_contacted's CountNodes) are
	// deliberately identical to collector.PollUnconfirmed/PollNeverContacted's own NodeFilter
	// construction (see internal/collector/collector.go) -- these ARE the collector's poll
	// queues, just counted/classified rather than listed-and-dialed.
	unconfirmed := false
	if err := m.refreshUnconfirmedQueueBacklog(queryCtx, store); err != nil {
		log.Printf("netmap: metrics refresh: unconfirmed queue backlog: %v", err)
	}

	noHistory := false
	if n, err := store.CountNodes(queryCtx, storage.NodeFilter{Confirmed: &unconfirmed, HasHealthChecks: &noHistory}); err != nil {
		log.Printf("netmap: metrics refresh: count never-contacted nodes: %v", err)
	} else {
		m.queueBacklog.WithLabelValues("never_contacted").Set(float64(n))
	}

	counts, err := api.FetchNodeCounts(queryCtx, store)
	if err != nil {
		log.Printf("netmap: metrics refresh: fetch node counts: %v", err)
		return
	}
	m.knownNodes.WithLabelValues("p2p").Set(float64(counts.P2P))
	m.knownNodes.WithLabelValues("registry").Set(float64(counts.Registry))
	m.knownNodes.WithLabelValues("both").Set(float64(counts.Both))
}

// likelyDeadHistoryLimit is the number of most-recent health-check rows fetched per
// unconfirmed node in refreshUnconfirmedQueueBacklog to classify it via storage.IsLikelyDead --
// exactly 3, matching that heuristic's own "most recent 3, all failed" windowing requirement
// (see internal/collector/collector.go's identical GetNodeHistory(ctx, n.ID, 3) call in
// pollInterval).
const likelyDeadHistoryLimit = 3

// refreshUnconfirmedQueueBacklog is queueBacklog's unconfirmed_active/unconfirmed_likely_dead
// half of refresh (see queueBacklog's own doc comment for the full "why split it" rationale
// and the breaking-change note). It lists every unconfirmed node with at least one
// health-check row (Confirmed: false, HasHealthChecks: true -- the exact same NodeFilter the
// old, single "unconfirmed" gauge used, and the same filter internal/collector's
// PollUnconfirmed uses for its own poll queue), then classifies each one into
// unconfirmed_active vs unconfirmed_likely_dead via storage.IsLikelyDead applied to that
// node's most recent likelyDeadHistoryLimit health checks -- fetched in one batched
// GetNodeHistoryForNodes call, not one GetNodeHistory call per node, since production scale
// here is tens of thousands of nodes. This reuses the EXACT same heuristic
// internal/collector's own pollInterval/collectorLikelyDead consults to decide a node's poll
// cadence (both now call storage.IsLikelyDead), rather than a second, possibly-drifting
// reimplementation.
func (m *netmapMetrics) refreshUnconfirmedQueueBacklog(ctx context.Context, store storage.Store) error {
	unconfirmed := false
	hasHistory := true
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{Confirmed: &unconfirmed, HasHealthChecks: &hasHistory})
	if err != nil {
		return fmt.Errorf("list unconfirmed nodes with history: %w", err)
	}

	nodeIDs := make([]uuid.UUID, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}
	historyByNode, err := store.GetNodeHistoryForNodes(ctx, nodeIDs, likelyDeadHistoryLimit)
	if err != nil {
		return fmt.Errorf("get node history for unconfirmed nodes: %w", err)
	}

	var active, likelyDead int
	for _, id := range nodeIDs {
		if storage.IsLikelyDead(historyByNode[id]) {
			likelyDead++
		} else {
			active++
		}
	}

	m.queueBacklog.WithLabelValues("unconfirmed_active").Set(float64(active))
	m.queueBacklog.WithLabelValues("unconfirmed_likely_dead").Set(float64(likelyDead))
	return nil
}

// runMetricsRefreshLoop calls refresh once immediately, then every metricsRefreshInterval,
// until ctx is cancelled -- started only when -metrics-addr is actually set (see run()), so a
// process with metrics disabled never issues these extra periodic queries at all.
func (m *netmapMetrics) runMetricsRefreshLoop(ctx context.Context, store storage.Store) {
	m.refresh(ctx, store)

	ticker := time.NewTicker(metricsRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refresh(ctx, store)
		}
	}
}

// statusRecordingWriter wraps an http.ResponseWriter, recording the status code passed to the
// first WriteHeader call (defaulting to 200, matching net/http's own implicit-200 behavior if
// a handler never calls WriteHeader at all before its first Write) -- instrumentHTTP's own
// after-the-fact "status" label needs this, since http.ResponseWriter itself exposes no way to
// read back a status code once written.
type statusRecordingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusRecordingWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// instrumentHTTP wraps next (this binary's existing top-level mux -- see main.go, "/" for the
// dashboard and "/api/" for the JSON API) with a small manual middleware recording
// httpRequestsTotal/httpRequestDuration per request -- a standard promhttp middleware/full
// router framework was deliberately NOT pulled in for this (see this file's own doc comment):
// this repo's mux is a plain net/http.ServeMux with Go 1.22 method+pattern routes, and this is
// the smallest wrapper that gets method/status/latency plus a genuinely bounded route label
// (see httpRouteLabel) out of that.
func (m *netmapMetrics) instrumentHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecordingWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(rec, r)

		route := httpRouteLabel(r.URL.Path)
		duration := time.Since(start).Seconds()
		m.httpRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
		m.httpRequestDuration.WithLabelValues(r.Method, route).Observe(duration)
	})
}

// httpRouteLabel classifies path into a small, fixed set of route labels rather than using the
// raw URL path directly -- several of this binary's real routes embed a node UUID
// (/nodes/{id}, /api/nodes/{id}, /api/nodes/{id}/history, /api/nodes/{id}/edges, see
// internal/web/web.go and internal/api/api.go's own mux.HandleFunc calls), and a raw-path
// label would give Prometheus one time series PER NODE EVER VIEWED -- unbounded cardinality
// that only grows over the life of the deployment. Every case below is checked longest-prefix/
// most-specific first, mirroring the exact same route list both mux's own registration calls
// use, and falls back to "other" for anything unrecognized (e.g. a 404) rather than silently
// omitting it from the metric.
func httpRouteLabel(path string) string {
	switch {
	case path == "/":
		return "dashboard_home"
	case path == "/topology":
		return "dashboard_topology"
	case path == "/network":
		return "dashboard_network"
	case strings.HasPrefix(path, "/static/"):
		return "dashboard_static"
	case strings.HasPrefix(path, "/nodes/"):
		return "dashboard_node_detail"
	case strings.HasPrefix(path, "/admin/"):
		return "dashboard_admin"

	case path == "/api/v1/stats":
		return "api_stats"
	case path == "/api/healthz":
		return "api_healthz"
	case path == "/api/nodes/seeds":
		return "api_seed_candidates"
	case path == "/api/config/peer-seeds":
		return "api_config_peer_seeds"
	case path == "/api/topology/top-peered":
		return "api_topology_top_peered"
	case path == "/api/topology":
		return "api_topology"
	case path == "/api/nodes":
		return "api_nodes_collection"
	case strings.HasPrefix(path, "/api/nodes/") && strings.HasSuffix(path, "/history"):
		return "api_node_history"
	case strings.HasPrefix(path, "/api/nodes/") && strings.HasSuffix(path, "/edges"):
		return "api_node_edges"
	case strings.HasPrefix(path, "/api/nodes/"):
		return "api_node_detail"
	case strings.HasPrefix(path, "/api/admin/"):
		return "api_admin"

	default:
		return "other"
	}
}

// healthzTimeout/healthzResponse/newMetricsServer below reuse cmd/netmap-p2p-responder/
// metrics.go's EXACT shape (per BRIEF5.md's Change 2 "reuse newMetricsServer/healthzResponse's
// existing shape... don't invent a different JSON shape") -- a minimal net/http server on its
// own listener serving /metrics (this process' own dedicated registry, via
// promhttp.HandlerFor) and /healthz ({"status":"ok"} 200, or {"status":"error: ..."} 503 on a
// failed store.Ping).

// healthzTimeout bounds the store.Ping call /healthz makes -- same short-timeout rationale as
// cmd/netmap-p2p-responder/metrics.go's identical constant.
const healthzTimeout = 2 * time.Second

// healthzResponse is the minimal JSON body /healthz returns -- identical shape to
// cmd/netmap-p2p-responder/metrics.go's healthzResponse.
type healthzResponse struct {
	Status string `json:"status"`
}

// newMetricsServer builds the *http.Server this binary serves /metrics and /healthz from, on
// its own listener, entirely separate from this binary's existing (Caddy-proxied) dashboard/
// API listener -- see main.go's -metrics-addr flag and the loud "internal-only, never the
// public interface" warnings there and at the bind call site. store is used only for
// /healthz's store.Ping(ctx) reachability check.
func newMetricsServer(store storage.Store, metrics *netmapMetrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), healthzTimeout)
		defer cancel()

		if err := store.Ping(ctx); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(healthzResponse{Status: "error: " + err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(healthzResponse{Status: "ok"})
	})
	return &http.Server{Handler: mux}
}

// staticNodeClientCheck exists purely to keep the collector import used even if a future edit
// removes onPollResult's only other collector.* reference (collector.PollResultFunc, in this
// file's onPollResult doc comment) -- see collector.PollResultFunc's own doc comment in
// internal/collector/collector.go for the type this method satisfies.
var _ collector.PollResultFunc = (*netmapMetrics)(nil).onPollResult
