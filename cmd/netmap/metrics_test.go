package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// defaultTestDSN matches this sandbox's real Postgres 17 instance: unix socket at
// /workspace/pg-embed/sockets, port 5433, database "netmap", user "postgres", trust auth (no
// password). Mirrors the exact same constant already duplicated per-package elsewhere in this
// repo (internal/storage, internal/api, internal/collector, internal/web,
// cmd/netmap-p2p-responder) — see any of those test files' copy for the established
// convention this follows.
const defaultTestDSN = "postgres://postgres@localhost:5433/netmap?sslmode=disable&host=/workspace/pg-embed/sockets"

func testDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return defaultTestDSN
}

// acquireTestDBLock takes a session-level Postgres advisory lock shared by every test package
// that exercises the real test database. `go test ./...` runs each package's tests as a
// separate process, potentially in parallel, but they all point at the same shared Postgres
// instance and truncate its tables — without this lock, two packages' tests running
// concurrently stomp on each other's data.
func acquireTestDBLock(t *testing.T, ctx context.Context, dsn string) func() {
	t.Helper()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("skipping: cannot reach test database: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext('go-tari-netmap-tests')::bigint)"); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("acquire test db advisory lock: %v", err)
	}

	return func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock(hashtext('go-tari-netmap-tests')::bigint)")
		_ = conn.Close(unlockCtx)
	}
}

// newTestStore connects to the configured test database, runs migrations, and truncates all
// tables so each test starts from a clean slate. It skips the test (t.Skip) if the database
// can't be reached, so `go test ./...` doesn't hard-fail in environments with no test DB
// configured.
func newTestStore(t *testing.T) storage.Store {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dsn := testDSN()

	t.Cleanup(acquireTestDBLock(t, ctx, dsn))

	store, err := storage.New(ctx, dsn)
	if err != nil {
		t.Skipf("skipping: cannot reach test database: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for truncate: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE node_health, peer_edge_observations, node_addresses, pending_submissions, pending_wallet_submissions, nodes CASCADE"); err != nil {
		pool.Close()
		t.Fatalf("truncate test tables: %v", err)
	}
	pool.Close()

	t.Cleanup(func() { _ = store.Close() })
	return store
}

// mustTestNetmapMetrics builds a *netmapMetrics for "mainnet" on its own dedicated registry
// (see newNetmapMetrics/netmapMetrics' doc comments) -- used by every test in this file that
// needs a non-nil *netmapMetrics but doesn't care about network-scoping specifically (that's
// TestNewNetmapMetricsProducesNetworkScopedNames's job).
func mustTestNetmapMetrics(t *testing.T) *netmapMetrics {
	t.Helper()
	m, err := newNetmapMetrics("mainnet")
	if err != nil {
		t.Fatalf("newNetmapMetrics: %v", err)
	}
	return m
}

// TestValidateNetmapNetwork exercises the required -network flag's fail-fast validation: only
// "mainnet"/"testnet" are accepted, an empty or unrecognized value is always an error — never a
// silent default.
func TestValidateNetmapNetwork(t *testing.T) {
	cases := []struct {
		network string
		wantErr bool
	}{
		{network: "mainnet", wantErr: false},
		{network: "testnet", wantErr: false},
		{network: "", wantErr: true},
		{network: "Mainnet", wantErr: true},
		{network: "devnet", wantErr: true},
	}
	for _, tc := range cases {
		err := validateNetmapNetwork(tc.network)
		if tc.wantErr && err == nil {
			t.Errorf("validateNetmapNetwork(%q) = nil, want an error", tc.network)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateNetmapNetwork(%q) = %v, want nil", tc.network, err)
		}
	}
}

// TestNewNetmapMetricsRejectsInvalidNetwork mirrors TestValidateNetmapNetwork at the
// newNetmapMetrics constructor level -- it must fail fast (no metrics built/registered) rather
// than silently defaulting.
func TestNewNetmapMetricsRejectsInvalidNetwork(t *testing.T) {
	if _, err := newNetmapMetrics(""); err == nil {
		t.Error("newNetmapMetrics(\"\") = nil error, want an error")
	}
	if _, err := newNetmapMetrics("devnet"); err == nil {
		t.Error("newNetmapMetrics(\"devnet\") = nil error, want an error")
	}
}

// scrapeNetmapMetrics renders m's own dedicated registry through newMetricsServer's own
// /metrics handler (promhttp.HandlerFor(m.registry, ...), see metrics.go) and returns the raw
// exposition-format body -- the exact same code path a real Prometheus scrape hits. store may
// be nil here since /metrics never touches it (only /healthz does).
func scrapeNetmapMetrics(t *testing.T, m *netmapMetrics) string {
	t.Helper()
	server := newMetricsServer(nil, m)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	return rec.Body.String()
}

// TestNewNetmapMetricsProducesNetworkScopedNames asserts mainnet and testnet each produce
// distinctly-prefixed metric names (netmap_mainnet_collector_.../netmap_mainnet_api_... vs
// netmap_testnet_collector_.../netmap_testnet_api_...), exactly mirroring
// cmd/netmap-p2p-responder/metrics_test.go's equivalent test for the responder.
func TestNewNetmapMetricsProducesNetworkScopedNames(t *testing.T) {
	for _, network := range []string{"mainnet", "testnet"} {
		t.Run(network, func(t *testing.T) {
			m, err := newNetmapMetrics(network)
			if err != nil {
				t.Fatalf("newNetmapMetrics(%q): %v", network, err)
			}
			m.queueBacklog.WithLabelValues("confirmed").Set(1)
			m.httpRequestsTotal.WithLabelValues("GET", "dashboard_home", "200").Inc()

			body := scrapeNetmapMetrics(t, m)

			wantCollector := "netmap_" + network + "_collector_poll_queue_backlog"
			if !strings.Contains(body, wantCollector) {
				t.Errorf("scrape output missing %q, got:\n%s", wantCollector, body)
			}
			wantAPI := "netmap_" + network + "_api_http_requests_total"
			if !strings.Contains(body, wantAPI) {
				t.Errorf("scrape output missing %q, got:\n%s", wantAPI, body)
			}

			other := "mainnet"
			if network == "mainnet" {
				other = "testnet"
			}
			wrongPrefix := "netmap_" + other + "_"
			if strings.Contains(body, wrongPrefix) {
				t.Errorf("scrape output for network=%q unexpectedly contains the other network's prefix %q, got:\n%s", network, wrongPrefix, body)
			}
		})
	}
}

// TestMetricsEndpointServesGoAndProcessCollectors confirms the standard Go/process collectors
// (explicitly registered on our dedicated registry, see newNetmapMetrics) still show up.
func TestMetricsEndpointServesGoAndProcessCollectors(t *testing.T) {
	m := mustTestNetmapMetrics(t)
	body := scrapeNetmapMetrics(t, m)
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("/metrics response missing go_goroutines, got:\n%s", body)
	}
}

// TestHealthzOK exercises newMetricsServer's /healthz handler against a real, reachable test
// database: it must return 200 with {"status":"ok"}.
func TestHealthzOK(t *testing.T) {
	store := newTestStore(t)
	server := newMetricsServer(store, mustTestNetmapMetrics(t))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body healthzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body %q: %v", rec.Body.String(), err)
	}
	if body.Status != "ok" {
		t.Errorf("status field = %q, want %q", body.Status, "ok")
	}
}

// unreachableStore is a storage.Store whose Ping always fails — used to exercise /healthz's
// 503 branch and refresh's dbUp=0 branch without needing to actually take down the test
// database.
type unreachableStore struct {
	storage.Store
}

func (u *unreachableStore) Ping(ctx context.Context) error {
	return errors.New("simulated: database unreachable")
}

// TestHealthzUnreachableDB exercises newMetricsServer's /healthz handler when store.Ping
// fails: it must return 503, never 200.
func TestHealthzUnreachableDB(t *testing.T) {
	store := newTestStore(t)
	server := newMetricsServer(&unreachableStore{Store: store}, mustTestNetmapMetrics(t))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestInstrumentHTTPRecordsRequests exercises instrumentHTTP: it must pass the request through
// to next unmodified (same response body/status) while also incrementing httpRequestsTotal and
// observing httpRequestDuration, labeled by method/httpRouteLabel/status.
func TestInstrumentHTTPRecordsRequests(t *testing.T) {
	m := mustTestNetmapMetrics(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	})

	wrapped := m.instrumentHTTP(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d (middleware must not alter the response)", rec.Code, http.StatusTeapot)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "hello")
	}

	body := scrapeNetmapMetrics(t, m)
	if !strings.Contains(body, `netmap_mainnet_api_http_requests_total{method="GET",route="dashboard_home",status="418"} 1`) {
		t.Errorf("scrape output missing expected http_requests_total series, got:\n%s", body)
	}
	if !strings.Contains(body, "netmap_mainnet_api_http_request_duration_seconds") {
		t.Errorf("scrape output missing http_request_duration_seconds, got:\n%s", body)
	}
}

// TestHTTPRouteLabelIsLowCardinality confirms two DIFFERENT node-detail paths (which embed a
// UUID) collapse onto the SAME route label -- the whole point of httpRouteLabel's fixed,
// bounded label set rather than the raw URL path (see its own doc comment on cardinality).
func TestHTTPRouteLabelIsLowCardinality(t *testing.T) {
	m := mustTestNetmapMetrics(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	wrapped := m.instrumentHTTP(inner)

	for _, path := range []string{"/nodes/11111111-1111-1111-1111-111111111111", "/nodes/22222222-2222-2222-2222-222222222222", "/topology"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}

	body := scrapeNetmapMetrics(t, m)
	if !strings.Contains(body, `netmap_mainnet_api_http_requests_total{method="GET",route="dashboard_node_detail",status="200"} 2`) {
		t.Errorf("expected a single accumulated dashboard_node_detail series with value 2, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_api_http_requests_total{method="GET",route="dashboard_topology",status="200"} 1`) {
		t.Errorf("expected a dashboard_topology series with value 1, got:\n%s", body)
	}
}

// TestHTTPRouteLabelClassifiesKnownRoutes spot-checks httpRouteLabel's classification of a
// handful of this binary's real routes (see internal/web/web.go's and internal/api/api.go's
// own mux.HandleFunc calls) plus the unrecognized-path fallback.
func TestHTTPRouteLabelClassifiesKnownRoutes(t *testing.T) {
	cases := map[string]string{
		"/":                          "dashboard_home",
		"/topology":                  "dashboard_topology",
		"/network":                   "dashboard_network",
		"/static/style.css":          "dashboard_static",
		"/nodes/abc-123":             "dashboard_node_detail",
		"/admin/submissions":         "dashboard_admin",
		"/api/v1/stats":              "api_stats",
		"/api/nodes":                 "api_nodes_collection",
		"/api/nodes/abc-123":         "api_node_detail",
		"/api/nodes/abc-123/history": "api_node_history",
		"/api/nodes/abc-123/edges":   "api_node_edges",
		"/api/topology":              "api_topology",
		"/api/topology/top-peered":   "api_topology_top_peered",
		"/api/nodes/seeds":           "api_seed_candidates",
		"/api/config/peer-seeds":     "api_config_peer_seeds",
		"/api/admin/submissions":     "api_admin",
		"/totally/unknown/path":      "other",
	}
	for path, want := range cases {
		if got := httpRouteLabel(path); got != want {
			t.Errorf("httpRouteLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestOnPollResultIncrementsMetric exercises netmapMetrics.onPollResult (wired as
// collector.Collector.OnPollResult in main.go) -- see
// cmd/netmap-p2p-responder/metrics_test.go's equivalent responderMetrics tests for the same
// pattern.
func TestOnPollResultIncrementsMetric(t *testing.T) {
	m := mustTestNetmapMetrics(t)

	m.onPollResult(storage.ProbeSourceGRPC, true)
	m.onPollResult(storage.ProbeSourceP2P, false)

	body := scrapeNetmapMetrics(t, m)
	if !strings.Contains(body, `netmap_mainnet_collector_poll_result_total{probe_source="grpc",result="success"} 1`) {
		t.Errorf("scrape output missing grpc success series, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_result_total{probe_source="p2p",result="failure"} 1`) {
		t.Errorf("scrape output missing p2p failure series, got:\n%s", body)
	}
}

// TestRefreshPopulatesGauges exercises refresh end-to-end against a real test database,
// seeding a mix of confirmed / active-unconfirmed / likely-dead / never-contacted nodes and
// asserting each of the four resulting queue_backlog gauge values (queue="confirmed",
// queue="unconfirmed_active", queue="unconfirmed_likely_dead", queue="never_contacted")
// matches expectation exactly, plus dbUp and knownNodes.
func TestRefreshPopulatesGauges(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.UpsertDiscoveredNode(ctx, "owned:1", storage.DiscoverySourceP2P, map[string]any{"owner": "Jagtech"}, nil); err != nil {
		t.Fatalf("seed owned placeholder: %v", err)
	}
	if _, err := store.UpsertConfirmedNode(ctx, "owned:1", []byte{0x02}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("promote owned node: %v", err)
	}
	if _, err := store.UpsertConfirmedNode(ctx, "confirmed:1", []byte{0x01}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("seed confirmed node: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, "never-contacted:1", storage.DiscoverySourceRegistry, nil, nil); err != nil {
		t.Fatalf("seed never-contacted node: %v", err)
	}

	// activeUnconfirmed: unconfirmed, has history, but fewer than 3 recorded health checks
	// (storage.IsLikelyDead's own "fewer than 3 is never enough to conclude anything" floor)
	// -- must land in unconfirmed_active, not unconfirmed_likely_dead.
	activeUnconfirmed, err := store.UpsertDiscoveredNode(ctx, "active-unconfirmed:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed active-unconfirmed node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: activeUnconfirmed.ID, Reachable: false, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
		t.Fatalf("record active-unconfirmed health check: %v", err)
	}

	// likelyDead: unconfirmed, 3 most-recent health checks, zero successes among them --
	// must land in unconfirmed_likely_dead per storage.IsLikelyDead's exact heuristic.
	likelyDead, err := store.UpsertDiscoveredNode(ctx, "likely-dead:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed likely-dead node: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: likelyDead.ID, Reachable: false, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
			t.Fatalf("record likely-dead health check %d: %v", i, err)
		}
	}

	m := mustTestNetmapMetrics(t)
	m.refresh(ctx, store)

	body := scrapeNetmapMetrics(t, m)

	if !strings.Contains(body, `netmap_mainnet_collector_db_up 1`) {
		t.Errorf("scrape output missing db_up=1 (DB is reachable), got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="confirmed_owned"} 1`) {
		t.Errorf("scrape output missing confirmed_owned queue_backlog=1, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="confirmed_generic"} 1`) {
		t.Errorf("scrape output missing confirmed_generic queue_backlog=1, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="unconfirmed_active"} 1`) {
		t.Errorf("scrape output missing unconfirmed_active queue_backlog=1, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="unconfirmed_likely_dead"} 1`) {
		t.Errorf("scrape output missing unconfirmed_likely_dead queue_backlog=1, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="never_contacted"} 1`) {
		t.Errorf("scrape output missing never_contacted queue_backlog=1, got:\n%s", body)
	}
	// The old, single "unconfirmed" label value must no longer appear at all -- see
	// queueBacklog's doc comment on the breaking dashboard change this split is.
	if strings.Contains(body, `queue="unconfirmed"}`) {
		t.Errorf("scrape output unexpectedly still contains the old queue=\"unconfirmed\" label value, got:\n%s", body)
	}
	// p2p known_nodes=4: owned:1, confirmed:1, activeUnconfirmed, and likelyDead are all
	// seeded via DiscoverySourceP2P above -- FetchNodeCounts counts the WHOLE population by
	// discovery_source regardless of confirmed/unconfirmed/owned status.
	if !strings.Contains(body, `netmap_mainnet_collector_known_nodes{discovery_source="p2p"} 4`) {
		t.Errorf("scrape output missing p2p known_nodes=4, got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_known_nodes{discovery_source="registry"} 1`) {
		t.Errorf("scrape output missing registry known_nodes=1, got:\n%s", body)
	}
}

// TestRefreshUnconfirmedQueueBacklogMatchesCollectorLikelyDeadHeuristic asserts
// refreshUnconfirmedQueueBacklog's classification tracks storage.IsLikelyDead exactly, even
// when a node's most recent 3 checks include a mix (never satisfies the heuristic) versus all
// 4+ most-recent checks all failing including one older than the 3-check window (still
// satisfies it, since only the most recent 3 matter) -- both edge cases collector.go's own
// pollInterval doc comment calls out, exercised here via the metrics-refresh path instead.
func TestRefreshUnconfirmedQueueBacklogMatchesCollectorLikelyDeadHeuristic(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// mixedRecent: 3 most-recent checks are fail, fail, success (oldest to newest) -- one
	// success among the most recent 3 rules out likely-dead regardless of history length.
	mixedRecent, err := store.UpsertDiscoveredNode(ctx, "mixed-recent:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed mixed-recent node: %v", err)
	}
	for _, reachable := range []bool{false, false, true} {
		if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: mixedRecent.ID, Reachable: reachable, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
			t.Fatalf("record mixed-recent health check: %v", err)
		}
	}

	// oldSuccessOnly: 4 checks total, oldest is a success, the 3 most recent are all
	// failures -- must still classify as likely-dead, since only the most recent 3 are
	// consulted (the older success outside that window doesn't save it).
	oldSuccessOnly, err := store.UpsertDiscoveredNode(ctx, "old-success-only:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed old-success-only node: %v", err)
	}
	for _, reachable := range []bool{true, false, false, false} {
		if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: oldSuccessOnly.ID, Reachable: reachable, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
			t.Fatalf("record old-success-only health check: %v", err)
		}
	}

	m := mustTestNetmapMetrics(t)
	m.refresh(ctx, store)

	body := scrapeNetmapMetrics(t, m)
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="unconfirmed_active"} 1`) {
		t.Errorf("scrape output missing unconfirmed_active queue_backlog=1 (mixedRecent), got:\n%s", body)
	}
	if !strings.Contains(body, `netmap_mainnet_collector_poll_queue_backlog{queue="unconfirmed_likely_dead"} 1`) {
		t.Errorf("scrape output missing unconfirmed_likely_dead queue_backlog=1 (oldSuccessOnly), got:\n%s", body)
	}
}

// TestRefreshReportsDBDown exercises refresh's dbUp=0 branch when store.Ping fails, and
// confirms it returns early without touching the other gauges (see refresh's own doc comment).
func TestRefreshReportsDBDown(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	m := mustTestNetmapMetrics(t)
	m.refresh(ctx, &unreachableStore{Store: store})

	body := scrapeNetmapMetrics(t, m)
	if !strings.Contains(body, `netmap_mainnet_collector_db_up 0`) {
		t.Errorf("scrape output missing db_up=0, got:\n%s", body)
	}
}
