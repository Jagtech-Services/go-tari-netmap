package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"
	rpcpkg "github.com/Jagtech-Services/go-tari-lib/v3/p2p/rpc"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// TestValidateNetwork exercises the required -network flag's fail-fast validation (see
// BRIEF5.md's testing requirement: "an invalid/missing -network value fails fast rather than
// defaulting silently") -- "mainnet"/"testnet" must succeed, everything else (including empty)
// must return an error.
func TestValidateNetwork(t *testing.T) {
	cases := []struct {
		network string
		wantErr bool
	}{
		{network: "mainnet", wantErr: false},
		{network: "testnet", wantErr: false},
		{network: "", wantErr: true},
		{network: "Mainnet", wantErr: true},
		{network: "TESTNET", wantErr: true},
		{network: "devnet", wantErr: true},
	}
	for _, tc := range cases {
		err := validateNetwork(tc.network)
		if tc.wantErr && err == nil {
			t.Errorf("validateNetwork(%q) = nil, want an error", tc.network)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateNetwork(%q) = %v, want nil", tc.network, err)
		}
	}
}

// TestNewResponderMetricsRejectsInvalidNetwork mirrors TestValidateNetwork at the
// newResponderMetrics constructor level -- it must fail fast (no metrics built/registered) for
// an unset or unrecognized -network value rather than silently defaulting to some prefix.
func TestNewResponderMetricsRejectsInvalidNetwork(t *testing.T) {
	if _, err := newResponderMetrics(""); err == nil {
		t.Error("newResponderMetrics(\"\") = nil error, want an error")
	}
	if _, err := newResponderMetrics("devnet"); err == nil {
		t.Error("newResponderMetrics(\"devnet\") = nil error, want an error")
	}
}

// TestNewResponderMetricsProducesNetworkScopedNames is this file's core coverage for BRIEF5.md's
// Change 1: building a *responderMetrics for "mainnet" must produce metric names prefixed
// netmap_mainnet_p2p_responder_..., and for "testnet" netmap_testnet_p2p_responder_... -- both
// checked by actually incrementing a metric and scraping each instance's own dedicated registry
// via promhttp, exactly what a real Prometheus scrape would see.
func TestNewResponderMetricsProducesNetworkScopedNames(t *testing.T) {
	for _, network := range []string{"mainnet", "testnet"} {
		t.Run(network, func(t *testing.T) {
			m, err := newResponderMetrics(network)
			if err != nil {
				t.Fatalf("newResponderMetrics(%q): %v", network, err)
			}
			m.onConnectionAccepted(testAddr("203.0.113.1:1"))

			body := scrapeRegistry(t, m.registry)

			want := "netmap_" + network + "_p2p_responder_connections_accepted_total"
			if !strings.Contains(body, want) {
				t.Errorf("scrape output missing %q, got:\n%s", want, body)
			}

			// Cross-check: the OTHER network's prefix must never appear on this instance's
			// registry -- names are strictly per-instance, not accidentally shared/leaked.
			other := "mainnet"
			if network == "mainnet" {
				other = "testnet"
			}
			wrongPrefix := "netmap_" + other + "_p2p_responder_"
			if strings.Contains(body, wrongPrefix) {
				t.Errorf("scrape output for network=%q unexpectedly contains the other network's prefix %q, got:\n%s", network, wrongPrefix, body)
			}
		})
	}
}

// scrapeRegistry renders reg's current state through newMetricsServer's own /metrics handler
// (promhttp.HandlerFor(reg, ...), see metrics.go) and returns the raw exposition-format body --
// the exact same code path a real Prometheus scrape hits.
func scrapeRegistry(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	server := newMetricsServer(nil, &responderMetrics{registry: reg})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	return rec.Body.String()
}

// TestOnConnectionAcceptedIncrementsMetric through TestOnSubstreamProtocolDeclinedIncrementsMetric
// exercise responderMetrics' own methods, which are wired directly as p2p.ResponderConfig's
// On*/observability fields in main.go (see metrics.go) -- each just increments/observes the
// matching Prometheus metric. Every test below builds its own *responderMetrics on its own
// dedicated registry (see newResponderMetrics), so plain before/after absolute assertions work
// fine -- no shared global registry to worry about (unlike this file's previous
// prometheus.DefaultRegisterer-based version).

func TestOnConnectionAcceptedIncrementsMetric(t *testing.T) {
	m := mustTestResponderMetrics(t)
	before := testutil.ToFloat64(m.connectionsAccepted)
	m.onConnectionAccepted(testAddr("203.0.113.1:1"))
	after := testutil.ToFloat64(m.connectionsAccepted)
	if after != before+1 {
		t.Errorf("connections_accepted_total = %v, want %v", after, before+1)
	}
}

func TestOnHandshakeResultIncrementsMetric(t *testing.T) {
	m := mustTestResponderMetrics(t)
	beforeSuccess := testutil.ToFloat64(m.handshakeResult.WithLabelValues("success"))
	beforeFailure := testutil.ToFloat64(m.handshakeResult.WithLabelValues("failure"))

	m.onHandshakeResult(testAddr("203.0.113.2:1"), true)
	m.onHandshakeResult(testAddr("203.0.113.3:1"), false)

	if got := testutil.ToFloat64(m.handshakeResult.WithLabelValues("success")); got != beforeSuccess+1 {
		t.Errorf("handshake_result_total{result=success} = %v, want %v", got, beforeSuccess+1)
	}
	if got := testutil.ToFloat64(m.handshakeResult.WithLabelValues("failure")); got != beforeFailure+1 {
		t.Errorf("handshake_result_total{result=failure} = %v, want %v", got, beforeFailure+1)
	}
}

func TestOnIdentityExchangeResultIncrementsMetric(t *testing.T) {
	m := mustTestResponderMetrics(t)
	beforeSuccess := testutil.ToFloat64(m.identityExchangeResult.WithLabelValues("success"))
	beforeFailure := testutil.ToFloat64(m.identityExchangeResult.WithLabelValues("failure"))

	m.onIdentityExchangeResult(testAddr("203.0.113.4:1"), true)
	m.onIdentityExchangeResult(testAddr("203.0.113.5:1"), false)

	if got := testutil.ToFloat64(m.identityExchangeResult.WithLabelValues("success")); got != beforeSuccess+1 {
		t.Errorf("identity_exchange_result_total{result=success} = %v, want %v", got, beforeSuccess+1)
	}
	if got := testutil.ToFloat64(m.identityExchangeResult.WithLabelValues("failure")); got != beforeFailure+1 {
		t.Errorf("identity_exchange_result_total{result=failure} = %v, want %v", got, beforeFailure+1)
	}
}

func TestOnGetPeersServedIncrementsMetricAndObservesHistogram(t *testing.T) {
	m := mustTestResponderMetrics(t)
	beforeServed := testutil.ToFloat64(m.getPeersServed)
	beforeSampleCount := histogramSampleCount(t, m.getPeersPeerCount)

	m.onGetPeersServed(testAddr("203.0.113.6:1"), 7)

	if got := testutil.ToFloat64(m.getPeersServed); got != beforeServed+1 {
		t.Errorf("get_peers_served_total = %v, want %v", got, beforeServed+1)
	}
	if got := histogramSampleCount(t, m.getPeersPeerCount); got != beforeSampleCount+1 {
		t.Errorf("get_peers_peer_count sample count = %d, want %d", got, beforeSampleCount+1)
	}
}

// histogramSampleCount reads a Histogram metric's cumulative observation count via its Write
// method (the same mechanism promhttp.Handler() itself uses internally to serialize a
// Histogram) -- testutil.CollectAndCount is NOT usable here since it counts distinct metric
// *series* (always 1 for an unlabeled Histogram), not the number of Observe calls.
func histogramSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("writing histogram metric: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestOnSubstreamProtocolDeclinedIncrementsMetric(t *testing.T) {
	m := mustTestResponderMetrics(t)
	before := testutil.ToFloat64(m.substreamProtocolDeclined.WithLabelValues("t/msg/0.1"))
	m.onSubstreamProtocolDeclined(testAddr("203.0.113.7:1"), []byte("t/msg/0.1"))
	after := testutil.ToFloat64(m.substreamProtocolDeclined.WithLabelValues("t/msg/0.1"))
	if after != before+1 {
		t.Errorf("substream_protocol_declined_total{protocol=\"t/msg/0.1\"} = %v, want %v", after, before+1)
	}
}

// TestOnReportFlushResultIncrementsMetric exercises the report-flush counter (see this
// repo's readiness-review follow-up, Fix 2) -- wired as remotestore.Config.OnFlushResult's
// counter-only half in main.go.
func TestOnReportFlushResultIncrementsMetric(t *testing.T) {
	m := mustTestResponderMetrics(t)
	beforeSuccess := testutil.ToFloat64(m.reportFlushResult.WithLabelValues("success"))
	beforeFailure := testutil.ToFloat64(m.reportFlushResult.WithLabelValues("failure"))

	m.onReportFlushResult(true)
	m.onReportFlushResult(false)

	if got := testutil.ToFloat64(m.reportFlushResult.WithLabelValues("success")); got != beforeSuccess+1 {
		t.Errorf("report_flush_result_total{result=success} = %v, want %v", got, beforeSuccess+1)
	}
	if got := testutil.ToFloat64(m.reportFlushResult.WithLabelValues("failure")); got != beforeFailure+1 {
		t.Errorf("report_flush_result_total{result=failure} = %v, want %v", got, beforeFailure+1)
	}
}

// TestOnPollResultIncrementsMetric exercises the active-scanner poll-result counter (Fix
// 2 / findings I17/I28) -- wired as collector.Collector.OnPollResult in newActiveScanner.
func TestOnPollResultIncrementsMetric(t *testing.T) {
	m := mustTestResponderMetrics(t)
	beforeGRPCSuccess := testutil.ToFloat64(m.pollResult.WithLabelValues("grpc", "success"))
	beforeP2PFailure := testutil.ToFloat64(m.pollResult.WithLabelValues("p2p", "failure"))

	m.onPollResult(storage.ProbeSourceGRPC, true)
	m.onPollResult(storage.ProbeSourceP2P, false)

	if got := testutil.ToFloat64(m.pollResult.WithLabelValues("grpc", "success")); got != beforeGRPCSuccess+1 {
		t.Errorf("collector_poll_result_total{probe_source=grpc,result=success} = %v, want %v", got, beforeGRPCSuccess+1)
	}
	if got := testutil.ToFloat64(m.pollResult.WithLabelValues("p2p", "failure")); got != beforeP2PFailure+1 {
		t.Errorf("collector_poll_result_total{probe_source=p2p,result=failure} = %v, want %v", got, beforeP2PFailure+1)
	}
}

// TestOnPeerIdentityIncrementsDBWriteMetrics exercises the DB-write result counters wired
// directly at dbBackedResponder's storage.Store call sites (responder.go), against the real
// test database (same pattern as responder_test.go's newTestStore).
//
// The identity fixture claims a valid public address (rather than a zero-claims fixture) since
// OPENCODE_BRIEF.md's "stop recording blank-address nodes" fix makes onPeerIdentity skip both
// UpsertConfirmedNode and RecordHealthCheck entirely when there are no usable claimed
// addresses -- this test needs those DB calls to actually happen to exercise their metrics.
func TestOnPeerIdentityIncrementsDBWriteMetrics(t *testing.T) {
	store := newTestStore(t)
	metrics := mustTestResponderMetrics(t)
	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: metrics}

	beforeUpsertSuccess := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, "success"))
	beforeHealthSuccess := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationRecordHealth, "success"))

	claimedAddr, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.90/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}
	r.onPeerIdentity(testAddr("203.0.113.80:41000"), []byte{0x90}, &p2p.PeerInfo{
		RemoteStaticPubKey: []byte{0x90},
		Addresses:          [][]byte{claimedAddr},
		Features:           p2p.FeaturesCommunicationNode,
	})

	if got := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, "success")); got != beforeUpsertSuccess+1 {
		t.Errorf("db_write_result_total{operation=upsert_node,result=success} = %v, want %v", got, beforeUpsertSuccess+1)
	}
	if got := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationRecordHealth, "success")); got != beforeHealthSuccess+1 {
		t.Errorf("db_write_result_total{operation=record_health,result=success} = %v, want %v", got, beforeHealthSuccess+1)
	}
}

// failingStore wraps a real storage.Store, delegating every method to it except
// UpsertConfirmedNode/UpsertConfirmedNodeByPubKey, which always fail -- used to exercise
// onPeerIdentity's failure-path metric recording without needing to actually break the test
// database. Both are overridden since onPeerIdentity's own address-vs-no-address branch (see
// responder.go, BRIEF6.md) picks one or the other depending on whether the test's identity
// claims any addresses.
type failingStore struct {
	storage.Store
}

func (f *failingStore) UpsertConfirmedNode(ctx context.Context, address string, publicKey []byte, discoverySource storage.DiscoverySource) (storage.Node, error) {
	return storage.Node{}, errors.New("simulated UpsertConfirmedNode failure")
}

func (f *failingStore) UpsertConfirmedNodeByPubKey(ctx context.Context, publicKey []byte, discoverySource storage.DiscoverySource) (storage.Node, error) {
	return storage.Node{}, errors.New("simulated UpsertConfirmedNodeByPubKey failure")
}

// TestOnPeerIdentityRecordsDBWriteFailureMetric exercises the failure-path branch of the
// upsert_node DB-write metric: a failing store must increment
// db_write_result_total{operation="upsert_node",result="failure"} and must NOT reach
// RecordHealthCheck at all (onPeerIdentity returns early on the first UpsertConfirmedNode
// failure, see responder.go).
//
// The identity fixture claims a valid public address (rather than a zero-claims fixture) so
// onPeerIdentity actually reaches the UpsertConfirmedNode call this test means to fail --
// OPENCODE_BRIEF.md's "stop recording blank-address nodes" fix returns early before ever
// calling into the store when there are no usable claimed addresses.
func TestOnPeerIdentityRecordsDBWriteFailureMetric(t *testing.T) {
	store := newTestStore(t)
	metrics := mustTestResponderMetrics(t)
	r := &dbBackedResponder{store: &failingStore{Store: store}, logf: t.Logf, metrics: metrics}

	beforeUpsertFailure := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, "failure"))
	beforeHealthSuccess := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationRecordHealth, "success"))

	claimedAddr, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.91/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}
	r.onPeerIdentity(testAddr("203.0.113.81:41000"), []byte{0x91}, &p2p.PeerInfo{
		RemoteStaticPubKey: []byte{0x91},
		Addresses:          [][]byte{claimedAddr},
		Features:           p2p.FeaturesCommunicationNode,
	})

	if got := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, "failure")); got != beforeUpsertFailure+1 {
		t.Errorf("db_write_result_total{operation=upsert_node,result=failure} = %v, want %v", got, beforeUpsertFailure+1)
	}
	if got := testutil.ToFloat64(metrics.bufferAppendResult.WithLabelValues(bufferOperationRecordHealth, "success")); got != beforeHealthSuccess {
		t.Errorf("db_write_result_total{operation=record_health,result=success} = %v, want unchanged %v (RecordHealthCheck must never be reached after a failed UpsertConfirmedNode)", got, beforeHealthSuccess)
	}
}

// TestServeWiresPeerListAndIdentityOverLoopback runs a REAL p2p.Serve loop configured with
// this binary's actual production ResponderConfig wiring (mirroring main.go's cfg exactly) on a
// loopback listener, and dials it with go-tari-lib's own probe clients to prove the responder
// still functions end to end: a get_peers round trip succeeds (PeerListProvider), and an
// unsupported-protocol probe is still correctly declined.
//
// This test previously ALSO asserted that dialing moved five Prometheus metrics
// (connections_accepted_total, handshake_result_total, identity_exchange_result_total,
// get_peers_served_total, substream_protocol_declined_total), via
// ResponderConfig.OnConnectionAccepted/OnHandshakeResult/OnIdentityExchangeResult/
// OnGetPeersServed/OnSubstreamProtocolDeclined. Those fields do NOT exist on go-tari-lib/v3's
// actually-tagged v3.1.0 p2p.ResponderConfig -- they only ever existed on go-tari-lib's
// feat/db-backed-peer-list branch (commit 5339107), which was never merged into main and never
// released. See main.go's ResponderConfig construction site for the full explanation. Those
// five metric assertions have been removed from this test along with the fields that drove
// them -- this is a genuine upstream capability loss surfaced by this migration, not a test
// simplification of convenience. metrics.onConnectionAccepted etc. remain covered by their own
// direct unit tests above (TestOnConnectionAcceptedIncrementsMetric etc.), which still validate
// the increment logic itself even though nothing in production can reach it anymore.
func TestServeWiresPeerListAndIdentityOverLoopback(t *testing.T) {
	store := newTestStore(t)
	metrics := mustTestResponderMetrics(t)
	responder := &dbBackedResponder{store: store, logf: t.Logf, metrics: metrics}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	staticKeypair, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	cfg := p2p.ResponderConfig{
		StaticKeypair:    staticKeypair,
		OurFeatures:      p2p.FeaturesCommunicationNode,
		PeerListProvider: responder.peerListProvider,
		OnPeerIdentity:   responder.onPeerIdentity,
		Logf:             t.Logf,
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- p2p.Serve(serveCtx, listener, cfg)
	}()
	defer func() {
		serveCancel()
		listener.Close()
		<-serveErrCh
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connection 1: a real get_peers round trip -- exercises accept, handshake success,
	// identity exchange success, and a served (empty, since no confirmed/reachable nodes
	// exist yet) get_peers response, end to end.
	if _, err := p2p.ProbeGetPeersWithOptions(ctx, listener.Addr().String(), rpcpkg.GetPeersRequest{N: 50}, p2p.ProbeOptions{}); err != nil {
		t.Fatalf("ProbeGetPeersWithOptions: %v", err)
	}

	// Connection 2: ProbeChainMetadataWithOptions negotiates t/blksync/1 -- a protocol this
	// responder does NOT support (it only serves t/dht/1, see responder.go/main.go) -- this
	// must still fail even though we can no longer count it via OnSubstreamProtocolDeclined.
	if _, err := p2p.ProbeChainMetadataWithOptions(ctx, listener.Addr().String(), p2p.ProbeOptions{}); err == nil {
		t.Fatalf("expected ProbeChainMetadataWithOptions to fail against a responder that only supports t/dht/1")
	}
}

// TestHealthzOK exercises newMetricsServer's /healthz handler against a real, reachable test
// database: it must return 200 with {"status":"ok"}.
func TestHealthzOK(t *testing.T) {
	store := newTestStore(t)
	server := newMetricsServer(store, mustTestResponderMetrics(t))

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

// unreachableStore is a storage.Store whose Ping always fails -- used to exercise /healthz's
// 503 branch without needing to actually take down the test database.
type unreachableStore struct {
	storage.Store
}

func (u *unreachableStore) Ping(ctx context.Context) error {
	return errors.New("simulated: database unreachable")
}

// TestHealthzUnreachableDB exercises newMetricsServer's /healthz handler when store.Ping fails:
// it must return 503, never 200, and never touch the P2P listener (there is none in this test
// at all -- this endpoint's whole point is to be checkable independent of the P2P listener).
func TestHealthzUnreachableDB(t *testing.T) {
	store := newTestStore(t)
	server := newMetricsServer(&unreachableStore{Store: store}, mustTestResponderMetrics(t))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestMetricsEndpointServesPrometheusFormat exercises newMetricsServer's /metrics handler,
// confirming it serves this responderMetrics instance's own dedicated-registry Prometheus
// exposition format (see responderMetrics' doc comment on why it's no longer
// prometheus.DefaultGatherer), including at least one of this binary's own custom metrics by
// its network-scoped name, plus the standard process/Go collectors we now register explicitly.
func TestMetricsEndpointServesPrometheusFormat(t *testing.T) {
	store := newTestStore(t)
	metrics := mustTestResponderMetrics(t) // network="mainnet"
	server := newMetricsServer(store, metrics)

	// Increment something first so its HELP/TYPE lines are guaranteed to be emitted (a fresh
	// CounterVec with zero label combinations used yet emits nothing).
	metrics.onConnectionAccepted(testAddr("203.0.113.90:1"))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "netmap_mainnet_p2p_responder_connections_accepted_total") {
		t.Errorf("/metrics response missing netmap_mainnet_p2p_responder_connections_accepted_total, got:\n%s", body)
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Errorf("/metrics response missing the standard Go collector's go_goroutines (see newResponderMetrics registering it explicitly on our dedicated registry), got:\n%s", body)
	}
}
