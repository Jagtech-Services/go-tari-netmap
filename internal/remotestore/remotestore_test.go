package remotestore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

func testConfig(baseURL string) Config {
	return Config{
		BaseURL:       baseURL,
		APIKey:        "test-api-key",
		CollectorName: "test-collector",
		SelfAddresses: []string{"203.0.113.1:18189"},
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		Logf:          func(format string, args ...any) { /* silence in tests */ },
	}
}

func mustNewStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// TestFlushSplitsIntoMultipleBoundedBatches proves Fix 3: a flush whose combined pending
// buffer exceeds Config.FlushBatchSize is split into multiple requests, each bounded at (at
// most) FlushBatchSize combined records -- not sent as a single unbounded request, the
// previous (fixed) behavior. See flushOnce/splitBatch's own doc comments.
func TestFlushSplitsIntoMultipleBoundedBatches(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.FlushBatchSize = 2
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	// 5 confirmed nodes buffered, FlushBatchSize=2 -- must split into ceil(5/2) = 3 requests
	// (2, 2, 1), not one request carrying all 5.
	const total = 5
	for i := 0; i < total; i++ {
		addr := fmt.Sprintf("10.10.10.%d:1", i)
		if _, err := s.UpsertConfirmedNode(ctx, addr, []byte{byte(i)}, storage.DiscoverySourceP2P); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}

	if err := s.flushOnce(ctx); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	if got := captured.requestCount(); got != 3 {
		t.Fatalf("requestCount = %d, want 3 (ceil(%d/%d))", got, total, cfg.FlushBatchSize)
	}

	var seenAddrs []string
	sumApplied := 0
	for i, req := range captured.allRequests() {
		if len(req.ConfirmedNodes) > cfg.FlushBatchSize {
			t.Errorf("request #%d has %d confirmed_nodes, want <= %d (FlushBatchSize)", i, len(req.ConfirmedNodes), cfg.FlushBatchSize)
		}
		sumApplied += len(req.ConfirmedNodes)
		for _, cn := range req.ConfirmedNodes {
			seenAddrs = append(seenAddrs, cn.Address)
		}
	}
	if sumApplied != total {
		t.Errorf("sum of confirmed_nodes across all requests = %d, want %d", sumApplied, total)
	}
	for i := 0; i < total; i++ {
		want := fmt.Sprintf("10.10.10.%d:1", i)
		if i >= len(seenAddrs) || seenAddrs[i] != want {
			t.Errorf("seenAddrs[%d] = %q, want %q (order must be preserved across sub-batches)", i, safeIndex(seenAddrs, i), want)
		}
	}

	s.mu.Lock()
	pending := len(s.pendingConfirmed)
	s.mu.Unlock()
	if pending != 0 {
		t.Errorf("pendingConfirmed after a fully successful multi-batch flush = %d, want 0", pending)
	}
}

// TestFlushMultiBatchFailurePreservesRemainderInOrder proves the failure-handling half of
// Fix 3: if a sub-batch partway through a multi-batch flush fails, every not-yet-sent item
// (the failed sub-batch itself, plus everything still queued behind it) is restored to the
// pending buffer, in its original order, for retry -- exactly one sub-batch's worth of items
// (not the whole original backlog) was actually sent to the (failing) server.
func TestFlushMultiBatchFailurePreservesRemainderInOrder(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()
	captured.fail.Store(true)

	cfg := testConfig(srv.URL)
	cfg.FlushBatchSize = 2
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	const total = 5
	for i := 0; i < total; i++ {
		addr := fmt.Sprintf("10.20.30.%d:1", i)
		if _, err := s.UpsertConfirmedNode(ctx, addr, []byte{byte(i)}, storage.DiscoverySourceP2P); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}

	if err := s.flushOnce(ctx); err == nil {
		t.Fatal("expected flushOnce to fail")
	}

	// Only the FIRST sub-batch (<=FlushBatchSize items) was ever attempted -- flushOnce
	// stops at the first failure rather than trying every remaining sub-batch too.
	if got := captured.requestCount(); got != 1 {
		t.Fatalf("requestCount = %d, want 1 (flushOnce must stop retrying further sub-batches after the first failure)", got)
	}

	s.mu.Lock()
	pending := append([]pendingConfirmedNode{}, s.pendingConfirmed...)
	s.mu.Unlock()
	if len(pending) != total {
		t.Fatalf("pendingConfirmed after failure = %d, want %d (every unsent item must be restored)", len(pending), total)
	}
	for i, p := range pending {
		want := fmt.Sprintf("10.20.30.%d:1", i)
		if p.Address != want {
			t.Errorf("restored pendingConfirmed[%d].Address = %q, want %q (order must be preserved)", i, p.Address, want)
		}
	}
}

func safeIndex(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return "<out of range>"
	}
	return s[i]
}

func TestNewRequiresBaseURLAndAPIKey(t *testing.T) {
	if _, err := New(Config{APIKey: "k"}); err == nil {
		t.Error("expected error for missing BaseURL")
	}
	if _, err := New(Config{BaseURL: "http://example.com"}); err == nil {
		t.Error("expected error for missing APIKey")
	}
	if _, err := New(Config{BaseURL: "http://example.com", APIKey: "k"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpsertConfirmedNodeThenListAndGetNode(t *testing.T) {
	s := mustNewStore(t, testConfig("http://unused.invalid"))
	ctx := context.Background()

	n, err := s.UpsertConfirmedNode(ctx, "1.2.3.4:18189", []byte{0xaa, 0xbb}, storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("UpsertConfirmedNode: %v", err)
	}
	if len(n.PublicKey) == 0 {
		t.Fatalf("expected a public key to be set")
	}

	got, err := s.GetNode(ctx, n.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Address != "1.2.3.4:18189" {
		t.Errorf("address = %q, want %q", got.Address, "1.2.3.4:18189")
	}

	confirmed := true
	nodes, err := s.ListNodes(ctx, storage.NodeFilter{Confirmed: &confirmed})
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != n.ID {
		t.Fatalf("ListNodes(Confirmed=true) = %+v, want exactly [%s]", nodes, n.ID)
	}

	unconfirmed := false
	nodes2, err := s.ListNodes(ctx, storage.NodeFilter{Confirmed: &unconfirmed})
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes2) != 0 {
		t.Fatalf("ListNodes(Confirmed=false) = %+v, want empty", nodes2)
	}
}

func TestUpsertDiscoveredNodeMergesTagsAndDiscoverySourceLocally(t *testing.T) {
	s := mustNewStore(t, testConfig("http://unused.invalid"))
	ctx := context.Background()

	n1, err := s.UpsertDiscoveredNode(ctx, "5.6.7.8:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	if len(n1.PublicKey) != 0 {
		t.Errorf("expected unconfirmed node to have no public key")
	}

	n2, err := s.UpsertDiscoveredNode(ctx, "5.6.7.8:1", storage.DiscoverySourceRegistry, map[string]any{"owner": "alice"}, nil)
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if n2.ID != n1.ID {
		t.Fatalf("repeated upsert of the same address must return the same ID, got %s and %s", n1.ID, n2.ID)
	}
	if n2.DiscoverySource != storage.DiscoverySourceBoth {
		t.Errorf("discovery_source = %q, want %q after a differing second upsert", n2.DiscoverySource, storage.DiscoverySourceBoth)
	}
	if n2.Tags["owner"] != "alice" {
		t.Errorf("tags[owner] = %v, want %q", n2.Tags["owner"], "alice")
	}
}

func TestRecordHealthCheckUnknownNodeErrors(t *testing.T) {
	s := mustNewStore(t, testConfig("http://unused.invalid"))
	ctx := context.Background()

	err := s.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: uuid.New(), Reachable: true, ProbeSource: storage.ProbeSourceP2P})
	if err == nil {
		t.Fatal("expected an error for an unresolved node id")
	}
}

func TestRecordPeerEdgeObservationUnknownNodeErrors(t *testing.T) {
	s := mustNewStore(t, testConfig("http://unused.invalid"))
	ctx := context.Background()

	n, err := s.UpsertDiscoveredNode(ctx, "9.9.9.9:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := s.RecordPeerEdgeObservation(ctx, n.ID, uuid.New()); err == nil {
		t.Error("expected an error when to-node is unresolved")
	}
	if err := s.RecordPeerEdgeObservation(ctx, uuid.New(), n.ID); err == nil {
		t.Error("expected an error when from-node is unresolved")
	}
}

// capturingReportServer records every POST /internal/collectors/report body it receives and
// replies according to fail (controlled via an atomic flag so a single test can flip
// behavior between requests).
type capturingReportServer struct {
	mu       sync.Mutex
	requests []reportWireRequest
	fail     atomic.Bool
}

func newCapturingReportServer() (*httptest.Server, *capturingReportServer) {
	c := &capturingReportServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/collectors/report", func(w http.ResponseWriter, r *http.Request) {
		var req reportWireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.requests = append(c.requests, req)
		c.mu.Unlock()

		if c.fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(reportWireResponse{
			ConfirmedNodesApplied:  len(req.ConfirmedNodes),
			DiscoveredNodesApplied: len(req.DiscoveredNodes),
			HealthChecksApplied:    len(req.HealthChecks),
			PeerEdgesApplied:       len(req.PeerEdges),
			SelfIdentityTagged:     len(req.SelfIdentity),
		})
	})
	srv := httptest.NewServer(mux)
	return srv, c
}

func (c *capturingReportServer) requestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *capturingReportServer) lastRequest() reportWireRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests[len(c.requests)-1]
}

// allRequests returns a snapshot of every request captured so far, in receipt order.
func (c *capturingReportServer) allRequests() []reportWireRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]reportWireRequest{}, c.requests...)
}

func TestFlushSendsSelfIdentityEvenWithNothingElseBuffered(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()

	s := mustNewStore(t, testConfig(srv.URL))
	if err := s.flushOnce(context.Background()); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	if captured.requestCount() != 1 {
		t.Fatalf("requestCount = %d, want 1", captured.requestCount())
	}
	got := captured.lastRequest()
	if len(got.SelfIdentity) != 1 || got.SelfIdentity[0] != "203.0.113.1:18189" {
		t.Errorf("self_identity = %+v, want [203.0.113.1:18189]", got.SelfIdentity)
	}
}

func TestFlushSkippedWhenNothingToReportAndNoSelfIdentity(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.SelfAddresses = nil
	s := mustNewStore(t, cfg)

	if err := s.flushOnce(context.Background()); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}
	if captured.requestCount() != 0 {
		t.Fatalf("requestCount = %d, want 0 (nothing to report)", captured.requestCount())
	}
}

func TestFlushRetainsBufferOnFailure(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()
	captured.fail.Store(true)

	s := mustNewStore(t, testConfig(srv.URL))
	ctx := context.Background()

	if _, err := s.UpsertConfirmedNode(ctx, "1.1.1.1:1", []byte{0x01}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := s.flushOnce(ctx); err == nil {
		t.Fatal("expected flushOnce to fail")
	}

	s.mu.Lock()
	pending := len(s.pendingConfirmed)
	s.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pendingConfirmed after failed flush = %d, want 1 (buffered data must be retained)", pending)
	}

	// Now let the next flush succeed, and confirm the retained data is actually sent.
	captured.fail.Store(false)
	if err := s.flushOnce(ctx); err != nil {
		t.Fatalf("second flushOnce: %v", err)
	}
	if captured.requestCount() != 2 {
		t.Fatalf("requestCount = %d, want 2", captured.requestCount())
	}
	last := captured.lastRequest()
	if len(last.ConfirmedNodes) != 1 || last.ConfirmedNodes[0].Address != "1.1.1.1:1" {
		t.Errorf("retried request's confirmed_nodes = %+v, want the retained entry", last.ConfirmedNodes)
	}

	s.mu.Lock()
	pendingAfter := len(s.pendingConfirmed)
	s.mu.Unlock()
	if pendingAfter != 0 {
		t.Errorf("pendingConfirmed after successful retry = %d, want 0", pendingAfter)
	}
}

func TestSizeTriggeredFlushSignalsFlushTrigger(t *testing.T) {
	srv, _ := newCapturingReportServer()
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.FlushBatchSize = 2
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	if _, err := s.UpsertConfirmedNode(ctx, "2.2.2.2:1", []byte{0x02}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	select {
	case <-s.flushTrigger:
		t.Fatal("flushTrigger fired too early (only 1 of 2 batch-size records buffered)")
	default:
	}

	if _, err := s.UpsertConfirmedNode(ctx, "3.3.3.3:1", []byte{0x03}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	select {
	case <-s.flushTrigger:
	default:
		t.Fatal("expected flushTrigger to fire once the batch size threshold was reached")
	}
}

func TestRefreshCacheParsesSeedListAndPopulatesNodes(t *testing.T) {
	nodeID := uuid.New()
	mux := http.NewServeMux()
	mux.HandleFunc("/nodes/seed_list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(seedListWireResponse{
			Candidates: []seedListWireCandidate{
				{
					NodeID:    nodeID,
					PublicKey: "aabbcc",
					Addresses: []string{"198.51.100.1:18189", "abc123.onion:18189"},
				},
			},
			Since: "3h0m0s",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := mustNewStore(t, testConfig(srv.URL))
	ctx := context.Background()

	if err := s.refreshCache(ctx); err != nil {
		t.Fatalf("refreshCache: %v", err)
	}

	got, err := s.GetNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Address != "198.51.100.1:18189" {
		t.Errorf("address = %q, want %q", got.Address, "198.51.100.1:18189")
	}
	if len(got.PublicKey) == 0 {
		t.Errorf("expected a decoded public key")
	}

	addrs, err := s.ListNodeAddresses(ctx, nodeID)
	if err != nil {
		t.Fatalf("ListNodeAddresses: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("len(addresses) = %d, want 2", len(addrs))
	}

	confirmed := true
	hasHistory := true
	nodes, err := s.ListNodes(ctx, storage.NodeFilter{Confirmed: &confirmed, HasHealthChecks: &hasHistory})
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != nodeID {
		t.Fatalf("ListNodes(Confirmed,HasHealthChecks) = %+v, want exactly [%s]", nodes, nodeID)
	}

	// A cache-derived node's Owned status is always false (see refreshCache's doc comment:
	// the wire response carries no Tags at all).
	owned := true
	ownedNodes, err := s.ListNodes(ctx, storage.NodeFilter{Owned: &owned})
	if err != nil {
		t.Fatalf("ListNodes(Owned): %v", err)
	}
	if len(ownedNodes) != 0 {
		t.Fatalf("ListNodes(Owned=true) = %+v, want empty (cache carries no tags)", ownedNodes)
	}
}

// TestLocalUpsertThenCacheRefreshUpgradesToRealID asserts that an address this store first
// saw via a local UpsertDiscoveredNode call (getting a synthetic ID) later resolves to the
// REAL, central-authoritative ID once a seed_list refresh reveals it for the same address --
// the "soft transition" documented on resolveNodeIDLocked.
func TestLocalUpsertThenCacheRefreshUpgradesToRealID(t *testing.T) {
	const addr = "203.0.113.55:18189"
	realID := uuid.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/nodes/seed_list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(seedListWireResponse{
			Candidates: []seedListWireCandidate{
				{NodeID: realID, PublicKey: "aa", Addresses: []string{addr}},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := mustNewStore(t, testConfig(srv.URL))
	ctx := context.Background()

	synthetic, err := s.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	if synthetic.ID == realID {
		t.Fatalf("synthetic ID unexpectedly already equals the real ID -- test fixture collision")
	}

	if err := s.refreshCache(ctx); err != nil {
		t.Fatalf("refreshCache: %v", err)
	}

	upgraded, err := s.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("post-refresh upsert: %v", err)
	}
	if upgraded.ID != realID {
		t.Errorf("post-refresh upsert ID = %s, want the real ID %s", upgraded.ID, realID)
	}
}

// TestPingFailsWhenReportChannelStaleEvenIfHealthzOK proves Fix 1: Ping must reflect the
// report channel's own health, not just proxy the central GET /healthz call (which is an
// unconditional 200 with no backend check at all -- see internal/api/api.go's own doc
// comment on that route). A satellite whose last flush attempt failed, and whose last
// success (or, if none, first attempt) is further in the past than
// Config.ReportChannelUnhealthyThreshold, must fail Ping even though the central GET
// /healthz itself still returns 200.
func TestPingFailsWhenReportChannelStaleEvenIfHealthzOK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.ReportChannelUnhealthyThreshold = 10 * time.Millisecond
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	// Simulate a stale, never-successful report channel directly (rather than actually
	// waiting out a real flush failure/threshold cycle).
	s.mu.Lock()
	s.lastFlushAttempt = time.Now().Add(-1 * time.Hour)
	s.lastFlushErr = errRemoteStore("simulated failure")
	s.mu.Unlock()

	if err := s.Ping(ctx); err == nil {
		t.Error("Ping = nil, want an error (report channel has been failing well past the configured threshold)")
	}
}

// TestPingToleratesRecentReportFailureWithinGracePeriod proves Ping does NOT fail
// immediately on a single recent flush failure -- only once it's been failing for longer
// than Config.ReportChannelUnhealthyThreshold (a generous grace period, see
// DefaultReportChannelUnhealthyThreshold's own doc comment).
func TestPingToleratesRecentReportFailureWithinGracePeriod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.ReportChannelUnhealthyThreshold = time.Hour
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	s.mu.Lock()
	s.lastFlushAttempt = time.Now()
	s.lastFlushSuccess = time.Now().Add(-time.Minute)
	s.lastFlushErr = errRemoteStore("simulated transient failure")
	s.mu.Unlock()

	if err := s.Ping(ctx); err != nil {
		t.Errorf("Ping = %v, want nil (a single recent failure within the grace threshold must not fail Ping)", err)
	}
}

// TestPingUnaffectedByReportChannelBeforeFirstAttempt proves a freshly-constructed Store
// (no flush attempted yet) is judged purely on central-API reachability, never on
// report-channel staleness it hasn't had a chance to establish yet.
func TestPingUnaffectedByReportChannelBeforeFirstAttempt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.ReportChannelUnhealthyThreshold = time.Nanosecond
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Errorf("Ping = %v, want nil (no flush has been attempted yet)", err)
	}
}

// TestFlushUpdatesHealthAndMetricsState proves flushOnce actually records
// lastFlushAttempt/lastFlushSuccess/lastFlushErr and invokes Config.OnFlushResult (Fix 1/Fix
// 2's underlying bookkeeping), and that PendingRecordCount/LastSuccessfulFlushAt reflect it.
func TestFlushUpdatesHealthAndMetricsState(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()

	var onFlushResults []bool
	cfg := testConfig(srv.URL)
	cfg.OnFlushResult = func(success bool) { onFlushResults = append(onFlushResults, success) }
	s := mustNewStore(t, cfg)
	ctx := context.Background()

	if _, err := s.UpsertConfirmedNode(ctx, "6.6.6.6:1", []byte{0x06}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got := s.PendingRecordCount(); got != 1 {
		t.Fatalf("PendingRecordCount before flush = %d, want 1", got)
	}

	before := time.Now()
	if err := s.flushOnce(ctx); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	if len(onFlushResults) != 1 || !onFlushResults[0] {
		t.Fatalf("onFlushResults = %+v, want [true]", onFlushResults)
	}
	if got := s.PendingRecordCount(); got != 0 {
		t.Errorf("PendingRecordCount after successful flush = %d, want 0", got)
	}
	if last := s.LastSuccessfulFlushAt(); last.Before(before) {
		t.Errorf("LastSuccessfulFlushAt = %v, want a time at/after %v", last, before)
	}
	if captured.requestCount() != 1 {
		t.Fatalf("requestCount = %d, want 1", captured.requestCount())
	}

	// Now a failing flush.
	captured.fail.Store(true)
	if _, err := s.UpsertConfirmedNode(ctx, "7.7.7.7:1", []byte{0x07}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.flushOnce(ctx); err == nil {
		t.Fatal("expected flushOnce to fail")
	}
	if len(onFlushResults) != 2 || onFlushResults[1] {
		t.Fatalf("onFlushResults = %+v, want [true false]", onFlushResults)
	}
}

func TestPingReflectsCentralHealthz(t *testing.T) {
	mux := http.NewServeMux()
	var status atomic.Int32
	status.Store(http.StatusOK)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := mustNewStore(t, testConfig(srv.URL))
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Errorf("Ping (healthy) = %v, want nil", err)
	}

	status.Store(http.StatusServiceUnavailable)
	if err := s.Ping(ctx); err == nil {
		t.Error("Ping (unhealthy) = nil, want an error")
	}
}

func TestCloseFlushesBufferedDataAndRejectsFurtherWrites(t *testing.T) {
	srv, captured := newCapturingReportServer()
	defer srv.Close()

	s := mustNewStore(t, testConfig(srv.URL))
	ctx := context.Background()

	if _, err := s.UpsertConfirmedNode(ctx, "4.4.4.4:1", []byte{0x04}, storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if captured.requestCount() != 1 {
		t.Fatalf("requestCount after Close = %d, want 1 (final best-effort flush)", captured.requestCount())
	}

	if _, err := s.UpsertConfirmedNode(ctx, "5.5.5.5:1", []byte{0x05}, storage.DiscoverySourceP2P); err == nil {
		t.Error("expected a write after Close to fail")
	}

	// Close is idempotent.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestRunRefreshesCacheAndFlushesOnTickers(t *testing.T) {
	nodeID := uuid.New()
	seedListHits := &atomic.Int32{}

	var captured capturingReportServer
	mux := http.NewServeMux()
	mux.HandleFunc("/nodes/seed_list", func(w http.ResponseWriter, r *http.Request) {
		seedListHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(seedListWireResponse{
			Candidates: []seedListWireCandidate{{NodeID: nodeID, PublicKey: "aa", Addresses: []string{"9.9.9.9:1"}}},
		})
	})
	mux.HandleFunc("/internal/collectors/report", func(w http.ResponseWriter, r *http.Request) {
		var req reportWireRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		captured.mu.Lock()
		captured.requests = append(captured.requests, req)
		captured.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reportWireResponse{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.CacheRefreshInterval = 20 * time.Millisecond
	cfg.FlushInterval = 20 * time.Millisecond
	s := mustNewStore(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = s.Run(ctx)
		close(done)
	}()
	<-done

	if seedListHits.Load() < 2 {
		t.Errorf("seed_list hits = %d, want at least 2 (initial + at least one tick)", seedListHits.Load())
	}
	if captured.requestCount() < 1 {
		t.Errorf("report requests = %d, want at least 1 (self_identity is always sent)", captured.requestCount())
	}

	if _, err := s.GetNode(context.Background(), nodeID); err != nil {
		t.Errorf("expected the cache-derived node to be visible after Run: %v", err)
	}
}
