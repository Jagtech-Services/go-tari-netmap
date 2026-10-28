package collector

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// TestWalletHTTPClientGetInfoCallsOnlyGetTipInfo is this feature's probe-function test,
// exercised against a mock HTTP server (httptest.Server) shaped like minotari_node's real
// wallet-sync HTTP service. It proves two things at once, both hard safety requirements from
// this feature's brief:
//   - walletHTTPClient.GetInfo calls GET /get_tip_info and nothing else (the mock server
//     500s any other path, and fails the test if that path is ever hit).
//   - the response's metadata.best_block_height is correctly parsed into NodeInfo.Height/
//     ChainTipHeight, and Reachable is true on a 200 response.
func TestWalletHTTPClientGetInfoCallsOnlyGetTipInfo(t *testing.T) {
	var requestedPaths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		if r.URL.Path != "/get_tip_info" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s -- walletHTTPClient must call ONLY GET /get_tip_info", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{
				"best_block_height": 123456,
				"best_block_hash":   "deadbeef",
			},
			"is_synced": true,
		})
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()

	client := NewWalletHTTPClient()
	info, err := client.GetInfo(context.Background(), addr)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !info.Reachable {
		t.Error("Reachable = false, want true")
	}
	if info.Height == nil || *info.Height != 123456 {
		t.Errorf("Height = %v, want 123456", info.Height)
	}
	if info.ChainTipHeight == nil || *info.ChainTipHeight != 123456 {
		t.Errorf("ChainTipHeight = %v, want 123456", info.ChainTipHeight)
	}

	if len(requestedPaths) != 1 || requestedPaths[0] != "/get_tip_info" {
		t.Fatalf("requestedPaths = %v, want exactly [\"/get_tip_info\"]", requestedPaths)
	}
}

// TestWalletHTTPClientGetInfoUnreachable verifies a connection failure (nothing listening)
// surfaces as an error, not a false "reachable" result.
func TestWalletHTTPClientGetInfoUnreachable(t *testing.T) {
	client := NewWalletHTTPClient()
	// Port 1 is reserved and essentially guaranteed to have nothing listening.
	_, err := client.GetInfo(context.Background(), "127.0.0.1:1")
	if err == nil {
		t.Fatal("GetInfo against an unreachable address: want an error, got nil")
	}
}

// TestWalletHTTPClientGetInfoNonOKStatus verifies a non-200 response is treated as an error,
// not silently parsed as success.
func TestWalletHTTPClientGetInfoNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := NewWalletHTTPClient()
	_, err := client.GetInfo(context.Background(), srv.Listener.Addr().String())
	if err == nil {
		t.Fatal("GetInfo against a 404 response: want an error, got nil")
	}
}

// TestPollWalletHTTPOnceSkipsWithoutWalletHTTPPort verifies the "no attempt to make" skip
// case (mirroring ErrGRPCAddressUnknown's role for the gRPC transport): a node with a nil
// WalletHTTPPort must never be probed, and no health-check row is recorded for it -- see
// storage.Node.WalletHTTPPort's hard safety rule.
func TestPollWalletHTTPOnceSkipsWithoutWalletHTTPPort(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "1.2.3.4:18189", storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	client := NewWalletHTTPClient()
	success, skip, err := pollWalletHTTPOnce(ctx, client, store, node)
	if err != nil {
		t.Fatalf("pollWalletHTTPOnce: %v", err)
	}
	if !skip {
		t.Error("skip = false, want true (node.WalletHTTPPort is nil)")
	}
	if success {
		t.Error("success = true, want false")
	}

	history, err := store.GetNodeHistory(ctx, node.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("history = %+v, want empty -- a skipped probe must not record a row", history)
	}
}

// TestPollWalletHTTPOnceRecordsSuccessAgainstNodeHost verifies the full happy path: given a
// node with a non-nil WalletHTTPPort, pollWalletHTTPOnce probes the node's OWN host (never a
// different one -- see walletHTTPTarget's doc comment) paired with that port, and records a
// reachable=true, probe_source=wallet_http row with the parsed height.
func TestPollWalletHTTPOnceRecordsSuccessAgainstNodeHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata":  map[string]any{"best_block_height": 42},
			"is_synced": true,
		})
	}))
	defer srv.Close()

	host, port, err := splitTestServerAddr(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server addr: %v", err)
	}

	store := newTestStore(t)
	ctx := context.Background()

	// The node's OWN address's host must match the mock server's host for this test to
	// prove walletHTTPTarget pairs WalletHTTPPort with the node's own address -- using
	// the real listener's host (typically 127.0.0.1) for both.
	nodeAddr := host + ":18189"
	node, err := store.UpsertDiscoveredNode(ctx, nodeAddr, storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert node: %v", err)
	}
	if err := store.SetNodeWalletHTTPPort(ctx, node.ID, &port); err != nil {
		t.Fatalf("set wallet_http_port: %v", err)
	}
	node.WalletHTTPPort = &port

	client := NewWalletHTTPClient()
	success, skip, err := pollWalletHTTPOnce(ctx, client, store, node)
	if err != nil {
		t.Fatalf("pollWalletHTTPOnce: %v", err)
	}
	if skip {
		t.Fatal("skip = true, want false")
	}
	if !success {
		t.Fatal("success = false, want true")
	}

	history, err := store.GetNodeHistory(ctx, node.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("history = %+v, want exactly one row", history)
	}
	h := history[0]
	if h.ProbeSource != storage.ProbeSourceWalletHTTP {
		t.Errorf("ProbeSource = %q, want %q", h.ProbeSource, storage.ProbeSourceWalletHTTP)
	}
	if !h.Reachable {
		t.Error("Reachable = false, want true")
	}
	if h.Height == nil || *h.Height != 42 {
		t.Errorf("Height = %v, want 42", h.Height)
	}
}

// splitTestServerAddr splits an httptest.Server listener address ("host:port") into its host
// and integer port, for building a node address that shares the mock server's host.
func splitTestServerAddr(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// TestPollGenericConfirmedNeverDialsWalletHTTPWhenDisabled is this feature's mainnet-only
// gating test at the SCHEDULED POLL LOOP level (see storage.Node.WalletHTTPPort's doc
// comment and this feature's dispatch brief's "the poll loop must never dial
// wallet_http_port for any node" requirement): a Collector with WalletHTTPEnabled == false
// (the zero value/default) must never call this transport for ANY node, even one whose
// WalletHTTPPort is already non-nil -- proving the flag really does gate the dial itself,
// not merely happen to correlate with some other skip condition, this same node/mock server
// IS successfully probed once a second Collector instance (independent nextPoll bookkeeping,
// same underlying storage.Store) is built with WalletHTTPEnabled: true.
func TestPollGenericConfirmedNeverDialsWalletHTTPWhenDisabled(t *testing.T) {
	var dialed int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&dialed, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata":  map[string]any{"best_block_height": 7},
			"is_synced": true,
		})
	}))
	defer srv.Close()

	host, port, err := splitTestServerAddr(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server addr: %v", err)
	}

	store := newTestStore(t)
	ctx := context.Background()

	nodeAddr := host + ":18189"
	pubKey := []byte("wallet-http-disabled-gate-test-pubkey")
	node, err := store.UpsertConfirmedNode(ctx, nodeAddr, pubKey, storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("upsert confirmed node: %v", err)
	}
	if err := store.SetNodeWalletHTTPPort(ctx, node.ID, &port); err != nil {
		t.Fatalf("set wallet_http_port: %v", err)
	}

	client := NewWalletHTTPClient()

	// First: WalletHTTPEnabled left at its zero value (false) -- the poll must complete
	// without ever dialing the mock server at all.
	disabled := New(Config{})
	disabled.Storage = store
	disabled.WalletHTTPClient = client
	if err := disabled.PollGenericConfirmed(ctx); err != nil {
		t.Fatalf("PollGenericConfirmed (disabled): %v", err)
	}
	if atomic.LoadInt32(&dialed) != 0 {
		t.Fatalf("dialed = %d, want 0 -- WalletHTTPEnabled=false must prevent ANY dial of this transport", dialed)
	}
	history, err := store.GetNodeHistory(ctx, node.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("history = %+v, want empty -- a gated-off transport must not record a row either", history)
	}

	// Second: a FRESH Collector instance (independent nextPoll bookkeeping) with
	// WalletHTTPEnabled: true against the SAME store/node proves the mock server (and this
	// test's fixture) genuinely would have been reachable -- the zero dial count above is
	// really the flag's effect, not a fixture/wiring mistake.
	enabled := New(Config{})
	enabled.Storage = store
	enabled.WalletHTTPClient = client
	enabled.WalletHTTPEnabled = true
	if err := enabled.PollGenericConfirmed(ctx); err != nil {
		t.Fatalf("PollGenericConfirmed (enabled): %v", err)
	}
	if atomic.LoadInt32(&dialed) != 1 {
		t.Fatalf("dialed = %d, want 1 -- WalletHTTPEnabled=true must actually dial this transport", dialed)
	}
	history, err = store.GetNodeHistory(ctx, node.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(history) != 1 || history[0].ProbeSource != storage.ProbeSourceWalletHTTP {
		t.Fatalf("history = %+v, want exactly one probe_source=wallet_http row", history)
	}
}
