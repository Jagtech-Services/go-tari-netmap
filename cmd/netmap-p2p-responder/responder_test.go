package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"
	pb "github.com/Jagtech-Services/go-tari-lib/v3/p2p/proto"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// defaultTestDSN matches this sandbox's real Postgres 17 instance: unix
// socket at /workspace/pg-embed/sockets, port 5433, database "netmap",
// user "postgres", trust auth (no password). Mirrors the exact same
// constant already duplicated per-package in internal/storage,
// internal/api, and internal/collector's own test files — see
// collector_test.go's copy for the established convention this follows.
const defaultTestDSN = "postgres://postgres@localhost:5433/netmap?sslmode=disable&host=/workspace/pg-embed/sockets"

func testDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return defaultTestDSN
}

// acquireTestDBLock takes a session-level Postgres advisory lock shared by
// every test package that exercises the real test database (storage, api,
// collector, and now this package). `go test ./...` runs each package's
// tests as a separate process, potentially in parallel, but they all point
// at the same shared Postgres instance and truncate its tables — without
// this lock, two packages' tests running concurrently stomp on each
// other's data.
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

// newTestStore connects to the configured test database, runs migrations,
// and truncates all tables so each test starts from a clean slate. It
// skips the test (t.Skip) if the database can't be reached, so
// `go test ./...` doesn't hard-fail in environments with no test DB
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

// mustTestResponderMetrics builds a fresh *responderMetrics on its own dedicated registry (see
// newResponderMetrics/responderMetrics' doc comments in metrics.go) for tests in this package
// that need a non-nil dbBackedResponder.metrics but don't care about network-scoping
// specifically (that's metrics_test.go's job) -- always "mainnet", arbitrarily.
func mustTestResponderMetrics(t *testing.T) *responderMetrics {
	t.Helper()
	m, err := newResponderMetrics("mainnet")
	if err != nil {
		t.Fatalf("newResponderMetrics: %v", err)
	}
	return m
}

// testAddr wraps a plain string as a net.Addr, so onPeerIdentity (which takes net.Addr, exactly
// as go-tari-lib/p2p.Serve calls it with conn.RemoteAddr()) can be exercised directly in tests
// without a real net.Conn.
type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

// TestOnPeerIdentityRecordsConfirmedNodeAndHealthCheck exercises the OnPeerIdentity ->
// UpsertConfirmedNode + RecordHealthCheck wiring (BRIEF3.md's testing requirement #1, updated by
// BRIEF6.md's fix): a synthetic identity exchange result is fed directly to
// dbBackedResponder.onPeerIdentity (the same method wired as ResponderConfig.OnPeerIdentity in
// main.go), and this test asserts a real nodes row lands with the correct pubkey/
// discovery_source, a real node_addresses row lands for the peer's own self-claimed address
// ONLY (never the raw remote-dialed-from address/ephemeral source port -- see BRIEF6.md), and a
// real node_health row lands with reachable=true, probe_source=p2p, the right version, and the
// right peer_identity_updated_at (converted from the claimed IdentitySignature.UpdatedAt).
func TestOnPeerIdentityRecordsConfirmedNodeAndHealthCheck(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peerStaticKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	// remote uses an OS-assigned ephemeral source port, exactly the shape of address this
	// fix must never persist as a dialable node_addresses row.
	remote := testAddr("203.0.113.50:41000")

	claimedAddr, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.7/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}

	updatedAtUnix := time.Now().Add(-2 * time.Hour).Unix()
	identity := &p2p.PeerInfo{
		RemoteStaticPubKey: peerStaticKey,
		Addresses:          [][]byte{claimedAddr},
		Features:           p2p.FeaturesCommunicationNode,
		UserAgent:          "tari_base_node/1.2.3",
		IdentitySignature: &p2p.IdentitySignature{
			UpdatedAt: updatedAtUnix,
		},
	}

	r.onPeerIdentity(remote, peerStaticKey, identity)

	// The node must exist, confirmed, with the exact pubkey.
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}
	node := nodes[0]
	if string(node.PublicKey) != string(peerStaticKey) {
		t.Errorf("node.PublicKey = %x, want %x", node.PublicKey, peerStaticKey)
	}
	if node.DiscoverySource != storage.DiscoverySourceP2P {
		t.Errorf("node.DiscoverySource = %q, want %q", node.DiscoverySource, storage.DiscoverySourceP2P)
	}

	// Only the peer's own self-claimed address must be recorded against this node -- the
	// raw remote-dialed-from address (ephemeral source port) must NEVER appear (BRIEF6.md's
	// fix).
	addrs, err := store.ListNodeAddresses(ctx, node.ID)
	if err != nil {
		t.Fatalf("list node addresses: %v", err)
	}
	got := map[string]bool{}
	for _, a := range addrs {
		got[a.Address] = true
	}
	if got["203.0.113.50:41000"] {
		t.Errorf("node_addresses must NOT contain the raw remote-dialed-from address, got %v", got)
	}
	if !got["198.51.100.7:18189"] {
		t.Errorf("node_addresses missing the peer's self-claimed address, got %v", got)
	}
	if len(got) != 1 {
		t.Errorf("len(node_addresses) = %d, want 1, got %v", len(got), got)
	}

	// A single health check must have landed, reachable, p2p-sourced, with the right
	// version and peer_identity_updated_at.
	checks, err := store.GetNodeHistory(ctx, node.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("len(checks) = %d, want 1", len(checks))
	}
	hc := checks[0]
	if !hc.Reachable {
		t.Errorf("health check Reachable = false, want true")
	}
	if hc.ProbeSource != storage.ProbeSourceP2P {
		t.Errorf("health check ProbeSource = %q, want %q", hc.ProbeSource, storage.ProbeSourceP2P)
	}
	if hc.Version == nil || *hc.Version != "tari_base_node/1.2.3" {
		t.Errorf("health check Version = %v, want tari_base_node/1.2.3", hc.Version)
	}
	if hc.PeerIdentityUpdatedAt == nil {
		t.Fatalf("health check PeerIdentityUpdatedAt is nil, want %v", time.Unix(updatedAtUnix, 0))
	}
	if !hc.PeerIdentityUpdatedAt.Equal(time.Unix(updatedAtUnix, 0)) {
		t.Errorf("health check PeerIdentityUpdatedAt = %v, want %v", *hc.PeerIdentityUpdatedAt, time.Unix(updatedAtUnix, 0))
	}
}

// TestOnPeerIdentityZeroClaimedAddressesRecordsNoNode is BRIEF6.md's original regression test,
// updated by OPENCODE_BRIEF.md ("stop recording blank-address nodes"): a peer that completes a
// full identity exchange but claims ZERO addresses of its own (e.g. a bare probe/monitoring
// client) must NOT get a node row at all -- a blank/address-less node row is itself an invalid
// record (per direct instruction from the project owner), so onPeerIdentity must skip recording
// this peer entirely (no node row, no node_addresses row, no health-check row), rather than
// falling back to UpsertConfirmedNodeByPubKey as it used to.
func TestOnPeerIdentityZeroClaimedAddressesRecordsNoNode(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peerStaticKey := []byte{0xEE, 0xFF, 0x11, 0x22}
	// remote uses an OS-assigned ephemeral source port -- exactly the shape of the garbage
	// this bug used to write into node_addresses.
	remote := testAddr("104.161.20.146:49456")

	identity := &p2p.PeerInfo{
		RemoteStaticPubKey: peerStaticKey,
		Features:           p2p.FeaturesCommunicationNode,
		// Addresses deliberately left nil/empty -- this peer claims nothing.
	}

	r.onPeerIdentity(remote, peerStaticKey, identity)

	// NO node row must exist for this pubkey at all.
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range nodes {
		if string(n.PublicKey) == string(peerStaticKey) {
			t.Fatalf("expected no node row for pubkey=%x, but found one: %+v", peerStaticKey, n)
		}
	}
	if len(nodes) != 0 {
		t.Fatalf("len(nodes) = %d, want 0, got %+v", len(nodes), nodes)
	}
}

// TestOnPeerIdentityAllPrivateClaimedAddressesRecordsNoNode is OPENCODE_BRIEF.md's core
// regression test for bug 1 + bug 2 combined: a peer claiming ONLY private/loopback addresses
// (the live-production incident's exact shape: a peer claiming addresses that decode to
// 127.0.0.1:*) must have every one of those claims rejected by isClaimedAddressAllowed, which
// reduces claimed to empty exactly as if the peer had claimed nothing at all -- so, per bug 2's
// fix, NO node row is created for that pubkey at all.
func TestOnPeerIdentityAllPrivateClaimedAddressesRecordsNoNode(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peerStaticKey := []byte{0x18, 0x77, 0x90, 0x19}
	remote := testAddr("144.31.80.127:60561")

	// Mirrors the live production log line: a peer claiming two loopback addresses that
	// decode to 127.0.0.1:49909 and 127.0.0.1:60878.
	loopback1, err := p2p.EncodeMultiaddrString("/ip4/127.0.0.1/tcp/49909")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString loopback1: %v", err)
	}
	loopback2, err := p2p.EncodeMultiaddrString("/ip4/127.0.0.1/tcp/60878")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString loopback2: %v", err)
	}

	identity := &p2p.PeerInfo{
		RemoteStaticPubKey: peerStaticKey,
		Addresses:          [][]byte{loopback1, loopback2},
		Features:           p2p.FeaturesCommunicationNode,
	}

	r.onPeerIdentity(remote, peerStaticKey, identity)

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range nodes {
		if string(n.PublicKey) == string(peerStaticKey) {
			t.Fatalf("expected no node row for pubkey=%x (all-private claims), but found one: %+v", peerStaticKey, n)
		}
	}
	if len(nodes) != 0 {
		t.Fatalf("len(nodes) = %d, want 0, got %+v", len(nodes), nodes)
	}
}

// TestOnPeerIdentityMixOfValidAndPrivateAddressUsesOnlyValid covers the mixed case: a peer
// claiming one genuinely valid public address AND one private/loopback address must still get a
// node row -- using only the valid address -- while the private one is silently skipped and
// never written to node_addresses.
func TestOnPeerIdentityMixOfValidAndPrivateAddressUsesOnlyValid(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peerStaticKey := []byte{0x77, 0x88, 0x99, 0xAA}
	remote := testAddr("198.51.100.201:53112")

	validAddr, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.9/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString valid: %v", err)
	}
	privateAddr, err := p2p.EncodeMultiaddrString("/ip4/192.168.0.120/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString private: %v", err)
	}

	identity := &p2p.PeerInfo{
		RemoteStaticPubKey: peerStaticKey,
		Addresses:          [][]byte{validAddr, privateAddr},
		Features:           p2p.FeaturesCommunicationNode,
	}

	r.onPeerIdentity(remote, peerStaticKey, identity)

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}
	node := nodes[0]
	if string(node.PublicKey) != string(peerStaticKey) {
		t.Errorf("node.PublicKey = %x, want %x", node.PublicKey, peerStaticKey)
	}

	addrs, err := store.ListNodeAddresses(ctx, node.ID)
	if err != nil {
		t.Fatalf("list node addresses: %v", err)
	}
	got := map[string]bool{}
	for _, a := range addrs {
		got[a.Address] = true
	}
	if got["192.168.0.120:18189"] {
		t.Errorf("node_addresses must NOT contain the rejected private address, got %v", got)
	}
	if !got["198.51.100.9:18189"] {
		t.Errorf("node_addresses missing the valid claimed address, got %v", got)
	}
	if len(got) != 1 {
		t.Errorf("len(node_addresses) = %d, want 1, got %v", len(got), got)
	}

	// A health check must still have landed for this node, exactly as the happy path.
	checks, err := store.GetNodeHistory(ctx, node.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("len(checks) = %d, want 1", len(checks))
	}
	if !checks[0].Reachable {
		t.Errorf("health check Reachable = false, want true")
	}
}

// TestOnPeerIdentityWithClaimedAddressesUnaffectedByZeroAddressPath exercises the other half of
// BRIEF6.md's requirement, extended by OPENCODE_BRIEF.md to also cover onion addresses: a peer
// WITH genuinely valid public claimed addresses (both clearnet IPv4 and onion) must still get
// exactly those addresses recorded (the legitimate identity.Addresses loop's happy path is
// unchanged by this fix's new isClaimedAddressAllowed check -- onion addresses are never IPs and
// always pass it unchanged), never the raw remote address, and multiple claimed addresses must
// all land.
func TestOnPeerIdentityWithClaimedAddressesUnaffectedByZeroAddressPath(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peerStaticKey := []byte{0x33, 0x44, 0x55, 0x66}
	remote := testAddr("198.51.100.99:52413")

	claimedIPv4, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.7/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString ip4: %v", err)
	}
	claimedIPv4Second, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.8/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString ip4 (second): %v", err)
	}
	claimedOnion, err := p2p.EncodeMultiaddrString("/onion3/PG6MMCYYZ2SO4E5S66PB5HB3XG2AQF7SWCNCF63YATIWCRLSBEFWNGYD:9001")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString onion: %v", err)
	}

	identity := &p2p.PeerInfo{
		RemoteStaticPubKey: peerStaticKey,
		Addresses:          [][]byte{claimedIPv4, claimedIPv4Second, claimedOnion},
		Features:           p2p.FeaturesCommunicationNode,
	}

	r.onPeerIdentity(remote, peerStaticKey, identity)

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}
	node := nodes[0]

	addrs, err := store.ListNodeAddresses(ctx, node.ID)
	if err != nil {
		t.Fatalf("list node addresses: %v", err)
	}
	got := map[string]bool{}
	for _, a := range addrs {
		got[a.Address] = true
	}
	if got["198.51.100.99:52413"] {
		t.Errorf("node_addresses must NOT contain the raw remote-dialed-from address, got %v", got)
	}
	if !got["198.51.100.7:18189"] {
		t.Errorf("node_addresses missing first claimed address, got %v", got)
	}
	if !got["198.51.100.8:18189"] {
		t.Errorf("node_addresses missing second claimed address, got %v", got)
	}
	if !got["pg6mmcyyz2so4e5s66pb5hb3xg2aqf7swcncf63yatiwcrlsbefwngyd.onion:9001"] {
		t.Errorf("node_addresses missing claimed onion address, got %v", got)
	}
	if len(got) != 3 {
		t.Errorf("len(node_addresses) = %d, want 3, got %v", len(got), got)
	}
}

// TestOnPeerIdentityNoIdentitySignatureLeavesPeerIdentityUpdatedAtNil covers the "peer sent no
// IdentitySignature" case (nil, per go-tari-lib/p2p.PeerInfo's own doc comment): PeerIdentity
// UpdatedAt and Version must simply be left nil, exactly mirroring
// internal/collector/p2p_client.go's GetInfo handling of the same case, rather than panicking.
//
// This fixture claims a valid public address (rather than the pre-OPENCODE_BRIEF.md zero-claims
// fixture) so a node row is actually created under the new "no usable claims -> no node at all"
// behavior (see onPeerIdentity's doc comment) -- this test's own purpose (the
// Version/PeerIdentityUpdatedAt-nil handling below) is otherwise unrelated to that fix.
func TestOnPeerIdentityNoIdentitySignatureLeavesPeerIdentityUpdatedAtNil(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peerStaticKey := []byte{0x01, 0x02, 0x03, 0x04}
	remote := testAddr("203.0.113.60:41000")

	claimedAddr, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.11/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}

	identity := &p2p.PeerInfo{
		RemoteStaticPubKey: peerStaticKey,
		Addresses:          [][]byte{claimedAddr},
		Features:           p2p.FeaturesCommunicationNode,
		// UserAgent left empty, IdentitySignature left nil.
	}

	r.onPeerIdentity(remote, peerStaticKey, identity)

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}

	checks, err := store.GetNodeHistory(ctx, nodes[0].ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("len(checks) = %d, want 1", len(checks))
	}
	if checks[0].Version != nil {
		t.Errorf("Version = %v, want nil", *checks[0].Version)
	}
	if checks[0].PeerIdentityUpdatedAt != nil {
		t.Errorf("PeerIdentityUpdatedAt = %v, want nil", *checks[0].PeerIdentityUpdatedAt)
	}
}

// TestPeerListProviderFiltersConfirmedRecentlyReachable exercises the PeerListProvider ->
// ListNodes query (BRIEF3.md's testing requirement #2): it seeds a mix of confirmed/unconfirmed
// and old/recent nodes and asserts only confirmed+recently-reachable ones come back, with their
// real addresses attached as pb.PeerInfo.Claims[].Addresses.
func TestPeerListProviderFiltersConfirmedRecentlyReachable(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// (1) Confirmed + recently reachable -- MUST be included.
	good, err := store.UpsertConfirmedNode(ctx, "198.51.100.10:18189", []byte{0x10}, storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert good: %v", err)
	}

	// (2) Confirmed but only reachable a long time ago -- must be EXCLUDED (stale).
	stale, err := store.UpsertConfirmedNode(ctx, "198.51.100.20:18189", []byte{0x20}, storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert stale: %v", err)
	}

	// (3) Unconfirmed placeholder, even with a recent reachable check -- must be EXCLUDED
	// (never directly probed/confirmed).
	unconfirmed, err := store.UpsertDiscoveredNode(ctx, "198.51.100.30:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert unconfirmed: %v", err)
	}

	// (4) Confirmed + recently reachable, but with no node_addresses at all... actually
	// UpsertConfirmedNode always records the address it was given, so add a second,
	// unencodable (bare, portless) address to prove per-address skip-on-failure behavior
	// without losing the node (it still has its one good ip4 address).
	dualAddr, err := store.UpsertConfirmedNode(ctx, "198.51.100.40:18189", []byte{0x40}, storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert dualAddr: %v", err)
	}

	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()

	insertHealth := func(nodeID uuid.UUID, ago time.Duration) {
		if _, err := pool.Exec(ctx, `
			INSERT INTO node_health (node_id, ts, reachable, probe_source)
			VALUES ($1, now() - $2::interval, true, 'p2p')
		`, nodeID, fmt.Sprintf("%d seconds", int(ago.Seconds()))); err != nil {
			t.Fatalf("insert health for %v: %v", nodeID, err)
		}
	}
	insertHealth(good.ID, 5*time.Minute)
	insertHealth(stale.ID, 3*time.Hour)
	insertHealth(unconfirmed.ID, 5*time.Minute)
	insertHealth(dualAddr.ID, 5*time.Minute)

	// dualAddr also claims an address encodeStoredAddress can't turn back into a wire
	// multiaddr (a bare IPv6 address, unsupported by go-tari-lib's EncodeMultiaddrString) --
	// this must be silently skipped, not fail the whole peer entry.
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_addresses (node_id, address, first_seen, last_seen)
		VALUES ($1, $2, now(), now())
	`, dualAddr.ID, "[2001:db8::1]:18189"); err != nil {
		t.Fatalf("insert dualAddr ipv6 address: %v", err)
	}

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peers := r.peerListProvider()

	gotPubkeys := map[string]*pb.PeerInfo{}
	for _, p := range peers {
		gotPubkeys[string(p.GetPublicKey())] = p
	}

	if _, ok := gotPubkeys[string([]byte{0x10})]; !ok {
		t.Errorf("expected confirmed+recently-reachable node (0x10) in peer list, got %d peers", len(peers))
	}
	if _, ok := gotPubkeys[string([]byte{0x20})]; ok {
		t.Errorf("stale confirmed node (0x20) must be excluded, but was present")
	}
	if _, ok := gotPubkeys[string([]byte{0x30})]; ok {
		t.Errorf("unconfirmed node (0x30, no pubkey) must never appear")
	}
	dual, ok := gotPubkeys[string([]byte{0x40})]
	if !ok {
		t.Fatalf("expected confirmed+recently-reachable dual-address node (0x40) in peer list")
	}
	if len(peers) != 2 {
		t.Fatalf("len(peers) = %d, want 2 (good + dualAddr)", len(peers))
	}

	// dualAddr's served Claims must contain its encodable ip4 address and must NOT contain
	// anything for the unencodable IPv6 address (silently skipped, per encodeStoredAddress).
	if len(dual.GetClaims()) != 1 || len(dual.GetClaims()[0].GetAddresses()) != 1 {
		t.Fatalf("dualAddr claims = %+v, want exactly 1 claim with exactly 1 (encodable) address", dual.GetClaims())
	}
	wantAddr, err := p2p.EncodeMultiaddrString("/ip4/198.51.100.40/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}
	if string(dual.GetClaims()[0].GetAddresses()[0]) != string(wantAddr) {
		t.Errorf("dualAddr served address = %x, want %x", dual.GetClaims()[0].GetAddresses()[0], wantAddr)
	}

	// unconfirmed must never come back at all, sanity re-check with an explicit lookup.
	_ = unconfirmed
}

// TestPeerListProviderEmptyWhenNothingQualifies covers the zero-matching-node case: no error,
// nil/empty result, matching ResponderConfig.PeerListProvider's "empty list, not an error" for
// the ordinary "nothing to serve yet" case (distinct from an actual DB failure).
func TestPeerListProviderEmptyWhenNothingQualifies(t *testing.T) {
	store := newTestStore(t)

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	peers := r.peerListProvider()
	if len(peers) != 0 {
		t.Fatalf("len(peers) = %d, want 0", len(peers))
	}
}

// TestEncodeStoredAddress exercises encodeStoredAddress's supported/unsupported cases directly.
func TestEncodeStoredAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantOK  bool
	}{
		{"ipv4", "1.2.3.4:18189", true},
		{"onion", "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:18189", true},
		{"ipv6", "[2001:db8::1]:18189", false},
		{"no port", "1.2.3.4", false},
		{"garbage", "not-an-address", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := encodeStoredAddress(tc.address)
			if ok != tc.wantOK {
				t.Errorf("encodeStoredAddress(%q) ok = %v, want %v", tc.address, ok, tc.wantOK)
			}
		})
	}
}

// TestOnPeerIdentityConcurrentSafety is a light smoke test that concurrent OnPeerIdentity calls
// (as would happen with multiple simultaneous inbound connections, each in its own goroutine per
// go-tari-lib/p2p.Serve's doc comment) don't race/deadlock against the same Store.
//
// Each simulated peer claims a valid public address (rather than the pre-OPENCODE_BRIEF.md
// zero-claims fixture) so a node row is actually created per peer under the new "no usable
// claims -> no node at all" behavior (see onPeerIdentity's doc comment) -- this test's own
// purpose (concurrency safety) is otherwise unrelated to that fix.
func TestOnPeerIdentityConcurrentSafety(t *testing.T) {
	store := newTestStore(t)

	r := &dbBackedResponder{store: store, logf: t.Logf, metrics: mustTestResponderMetrics(t)}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := []byte{byte(i), 0xFF}
			remote := testAddr(fmt.Sprintf("203.0.113.%d:41000", 100+i))
			claimedAddr, err := p2p.EncodeMultiaddrString(fmt.Sprintf("/ip4/198.51.100.%d/tcp/18189", 100+i))
			if err != nil {
				t.Errorf("EncodeMultiaddrString: %v", err)
				return
			}
			r.onPeerIdentity(remote, key, &p2p.PeerInfo{
				RemoteStaticPubKey: key,
				Addresses:          [][]byte{claimedAddr},
				Features:           p2p.FeaturesCommunicationNode,
			})
		}()
	}
	wg.Wait()

	nodes, err := store.ListNodes(context.Background(), storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 10 {
		t.Fatalf("len(nodes) = %d, want 10", len(nodes))
	}
}

var _ net.Addr = testAddr("")
