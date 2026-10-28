package remotestore

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// This file is an end-to-end integration test of this package's wire contract against a REAL
// internal/api server backed by a real Postgres storage.Store -- exactly the topology this
// package is built for (a remote collector satellite talking to the actual central system),
// as opposed to remotestore_test.go's httptest fakes that only assert this package's OWN
// request/response shapes match what it thinks the contract is. This is what actually proves
// internal/remotestore and internal/api/collector_report.go agree with each other, since
// nothing here imports the other's private wire types -- they are independently defined JSON
// tags on both ends (see flush.go/cache.go's doc comments) and this test is what would catch
// them drifting apart.

// centralTestDSN/acquireCentralTestDBLock/newTestCentralStore mirror the identical
// boilerplate already duplicated across internal/storage, internal/api, internal/collector,
// and cmd/netmap-p2p-responder's own test files -- see any of their doc comments for the full
// rationale (this sandbox's real Postgres 17 instance, TEST_DATABASE_URL override, a shared
// cross-package advisory lock since every one of those packages' tests truncates the same
// tables against the same database).
const centralDefaultTestDSN = "postgres://postgres@localhost:5433/netmap?sslmode=disable&host=/workspace/pg-embed/sockets"

func centralTestDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return centralDefaultTestDSN
}

func acquireCentralTestDBLock(t *testing.T, ctx context.Context, dsn string) func() {
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

func newTestCentralStore(t *testing.T) storage.Store {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dsn := centralTestDSN()
	t.Cleanup(acquireCentralTestDBLock(t, ctx, dsn))

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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE node_health, peer_edge_observations, node_addresses, pending_submissions, pending_wallet_submissions, nodes, geoip_cache CASCADE"); err != nil {
		pool.Close()
		t.Fatalf("truncate test tables: %v", err)
	}
	pool.Close()

	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestEndToEndReportFlowAgainstRealCentralAPI drives every write path (confirmed node,
// discovered node, health check, peer edge, self-identity tagging) through a real
// internal/api server backed by real Postgres, and asserts the resulting central storage
// state is exactly what's expected -- proving this package's flush wire format is actually
// accepted and correctly applied by the real handler, not just by its own httptest fakes.
func TestEndToEndReportFlowAgainstRealCentralAPI(t *testing.T) {
	central := newTestCentralStore(t)
	ctx := context.Background()

	const collectorKey = "sat1-test-key"
	const selfAddr = "203.0.113.200:18189"
	srv := httptest.NewServer(api.NewRouter(central, nil, nil, nil, true, adminauth.Credentials{}, map[string]api.CollectorConfig{"sat1": {APIKey: collectorKey, SelfAddresses: []string{selfAddr}}}, api.DefaultStatsCacheTTL, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL))
	defer srv.Close()

	const (
		confirmedAddr  = "198.51.100.200:18189"
		discoveredAddr = "198.51.100.201:18189"
	)
	pubkey := []byte{0xde, 0xad, 0xbe, 0xef}

	cfg := testConfig(srv.URL)
	cfg.APIKey = collectorKey
	cfg.SelfAddresses = []string{selfAddr}
	rs := mustNewStore(t, cfg)

	confirmedNode, err := rs.UpsertConfirmedNode(ctx, confirmedAddr, pubkey, storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("UpsertConfirmedNode: %v", err)
	}
	if err := rs.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: confirmedNode.ID, Reachable: true, ProbeSource: storage.ProbeSourceP2P}); err != nil {
		t.Fatalf("RecordHealthCheck: %v", err)
	}
	discoveredNode, err := rs.UpsertDiscoveredNode(ctx, discoveredAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("UpsertDiscoveredNode: %v", err)
	}
	if err := rs.RecordPeerEdgeObservation(ctx, confirmedNode.ID, discoveredNode.ID); err != nil {
		t.Fatalf("RecordPeerEdgeObservation: %v", err)
	}

	if err := rs.flushOnce(ctx); err != nil {
		t.Fatalf("flushOnce: %v", err)
	}

	centralNodes, err := central.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("central.ListNodes: %v", err)
	}
	byAddress := make(map[string]storage.Node, len(centralNodes))
	for _, n := range centralNodes {
		byAddress[n.Address] = n
	}

	confirmedCentral, ok := byAddress[confirmedAddr]
	if !ok {
		t.Fatalf("central store missing confirmed node %s", confirmedAddr)
	}
	if hex.EncodeToString(confirmedCentral.PublicKey) != hex.EncodeToString(pubkey) {
		t.Errorf("central confirmed node public key = %x, want %x", confirmedCentral.PublicKey, pubkey)
	}

	discoveredCentral, ok := byAddress[discoveredAddr]
	if !ok {
		t.Fatalf("central store missing discovered node %s", discoveredAddr)
	}
	if len(discoveredCentral.PublicKey) != 0 {
		t.Errorf("central discovered node unexpectedly has a public key: %x", discoveredCentral.PublicKey)
	}

	selfCentral, ok := byAddress[selfAddr]
	if !ok {
		t.Fatalf("central store missing self-identity node %s", selfAddr)
	}
	if role, _ := selfCentral.Tags["role"].(string); role != "collector" {
		t.Errorf("self-identity node tags[role] = %v, want %q", selfCentral.Tags["role"], "collector")
	}
	if role, _ := confirmedCentral.Tags["role"].(string); role == "collector" {
		t.Errorf("confirmed node must NOT be tagged role=collector")
	}

	history, err := central.GetNodeHistory(ctx, confirmedCentral.ID, 10)
	if err != nil {
		t.Fatalf("central.GetNodeHistory: %v", err)
	}
	if len(history) != 1 || !history[0].Reachable {
		t.Fatalf("central health history for confirmed node = %+v, want exactly one reachable entry", history)
	}

	edges, err := central.ListNodeEdges(ctx, confirmedCentral.ID, 10)
	if err != nil {
		t.Fatalf("central.ListNodeEdges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("central peer edges for confirmed node = %+v, want exactly 1", edges)
	}
}

// TestEndToEndSeedListCacheAgainstRealCentralAPI seeds the real central store directly with
// an opted-in, confirmed, recently-reachable node (bypassing the report flow entirely -- this
// exercises the READ side of the contract, GET /nodes/seed_list, independent of the report
// flow's own end-to-end test above), then asserts a remotestore.Store's refreshCache picks it
// up with the real, central-authoritative node ID and every known address.
func TestEndToEndSeedListCacheAgainstRealCentralAPI(t *testing.T) {
	central := newTestCentralStore(t)
	ctx := context.Background()

	srv := httptest.NewServer(api.NewRouter(central, nil, nil, nil, true, adminauth.Credentials{}, map[string]api.CollectorConfig{"sat1": {APIKey: "unused"}}, api.DefaultStatsCacheTTL, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL))
	defer srv.Close()

	const seedAddr = "192.0.2.77:18189"
	pubkey := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	seedNode, err := central.UpsertConfirmedNode(ctx, seedAddr, pubkey, storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("seed UpsertConfirmedNode: %v", err)
	}
	if err := central.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: seedNode.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
		t.Fatalf("seed RecordHealthCheck: %v", err)
	}

	rs := mustNewStore(t, testConfig(srv.URL))
	if err := rs.refreshCache(ctx); err != nil {
		t.Fatalf("refreshCache: %v", err)
	}

	got, err := rs.GetNode(ctx, seedNode.ID)
	if err != nil {
		t.Fatalf("GetNode(%s): %v", seedNode.ID, err)
	}
	if got.Address != seedAddr {
		t.Errorf("address = %q, want %q", got.Address, seedAddr)
	}
	if hex.EncodeToString(got.PublicKey) != hex.EncodeToString(pubkey) {
		t.Errorf("public key = %x, want %x", got.PublicKey, pubkey)
	}

	confirmed := true
	nodes, err := rs.ListNodes(ctx, storage.NodeFilter{Confirmed: &confirmed})
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != seedNode.ID {
		t.Fatalf("ListNodes(Confirmed=true) = %+v, want exactly [%s]", nodes, seedNode.ID)
	}
}
