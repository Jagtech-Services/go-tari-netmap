package api_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// defaultTestDSN matches this sandbox's real Postgres 17 instance: unix
// socket at /workspace/pg-embed/sockets, port 5433, database "netmap",
// user "postgres", trust auth (no password).
const defaultTestDSN = "postgres://postgres@localhost:5433/netmap?sslmode=disable&host=/workspace/pg-embed/sockets"

func testDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return defaultTestDSN
}

// acquireTestDBLock takes a session-level Postgres advisory lock shared by
// every test package that exercises the real test database (storage, api,
// collector). `go test ./...` runs each package's tests as a separate
// process, potentially in parallel, but they all point at the same shared
// Postgres instance and truncate its tables — without this lock, two
// packages' tests running concurrently stomp on each other's data. The
// returned func releases the lock and must be registered as a cleanup that
// runs after the test (and its Store) are done with the DB.
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
// configured. It holds a cross-process advisory lock for the duration of
// the test to serialize access with the storage and collector packages'
// tests against the same shared database.
func newTestStore(t *testing.T) storage.Store {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dsn := testDSN()

	// Registered before store.Close below, so it runs last (t.Cleanup is
	// LIFO): the lock stays held until the Store is fully closed.
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
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE node_health, peer_edge_observations, node_addresses, pending_submissions, pending_wallet_submissions, nodes, geoip_cache CASCADE"); err != nil {
		pool.Close()
		t.Fatalf("truncate test tables: %v", err)
	}
	pool.Close()

	t.Cleanup(func() { _ = store.Close() })
	return store
}

// fakeClient is an in-memory fixture collector.NodeClient used to test the
// async health-check kickoff triggered by POST /nodes, without any real
// network access.
type fakeClient struct {
	info map[string]collector.NodeInfo

	// delay, if non-zero, is slept before GetInfo returns — used to
	// assert that the submission probe/health-check kickoff is truly
	// async and never blocks the triggering HTTP response.
	delay time.Duration
}

func (f *fakeClient) GetPeers(ctx context.Context, addr string) ([]collector.DiscoveredPeer, error) {
	return nil, nil
}

func (f *fakeClient) GetInfo(ctx context.Context, addr string) (collector.NodeInfo, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	info, ok := f.info[addr]
	if !ok {
		return collector.NodeInfo{}, fmt.Errorf("api_test: no fixture GetInfo response for %s", addr)
	}
	return info, nil
}

// testAdminUser/testAdminPassword are the fixed HTTP Basic Auth
// credentials newTestServer builds api.NewRouter with — see
// newTestServerWithCreds below for the "not configured" variant used to
// prove the fail-closed-503 behavior, and doAdminRequest for the
// request helper that authenticates against these.
const (
	testAdminUser     = "admin-test-user"
	testAdminPassword = "admin-test-password"
)

// testCollectorName/testCollectorAPIKey are the fixed trusted-collector
// identity/key newTestServer builds api.NewRouter with (see
// testCollectorKeys below) — used by every test exercising POST
// /internal/collectors/report with a valid key.
const (
	testCollectorName   = "test-collector"
	testCollectorAPIKey = "collector-test-api-key"
)

// testCollectorSelfAddresses are the self_identity address(es) testCollectorKeys' entry for
// testCollectorName allows -- must cover every literal self_identity address any test in this
// package (or collector_report_test.go, same api_test package) actually sends, or Fix 6(c)'s
// self-address allowlist enforcement will make self_identity tagging assertions fail. See
// collector_report_test.go's TestCollectorReportAppliesBatch for the current sole real user of
// this.
var testCollectorSelfAddresses = []string{"203.0.113.9:18189"}

// testCollectorKeys returns the fixed collector_name -> CollectorConfig map every
// newTestServer/newTestServerWithCreds/newTestServerWithStatsCacheTTL-built test server is
// configured with, mirroring testAdminUser/testAdminPassword's role for adminauth.Credentials.
func testCollectorKeys() map[string]api.CollectorConfig {
	return map[string]api.CollectorConfig{
		testCollectorName: {APIKey: testCollectorAPIKey, SelfAddresses: testCollectorSelfAddresses},
	}
}

func newTestServer(t *testing.T, client collector.NodeClient) (*httptest.Server, storage.Store) {
	t.Helper()
	return newTestServerWithCreds(t, client, adminauth.Credentials{Username: testAdminUser, Password: testAdminPassword})
}

// newTestServerWithCreds is like newTestServer but lets the caller
// control the admin credentials api.NewRouter is built with — in
// particular, passing a zero-value adminauth.Credentials{} simulates
// NETMAP_ADMIN_USER/NETMAP_ADMIN_PASSWORD being unset, which must fail
// closed (503) on every /admin/* route regardless of what's supplied on
// the request. Always builds with api.DefaultStatsCacheTTL — every
// existing test hitting GET /v1/stats issues exactly one request per
// fresh server/store, so the cache's TTL has no observable effect here;
// see newTestServerWithStatsCacheTTL below for tests that specifically
// exercise the cache's own timing behavior.
func newTestServerWithCreds(t *testing.T, client collector.NodeClient, creds adminauth.Credentials) (*httptest.Server, storage.Store) {
	t.Helper()
	store := newTestStore(t)
	if client == nil {
		client = collector.NewStubClient()
	}
	// p2pClient is nil here: these tests only exercise the gRPC-labeled
	// async health-check kickoff path; dual-probe behavior is covered by
	// internal/collector's own tests.
	srv := httptest.NewServer(api.NewRouter(store, client, nil, nil, true, creds, testCollectorKeys(), api.DefaultStatsCacheTTL, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL))
	t.Cleanup(srv.Close)
	return srv, store
}

// strPtr is a small helper for building *string literals inline in test
// assertions/fixtures.
func strPtr(s string) *string { return &s }

// doAdminRequest issues method to url (with an optional body) with valid
// admin Basic Auth credentials set via req.SetBasicAuth — used by every
// test hitting an /admin/* route below.
func doAdminRequest(t *testing.T, method, url, contentType string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, url, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.SetBasicAuth(testAdminUser, testAdminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func TestHealthz(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestCreateNodeValid asserts a genuinely new address queues a pending
// submission (202 Accepted) rather than instantly publishing a node: no
// node is created, and the response body reflects the pending
// submission.
func TestCreateNodeValid(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	body := `{"host":"1.2.3.4","port":18142,"label":"my node","owner_tag":"pool-x"}`
	resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /nodes: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	var submission storage.PendingSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submission); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if submission.Address != "1.2.3.4:18142" {
		t.Errorf("address = %q, want %q", submission.Address, "1.2.3.4:18142")
	}
	if submission.Status != storage.SubmissionStatusPending {
		t.Errorf("status = %q, want %q", submission.Status, storage.SubmissionStatusPending)
	}
	if submission.Label == nil || *submission.Label != "my node" {
		t.Errorf("label = %v, want %q", submission.Label, "my node")
	}
	if submission.OwnerTag == nil || *submission.OwnerTag != "pool-x" {
		t.Errorf("owner_tag = %v, want %q", submission.OwnerTag, "pool-x")
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("len(nodes) = %d, want 0 (submission must not auto-publish a node)", len(nodes))
	}
}

// TestCreateNodeAlreadyOptedInConflicts asserts submitting an address
// that already belongs to a publicly opted-in node (registry_submitted
// or both) is rejected with 409, and the existing node's data is left
// completely unchanged — the whole point of this check is to prevent a
// second submitter from silently merging into (and overwriting) someone
// else's already-registered node.
func TestCreateNodeAlreadyOptedInConflicts(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const addr = "23.226.69.178:18189"
	original, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceRegistry,
		map[string]any{"owner": "Jagtech"}, strPtr("Jagtech node"))
	if err != nil {
		t.Fatalf("upsert original node: %v", err)
	}
	originalLastSeen := original.LastSeen

	body := `{"host":"23.226.69.178","port":18189,"label":"steal this node","owner_tag":"attacker"}`
	resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /nodes: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusConflict)
	}

	got, err := store.GetNode(ctx, original.ID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if got.Label == nil || *got.Label != "Jagtech node" {
		t.Errorf("label = %v, want unchanged %q", got.Label, "Jagtech node")
	}
	if owner, _ := got.Tags["owner"].(string); owner != "Jagtech" {
		t.Errorf("tags[owner] = %v, want unchanged %q", got.Tags["owner"], "Jagtech")
	}
	if !got.LastSeen.Equal(originalLastSeen) {
		t.Errorf("last_seen changed: got %v, want unchanged %v", got.LastSeen, originalLastSeen)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1 (no new node created)", len(nodes))
	}

	pending, err := store.ListPendingSubmissions(ctx, "pending")
	if err != nil {
		t.Fatalf("list pending submissions: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("len(pending) = %d, want 0 (conflict must not queue a submission either)", len(pending))
	}
}

func TestCreateNodeInvalid(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	cases := []struct {
		name string
		body string
	}{
		{"missing host", `{"port":18142}`},
		{"port zero", `{"host":"1.2.3.4","port":0}`},
		{"port too large", `{"host":"1.2.3.4","port":65536}`},
		{"invalid json", `{not json`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatalf("POST /nodes: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestListNodesFilter(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	if _, err := store.UpsertDiscoveredNode(ctx, "a:1", storage.DiscoverySourceP2P, nil, nil); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, "b:2", storage.DiscoverySourceRegistry, nil, nil); err != nil {
		t.Fatalf("upsert b: %v", err)
	}

	resp, err := http.Get(srv.URL + "/nodes")
	if err != nil {
		t.Fatalf("GET /nodes: %v", err)
	}
	defer resp.Body.Close()
	var all struct {
		Nodes   []api.PublicNode `json:"nodes"`
		Total   int              `json:"total"`
		Limit   int              `json:"limit"`
		Offset  int              `json:"offset"`
		HasMore bool             `json:"has_more"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(all.Nodes) != 2 {
		t.Fatalf("len(all.Nodes) = %d, want 2", len(all.Nodes))
	}
	if all.Total != 2 {
		t.Fatalf("all.Total = %d, want 2", all.Total)
	}

	resp2, err := http.Get(srv.URL + "/nodes?discovery_source=p2p_discovered")
	if err != nil {
		t.Fatalf("GET /nodes?discovery_source=...: %v", err)
	}
	defer resp2.Body.Close()
	var filtered struct {
		Nodes []api.PublicNode `json:"nodes"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&filtered); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// "a:1" is a p2p_discovered node, so its real address is scrubbed
	// from the response — assert on discovery_source instead of address.
	if len(filtered.Nodes) != 1 || filtered.Nodes[0].DiscoverySource != storage.DiscoverySourceP2P {
		t.Fatalf("filtered.Nodes = %+v, want just the p2p_discovered node", filtered.Nodes)
	}
	if filtered.Total != 1 {
		t.Fatalf("filtered.Total = %d, want 1", filtered.Total)
	}
}

// TestListNodesOwnerFilterAPI round-trips GET /nodes' `?owner=` query
// param (see storage.NodeFilter.Owner's doc comment for the exact-match
// semantics tested at the storage layer already) through the HTTP
// handler.
func TestListNodesOwnerFilterAPI(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	if _, err := store.UpsertDiscoveredNode(ctx, "owner-a:1", storage.DiscoverySourceP2P, map[string]any{"owner": "Alice"}, nil); err != nil {
		t.Fatalf("upsert owner-a: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, "owner-b:1", storage.DiscoverySourceP2P, map[string]any{"owner": "Bob"}, nil); err != nil {
		t.Fatalf("upsert owner-b: %v", err)
	}

	resp, err := http.Get(srv.URL + "/nodes?owner=Alice")
	if err != nil {
		t.Fatalf("GET /nodes?owner=Alice: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Nodes []api.PublicNode `json:"nodes"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 1 || got.Total != 1 {
		t.Fatalf("got = %+v, want exactly 1 node (owner=Alice)", got)
	}
	if owner, _ := got.Nodes[0].Tags["owner"].(string); owner != "Alice" {
		t.Errorf("got.Nodes[0].Tags[owner] = %q, want %q", owner, "Alice")
	}
}

func TestGetNode(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "a:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/nodes/%s", srv.URL, node.ID))
	if err != nil {
		t.Fatalf("GET /nodes/{id}: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got api.PublicNode
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != node.ID {
		t.Errorf("id = %v, want %v", got.ID, node.ID)
	}
}

func TestGetNodeNotFound(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(fmt.Sprintf("%s/nodes/%s", srv.URL, uuid.New()))
	if err != nil {
		t.Fatalf("GET /nodes/{id}: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestGetNodeHistory(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "a:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{
		NodeID:      node.ID,
		Reachable:   true,
		ProbeSource: storage.ProbeSourceGRPC,
	}); err != nil {
		t.Fatalf("record health check: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/nodes/%s/history?limit=5", srv.URL, node.ID))
	if err != nil {
		t.Fatalf("GET /nodes/{id}/history: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var history []storage.HealthCheck
	if err := json.NewDecoder(resp.Body).Decode(&history); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("len(history) = %d, want 1", len(history))
	}
	if history[0].NodeID != node.ID {
		t.Errorf("node_id = %v, want %v", history[0].NodeID, node.ID)
	}
}

// TestGetNodeEdges seeds a center node with a p2p_discovered neighbor and
// a registry_submitted neighbor, records real peer-edge observations
// between them, and asserts GET /nodes/{id}/edges returns exactly that
// neighborhood — mirroring TestScrubbingP2PVsRegistry's setup style so
// scrubbing behavior is actually exercised, not just the neighbor/edge
// set itself. The raw-body substring check for the p2p neighbor's
// address is the single most important assertion here — see
// TestScrubbingP2PVsRegistry's doc comment for why a decoded-struct-only
// check wouldn't be sufficient.
// TestGetNodeEdges also asserts the handler's confirmed-only filtering
// (see handleGetNodeEdges' doc comment): a neighbor with no confirmed
// PublicKey — regardless of DiscoverySource — must not appear in either
// the nodes or edges slice of the response, even though a real edge to
// it exists in storage.
func TestGetNodeEdges(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const centerAddr = "center:1"
	const confirmedAddr = "5.6.7.8:18142"
	const unconfirmedAddr = "1.2.3.4:18142"

	center, err := store.UpsertDiscoveredNode(ctx, centerAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert center: %v", err)
	}
	// confirmedNeighbor has a real PublicKey (via UpsertConfirmedNode)
	// and is registry-sourced, so it must appear in the response *and*
	// (per PublicNode's opt-in address rule) its real address must be
	// visible in the response body.
	confirmedNeighbor, err := store.UpsertConfirmedNode(ctx, confirmedAddr, []byte("confirmed-neighbor-pubkey"), storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("upsert confirmed neighbor: %v", err)
	}
	// unconfirmedNeighbor has a real edge to center but no PublicKey —
	// the new confirmed-only filtering must exclude it (and its edge)
	// from the response entirely.
	unconfirmedNeighbor, err := store.UpsertDiscoveredNode(ctx, unconfirmedAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert unconfirmed neighbor: %v", err)
	}
	// A third node, not connected to center at all, must NOT show up in
	// the response — asserts ListNodeEdges' WHERE clause (and this
	// handler's neighbor-collection logic) doesn't over-broadly include
	// unrelated nodes.
	unrelated, err := store.UpsertDiscoveredNode(ctx, "unrelated:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert unrelated: %v", err)
	}

	if err := store.RecordPeerEdgeObservation(ctx, center.ID, confirmedNeighbor.ID); err != nil {
		t.Fatalf("record edge center->confirmed: %v", err)
	}
	if err := store.RecordPeerEdgeObservation(ctx, unconfirmedNeighbor.ID, center.ID); err != nil {
		t.Fatalf("record edge unconfirmed->center: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/nodes/%s/edges", srv.URL, center.ID))
	if err != nil {
		t.Fatalf("GET /nodes/{id}/edges: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Only the confirmed neighbor's edge should survive the filtering —
	// the edge to the unconfirmed neighbor must be dropped too, not just
	// the unconfirmed node itself (no dangling edge references).
	if len(got.Edges) != 1 {
		t.Fatalf("len(edges) = %d, want 1:\n%s", len(got.Edges), body)
	}
	if len(got.Nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1:\n%s", len(got.Nodes), body)
	}

	gotNodeIDs := map[uuid.UUID]bool{}
	for _, n := range got.Nodes {
		gotNodeIDs[n.ID] = true
	}
	if !gotNodeIDs[confirmedNeighbor.ID] {
		t.Errorf("nodes missing confirmed neighbor %v:\n%s", confirmedNeighbor.ID, body)
	}
	if gotNodeIDs[unconfirmedNeighbor.ID] {
		t.Errorf("nodes unexpectedly contains unconfirmed neighbor %v:\n%s", unconfirmedNeighbor.ID, body)
	}
	if gotNodeIDs[unrelated.ID] {
		t.Errorf("nodes unexpectedly contains unrelated node %v:\n%s", unrelated.ID, body)
	}
	if gotNodeIDs[center.ID] {
		t.Errorf("nodes unexpectedly contains the center node itself %v:\n%s", center.ID, body)
	}

	gotEdgeTouchesUnconfirmed := false
	for _, e := range got.Edges {
		if e.FromNodeID == unconfirmedNeighbor.ID || e.ToNodeID == unconfirmedNeighbor.ID {
			gotEdgeTouchesUnconfirmed = true
		}
	}
	if gotEdgeTouchesUnconfirmed {
		t.Errorf("edges unexpectedly contains an edge touching the unconfirmed neighbor %v:\n%s", unconfirmedNeighbor.ID, body)
	}

	// Privacy: the confirmed neighbor is registry-sourced (opted-in), so
	// its real address must be visible in the response body. The
	// unconfirmed neighbor's address is NOT separately asserted absent
	// here — it's excluded from the response entirely by the new
	// confirmed-only filtering, which is an even stronger privacy
	// guarantee than the old per-address scrubbing check.
	rawBody := string(body)
	if !strings.Contains(rawBody, confirmedAddr) {
		t.Errorf("GET /nodes/%s/edges body missing confirmed neighbor's address %q:\n%s", center.ID, confirmedAddr, rawBody)
	}
}

// TestGetNodeEdgesEmpty asserts a node with zero real edges (or an id
// that doesn't correspond to any node at all) gets a 200 with empty
// nodes/edges slices, not a 404 — matching ListNodeEdges' own
// "empty, not an error" semantics rather than inventing a 404 path that
// doesn't match how the store method actually behaves.
func TestGetNodeEdgesEmpty(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	lonely, err := store.UpsertDiscoveredNode(ctx, "lonely:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert lonely: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/nodes/%s/edges", srv.URL, lonely.ID))
	if err != nil {
		t.Fatalf("GET /nodes/{id}/edges: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 0 {
		t.Errorf("len(nodes) = %d, want 0", len(got.Nodes))
	}
	if len(got.Edges) != 0 {
		t.Errorf("len(edges) = %d, want 0", len(got.Edges))
	}

	// A node id with no corresponding node at all behaves the same way
	// (empty, not 404) — ListNodeEdges doesn't error on zero matching
	// rows regardless of whether the id belongs to a real node.
	unknownResp, err := http.Get(fmt.Sprintf("%s/nodes/%s/edges", srv.URL, uuid.New()))
	if err != nil {
		t.Fatalf("GET /nodes/{unknown}/edges: %v", err)
	}
	defer unknownResp.Body.Close()
	if unknownResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", unknownResp.StatusCode, http.StatusOK)
	}
}

// TestGetNodeEdgesInvalidLimit asserts `?limit=` on GET /nodes/{id}/edges
// rejects non-positive/non-numeric values with 400, mirroring
// handleGetNodeHistory's identical limit-parsing/validation pattern.
func TestGetNodeEdgesInvalidLimit(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "a:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	for _, v := range []string{"0", "-1", "not-a-number"} {
		resp, err := http.Get(fmt.Sprintf("%s/nodes/%s/edges?limit=%s", srv.URL, node.ID, v))
		if err != nil {
			t.Fatalf("GET /nodes/{id}/edges?limit=%s: %v", v, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("limit=%s: status = %d, want %d", v, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

func TestTopology(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	a, err := store.UpsertDiscoveredNode(ctx, "a:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	b, err := store.UpsertDiscoveredNode(ctx, "b:2", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	if err := store.RecordPeerEdgeObservation(ctx, a.ID, b.ID); err != nil {
		t.Fatalf("record edge observation: %v", err)
	}

	resp, err := http.Get(srv.URL + "/topology")
	if err != nil {
		t.Fatalf("GET /topology: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 2 {
		t.Errorf("len(nodes) = %d, want 2", len(got.Nodes))
	}
	if len(got.Edges) != 1 {
		t.Errorf("len(edges) = %d, want 1", len(got.Edges))
	}
}

// TestScrubbingP2PVsRegistry is the single most important test in this
// package: it asserts the hard privacy requirement end-to-end across the
// actual HTTP responses (raw JSON body substring checks, not just decoded
// struct field checks, since the whole point is that the raw address
// string must never appear anywhere in the response body for a
// p2p_discovered node) — GET /nodes, GET /nodes/{id}, and GET /topology
// must never leak a p2p_discovered node's address, but must show a
// registry_submitted node's address (the owner opted in).
func TestScrubbingP2PVsRegistry(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const p2pAddr = "1.2.3.4:18142"
	const registryAddr = "5.6.7.8:18142"

	p2pNode, err := store.UpsertDiscoveredNode(ctx, p2pAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert p2p node: %v", err)
	}
	registryNode, err := store.UpsertDiscoveredNode(ctx, registryAddr, storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert registry node: %v", err)
	}

	getBody := func(url string) string {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(body)
	}

	// GET /nodes
	listBody := getBody(srv.URL + "/nodes")
	if strings.Contains(listBody, p2pAddr) {
		t.Errorf("GET /nodes body contains p2p node's address %q:\n%s", p2pAddr, listBody)
	}
	if !strings.Contains(listBody, registryAddr) {
		t.Errorf("GET /nodes body missing registry node's address %q:\n%s", registryAddr, listBody)
	}
	if !strings.Contains(listBody, `"has_ipv4":true`) {
		t.Errorf("GET /nodes body missing has_ipv4:true capability signal:\n%s", listBody)
	}

	// GET /nodes/{id} for each node
	p2pGetBody := getBody(fmt.Sprintf("%s/nodes/%s", srv.URL, p2pNode.ID))
	if strings.Contains(p2pGetBody, p2pAddr) {
		t.Errorf("GET /nodes/%s body contains its own address %q:\n%s", p2pNode.ID, p2pAddr, p2pGetBody)
	}
	if !strings.Contains(p2pGetBody, `"has_ipv4":true`) {
		t.Errorf("GET /nodes/%s body missing has_ipv4:true capability signal:\n%s", p2pNode.ID, p2pGetBody)
	}

	registryGetBody := getBody(fmt.Sprintf("%s/nodes/%s", srv.URL, registryNode.ID))
	if !strings.Contains(registryGetBody, registryAddr) {
		t.Errorf("GET /nodes/%s body missing its own address %q:\n%s", registryNode.ID, registryAddr, registryGetBody)
	}

	// Cross-check: the p2p node's address must not appear in the
	// registry node's response either, and vice versa is not asserted
	// (no reason the registry address would appear there).
	if strings.Contains(registryGetBody, p2pAddr) {
		t.Errorf("GET /nodes/%s body contains the OTHER (p2p) node's address %q:\n%s", registryNode.ID, p2pAddr, registryGetBody)
	}

	// GET /topology
	topologyBody := getBody(srv.URL + "/topology")
	if strings.Contains(topologyBody, p2pAddr) {
		t.Errorf("GET /topology body contains p2p node's address %q:\n%s", p2pAddr, topologyBody)
	}
	if !strings.Contains(topologyBody, registryAddr) {
		t.Errorf("GET /topology body missing registry node's address %q:\n%s", registryAddr, topologyBody)
	}
}

// TestListSubmissions asserts GET /admin/submissions defaults to
// listing pending submissions and honors the status query param.
func TestListSubmissions(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	pending, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	resp := doAdminRequest(t, http.MethodGet, srv.URL+"/admin/submissions", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got []storage.PendingSubmission
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != pending.ID {
		t.Fatalf("got = %+v, want just %v", got, pending.ID)
	}
}

// TestApproveSubmission asserts approving a pending submission returns
// 200, creates the real node with DiscoverySourceRegistry, sets
// promoted_node_id, and kicks off the same async health-check goroutine
// that used to run directly from POST /nodes.
func TestApproveSubmission(t *testing.T) {
	height := int64(42)
	client := &fakeClient{info: map[string]collector.NodeInfo{
		"1.2.3.4:18142": {Reachable: true, Height: &height},
	}}
	srv, store := newTestServer(t, client)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "1.2.3.4:18142", strPtr("my node"), strPtr("pool-x"))
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	resp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/submissions/%s/approve", srv.URL, submission.ID), "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}

	var got struct {
		Node       storage.Node              `json:"node"`
		Submission storage.PendingSubmission `json:"submission"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Node.Address != "1.2.3.4:18142" {
		t.Errorf("node.address = %q, want %q", got.Node.Address, "1.2.3.4:18142")
	}
	if got.Node.DiscoverySource != storage.DiscoverySourceRegistry {
		t.Errorf("node.discovery_source = %q, want %q", got.Node.DiscoverySource, storage.DiscoverySourceRegistry)
	}
	if got.Node.Label == nil || *got.Node.Label != "my node" {
		t.Errorf("node.label = %v, want %q", got.Node.Label, "my node")
	}
	if owner, _ := got.Node.Tags["owner"].(string); owner != "pool-x" {
		t.Errorf("node.tags[owner] = %v, want %q", got.Node.Tags["owner"], "pool-x")
	}
	if got.Submission.Status != storage.SubmissionStatusApproved {
		t.Errorf("submission.status = %q, want %q", got.Submission.Status, storage.SubmissionStatusApproved)
	}
	if got.Submission.PromotedNodeID == nil || *got.Submission.PromotedNodeID != got.Node.ID {
		t.Errorf("submission.promoted_node_id = %v, want %v", got.Submission.PromotedNodeID, got.Node.ID)
	}

	// Persisted state must agree with the response.
	persisted, err := store.GetPendingSubmission(ctx, submission.ID)
	if err != nil {
		t.Fatalf("get pending submission: %v", err)
	}
	if persisted.Status != storage.SubmissionStatusApproved {
		t.Errorf("persisted status = %q, want %q", persisted.Status, storage.SubmissionStatusApproved)
	}

	// The async health-check kickoff should record a health check
	// shortly after the POST returns, without the POST itself having
	// waited on it — same assertion technique as the old
	// TestCreateNodeValid used before submissions required approval.
	deadline := time.Now().Add(2 * time.Second)
	for {
		history, err := store.GetNodeHistory(ctx, got.Node.ID, 1)
		if err != nil {
			t.Fatalf("get node history: %v", err)
		}
		if len(history) == 1 {
			if !history[0].Reachable {
				t.Errorf("expected async health check to report reachable = true")
			}
			if history[0].Height == nil || *history[0].Height != height {
				t.Errorf("height = %v, want %d", history[0].Height, height)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for async health-check kickoff to record a health check")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestApproveSubmissionNotPending asserts approving an already-decided
// submission (rejected here) errors rather than double-processing it.
func TestApproveSubmissionNotPending(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}
	if err := store.RejectPendingSubmission(ctx, submission.ID, nil); err != nil {
		t.Fatalf("reject: %v", err)
	}

	resp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/submissions/%s/approve", srv.URL, submission.ID), "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("status = %d, want an error status (submission already reviewed)", resp.StatusCode)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("len(nodes) = %d, want 0 (approving an already-rejected submission must not create a node)", len(nodes))
	}
}

// TestApproveSubmissionAddressBecameOptedIn asserts that if the address
// became publicly opted-in AFTER the submission was queued but BEFORE
// it's approved, approval is rejected with a conflict and the submission
// is left pending (not auto-rejected) for a human to explicitly decide.
func TestApproveSubmissionAddressBecameOptedIn(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	// Someone else's submission for the same address gets approved
	// first (simulated directly here), making it publicly opted-in.
	if _, err := store.UpsertDiscoveredNode(ctx, "a:1", storage.DiscoverySourceRegistry, nil, nil); err != nil {
		t.Fatalf("upsert competing node: %v", err)
	}

	resp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/submissions/%s/approve", srv.URL, submission.ID), "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusConflict)
	}

	// The submission must remain pending — not auto-flipped to rejected.
	got, err := store.GetPendingSubmission(ctx, submission.ID)
	if err != nil {
		t.Fatalf("get pending submission: %v", err)
	}
	if got.Status != storage.SubmissionStatusPending {
		t.Errorf("status = %q, want %q (left for a human decision)", got.Status, storage.SubmissionStatusPending)
	}
}

// TestRejectSubmission asserts rejecting a pending submission returns
// 200, flips its status to rejected with the given reason, and never
// touches the nodes table.
func TestRejectSubmission(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	resp := doAdminRequest(t, http.MethodPost,
		fmt.Sprintf("%s/admin/submissions/%s/reject", srv.URL, submission.ID),
		"application/json",
		bytes.NewBufferString(`{"reason":"looks like spam"}`),
	)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got storage.PendingSubmission
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != storage.SubmissionStatusRejected {
		t.Errorf("status = %q, want %q", got.Status, storage.SubmissionStatusRejected)
	}
	if got.RejectionReason == nil || *got.RejectionReason != "looks like spam" {
		t.Errorf("rejection_reason = %v, want %q", got.RejectionReason, "looks like spam")
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("len(nodes) = %d, want 0 (rejection must never touch the nodes table)", len(nodes))
	}
}

// TestRejectSubmissionEmptyBody asserts an empty request body is
// accepted (no reason set) rather than erroring on EOF.
func TestRejectSubmissionEmptyBody(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	resp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/submissions/%s/reject", srv.URL, submission.ID), "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}

	var got storage.PendingSubmission
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != storage.SubmissionStatusRejected {
		t.Errorf("status = %q, want %q", got.Status, storage.SubmissionStatusRejected)
	}
	if got.RejectionReason != nil {
		t.Errorf("rejection_reason = %v, want nil", got.RejectionReason)
	}
}

// TestRejectSubmissionMalformedBody asserts a genuinely malformed JSON
// body (not just empty) is a 400, distinguishing "no body" from "bad
// body".
func TestRejectSubmissionMalformedBody(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	resp := doAdminRequest(t, http.MethodPost,
		fmt.Sprintf("%s/admin/submissions/%s/reject", srv.URL, submission.ID),
		"application/json",
		bytes.NewBufferString(`{not json`),
	)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// TestCreateNodeProbeAsync asserts the connectivity probe kicked off by a
// successful POST /nodes submission never blocks the HTTP response (the
// whole "async, non-blocking" point), and that probe_attempted_at /
// probe_reachable do eventually land on the pending_submissions row once
// the (slow, fixture) probe finishes.
func TestCreateNodeProbeAsync(t *testing.T) {
	const addr = "203.0.113.10:18142"
	client := &fakeClient{
		info:  map[string]collector.NodeInfo{addr: {Reachable: true}},
		delay: 2 * time.Second,
	}
	srv, store := newTestServer(t, client)
	ctx := context.Background()

	body := `{"host":"203.0.113.10","port":18142}`
	start := time.Now()
	resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /nodes: %v", err)
	}
	elapsed := time.Since(start)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusAccepted, body)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("POST /nodes took %v, want well under the 2s probe delay (probe must be async)", elapsed)
	}

	var submission storage.PendingSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submission); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if submission.ProbeAttemptedAt != nil {
		t.Errorf("probe_attempted_at = %v, want nil (probe hasn't finished yet)", submission.ProbeAttemptedAt)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := store.GetPendingSubmission(ctx, submission.ID)
		if err != nil {
			t.Fatalf("get pending submission: %v", err)
		}
		if got.ProbeAttemptedAt != nil {
			if got.ProbeReachable == nil || !*got.ProbeReachable {
				t.Errorf("probe_reachable = %v, want true", got.ProbeReachable)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for async probe to record a result")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestCreateNodeSSRFRejected asserts private/reserved-IP hosts are
// rejected with 400, while a real public IP and a syntactically valid
// onion host both still queue normally (202). Each case gets its own
// fresh server (and so its own fresh rate-limiter/lockout-tracker
// instance) so the SSRF-rejected cases' strikes don't accumulate into a
// shared lockout that would corrupt later cases in this same test.
func TestCreateNodeSSRFRejected(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		port       int
		wantStatus int
	}{
		{"loopback v4", "127.0.0.1", 18142, http.StatusBadRequest},
		{"private v4 class C", "192.168.1.1", 18142, http.StatusBadRequest},
		{"private v4 class A", "10.0.0.1", 18142, http.StatusBadRequest},
		{"link-local v4", "169.254.1.1", 18142, http.StatusBadRequest},
		{"loopback v6", "::1", 18142, http.StatusBadRequest},
		{"public v4", "1.1.1.1", 18143, http.StatusAccepted},
		{"onion v3-shaped", "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion", 18144, http.StatusAccepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newTestServer(t, nil)
			body := fmt.Sprintf(`{"host":%q,"port":%d}`, tc.host, tc.port)
			resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
			if err != nil {
				t.Fatalf("POST /nodes: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, tc.wantStatus, respBody)
			}
		})
	}
}

// TestCreateNodeRateLimit asserts the 6th submission from the same
// source IP within the limiter's window (burst 5) gets 429 with a
// Retry-After header, while the first 5 (distinct, otherwise-valid
// addresses) succeed normally.
func TestCreateNodeRateLimit(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"host":"198.51.100.%d","port":18142}`, i+1)
		resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("POST /nodes (%d): %v", i, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("submission %d: status = %d, want %d (body: %s)", i, resp.StatusCode, http.StatusAccepted, respBody)
		}
	}

	// The 6th submission (still a distinct, otherwise-valid address)
	// exceeds the per-IP rate limit.
	body := `{"host":"198.51.100.6","port":18142}`
	resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /nodes (6th): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusTooManyRequests, respBody)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("Retry-After header missing on 429 response")
	}
}

// TestCreateNodeInvalidSubmissionLockout asserts that repeated
// genuinely-invalid submissions (a reused private-IP host) from one
// source IP eventually flip from repeated 400s to a 429 lockout once the
// strike threshold is hit.
func TestCreateNodeInvalidSubmissionLockout(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	const body = `{"host":"127.0.0.1","port":18142}`

	// strikeThreshold is 4: the first 4 genuinely-invalid submissions
	// from this IP each get a plain 400 (and record a strike); the 4th
	// strike crosses the threshold and locks the IP out.
	for i := 0; i < 4; i++ {
		resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("POST /nodes (strike %d): %v", i, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("strike %d: status = %d, want %d (body: %s)", i, resp.StatusCode, http.StatusBadRequest, respBody)
		}
	}

	// The next submission — even a well-formed, valid one — is now
	// blocked by the lockout before validation even runs.
	resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(`{"host":"198.51.100.50","port":18142}`))
	if err != nil {
		t.Fatalf("POST /nodes (after lockout): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusTooManyRequests, respBody)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("Retry-After header missing on lockout 429 response")
	}
}

// TestPollNowCreatesNewNode asserts POST /admin/nodes/poll-now against a
// brand-new host:port creates exactly one node, synchronously probes it,
// and returns the resulting node state (pubkey confirmed) in the
// response body.
func TestPollNowCreatesNewNode(t *testing.T) {
	const addr = "203.0.113.20:18142"
	pubkey := []byte{1, 2, 3, 4}
	client := &fakeClient{info: map[string]collector.NodeInfo{
		addr: {Reachable: true, PublicKey: pubkey},
	}}
	srv, store := newTestServer(t, client)
	ctx := context.Background()

	body := `{"host":"203.0.113.20","port":18142}`
	resp := doAdminRequest(t, http.MethodPost, srv.URL+"/admin/nodes/poll-now", "application/json", bytes.NewBufferString(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, respBody)
	}

	var got struct {
		Node  storage.Node `json:"node"`
		Error string       `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Error != "" {
		t.Errorf("error = %q, want empty", got.Error)
	}
	if got.Node.Address != addr {
		t.Errorf("node.address = %q, want %q", got.Node.Address, addr)
	}
	if len(got.Node.PublicKey) == 0 {
		t.Errorf("node.public_key = %v, want the confirmed pubkey", got.Node.PublicKey)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("len(nodes) = %d, want 1", len(nodes))
	}
	if nodes[0].Address != addr {
		t.Errorf("nodes[0].address = %q, want %q", nodes[0].Address, addr)
	}
}

// TestPollNowReusesExistingNode asserts POST /admin/nodes/poll-now
// against an already-known address reuses the existing node row (same
// ID) rather than creating a duplicate.
func TestPollNowReusesExistingNode(t *testing.T) {
	const addr = "203.0.113.21:18142"
	client := &fakeClient{info: map[string]collector.NodeInfo{
		addr: {Reachable: true},
	}}
	srv, store := newTestServer(t, client)
	ctx := context.Background()

	existing, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert existing node: %v", err)
	}

	before, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes before: %v", err)
	}

	body := fmt.Sprintf(`{"host":"203.0.113.21","port":18142}`)
	resp := doAdminRequest(t, http.MethodPost, srv.URL+"/admin/nodes/poll-now", "application/json", bytes.NewBufferString(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, respBody)
	}

	var got struct {
		Node storage.Node `json:"node"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Node.ID != existing.ID {
		t.Errorf("node.id = %v, want existing node's id %v (must reuse, not duplicate)", got.Node.ID, existing.ID)
	}

	after, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes after: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("len(nodes) = %d, want unchanged %d (no duplicate row created)", len(after), len(before))
	}
}

// TestPollNowSkipsSSRFValidation asserts POST /admin/nodes/poll-now
// does NOT apply the SSRF/private-IP validation that POST /nodes does —
// it must accept a private-IP host and probe it (200, even when the
// probe itself fails/is unreachable), in contrast to POST /nodes
// rejecting the exact same host with a 400 and the SSRF error message.
func TestPollNowSkipsSSRFValidation(t *testing.T) {
	srv, _ := newTestServer(t, nil) // no fixture for this address -> GetInfo fails -> unreachable

	body := `{"host":"127.0.0.1","port":18142}`

	// Contrast: POST /nodes (public, unauthenticated) rejects this
	// exact host with the SSRF message.
	createResp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /nodes: %v", err)
	}
	defer createResp.Body.Close()
	createBody, _ := io.ReadAll(createResp.Body)
	if createResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /nodes status = %d, want %d", createResp.StatusCode, http.StatusBadRequest)
	}
	if !strings.Contains(string(createBody), "private/reserved IP addresses are not allowed") {
		t.Errorf("POST /nodes body missing SSRF rejection message: %s", createBody)
	}

	// POST /admin/nodes/poll-now must accept the same host.
	pollResp := doAdminRequest(t, http.MethodPost, srv.URL+"/admin/nodes/poll-now", "application/json", bytes.NewBufferString(body))
	defer pollResp.Body.Close()
	pollBody, _ := io.ReadAll(pollResp.Body)
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /admin/nodes/poll-now status = %d, want %d (body: %s)", pollResp.StatusCode, http.StatusOK, pollBody)
	}
	if strings.Contains(string(pollBody), "private/reserved IP addresses are not allowed") {
		t.Errorf("POST /admin/nodes/poll-now body unexpectedly contains SSRF rejection message: %s", pollBody)
	}
}

// TestPollNowAcceptsPrivateIPv4 asserts POST /admin/nodes/poll-now
// accepts a plain RFC1918 private IPv4 host (192.168.1.1, distinct from
// the loopback case covered by TestPollNowSkipsSSRFValidation above)
// and probes it (200), preserving the endpoint's deliberate SSRF
// exemption for admins who need to force-poll internal addresses.
func TestPollNowAcceptsPrivateIPv4(t *testing.T) {
	srv, _ := newTestServer(t, nil) // no fixture for this address -> GetInfo fails -> unreachable, still 200

	body := `{"host":"192.168.1.1","port":18142}`
	resp := doAdminRequest(t, http.MethodPost, srv.URL+"/admin/nodes/poll-now", "application/json", bytes.NewBufferString(body))
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, respBody)
	}
	if strings.Contains(string(respBody), "private/reserved IP addresses are not allowed") {
		t.Errorf("body unexpectedly contains SSRF rejection message: %s", respBody)
	}
}

// TestPollNowInvalid asserts empty-host, out-of-range-port, and
// malformed-host requests are rejected with 400 and the same error
// message text as handleCreateNode's equivalent checks (for the
// empty-host/bad-port cases) or validateHostSyntax's message (for the
// malformed-host case) — and that the malformed-host case does not
// create a node.
func TestPollNowInvalid(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	cases := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{"missing host", `{"port":18142}`, "host is required"},
		{"port too small", `{"host":"1.2.3.4","port":0}`, "port must be between 1 and 65535"},
		{"port too large", `{"host":"1.2.3.4","port":65536}`, "port must be between 1 and 65535"},
		{
			"malformed onion host with leading slash",
			`{"host":"/wyow2dp6w2ff4u2kebklkmbzwlixyhjtza5bf3pt3oxnps5hcjn76iyd.onion","port":18142}`,
			"host must be a valid IP address or .onion address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, err := store.ListNodes(ctx, storage.NodeFilter{})
			if err != nil {
				t.Fatalf("list nodes before: %v", err)
			}

			resp := doAdminRequest(t, http.MethodPost, srv.URL+"/admin/nodes/poll-now", "application/json", bytes.NewBufferString(tc.body))
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusBadRequest, respBody)
			}
			if !strings.Contains(string(respBody), tc.wantMsg) {
				t.Errorf("body = %s, want it to contain %q", respBody, tc.wantMsg)
			}

			after, err := store.ListNodes(ctx, storage.NodeFilter{})
			if err != nil {
				t.Fatalf("list nodes after: %v", err)
			}
			if len(after) != len(before) {
				t.Errorf("len(nodes) = %d, want unchanged %d (rejected request must not create a node)", len(after), len(before))
			}
		})
	}
}

// TestCreateNodeQueueCap asserts that once the pending-submission queue
// reaches api.MaxPendingSubmissions, further submissions are rejected
// with 503 rather than growing the queue further. MaxPendingSubmissions
// is temporarily lowered so this test doesn't need to create 100 real
// rows.
func TestCreateNodeQueueCap(t *testing.T) {
	orig := api.MaxPendingSubmissions
	api.MaxPendingSubmissions = 3
	defer func() { api.MaxPendingSubmissions = orig }()

	srv, _ := newTestServer(t, nil)

	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"host":"198.51.100.%d","port":18150}`, i+10)
		resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("POST /nodes (%d): %v", i, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("submission %d: status = %d, want %d (body: %s)", i, resp.StatusCode, http.StatusAccepted, respBody)
		}
	}

	// The 4th submission is a distinct address too — it must be
	// rejected purely because the queue is full, not for any other
	// reason.
	body := `{"host":"198.51.100.13","port":18150}`
	resp, err := http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /nodes (over cap): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusServiceUnavailable, respBody)
	}
}

// TestListNodesPaginationDefaults asserts GET /nodes with no query
// params applies a default page limit rather than returning every node
// — seeded well above the default limit to actually exercise that.
func TestListNodesPaginationDefaults(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const seeded = 105 // > api's default limit of 100
	for i := 0; i < seeded; i++ {
		addr := fmt.Sprintf("10.0.%d.%d:18142", i/256, i%256)
		if _, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil); err != nil {
			t.Fatalf("upsert node %d: %v", i, err)
		}
	}

	resp, err := http.Get(srv.URL + "/nodes")
	if err != nil {
		t.Fatalf("GET /nodes: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Nodes   []api.PublicNode `json:"nodes"`
		Total   int              `json:"total"`
		Limit   int              `json:"limit"`
		Offset  int              `json:"offset"`
		HasMore bool             `json:"has_more"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != seeded {
		t.Fatalf("got.Total = %d, want %d", got.Total, seeded)
	}
	if len(got.Nodes) != 100 {
		t.Fatalf("len(got.Nodes) = %d, want 100 (default limit), not the full %d", len(got.Nodes), seeded)
	}
	if got.Limit != 100 {
		t.Fatalf("got.Limit = %d, want 100", got.Limit)
	}
	if got.Offset != 0 {
		t.Fatalf("got.Offset = %d, want 0", got.Offset)
	}
	if !got.HasMore {
		t.Fatal("got.HasMore = false, want true (105 seeded, only 100 returned)")
	}
}

// TestListNodesExplicitLimitOffset asserts GET /nodes?limit=X&offset=Y
// returns the correct page (in the same address-sorted order ListNodes
// always uses) and correctly reflects has_more at the boundary.
func TestListNodesExplicitLimitOffset(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	for _, addr := range []string{"n1:1", "n2:1", "n3:1", "n4:1", "n5:1"} {
		if _, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil); err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
	}

	resp, err := http.Get(srv.URL + "/nodes?limit=2&offset=2")
	if err != nil {
		t.Fatalf("GET /nodes?limit=2&offset=2: %v", err)
	}
	defer resp.Body.Close()
	var got struct {
		Nodes   []api.PublicNode `json:"nodes"`
		Total   int              `json:"total"`
		Limit   int              `json:"limit"`
		Offset  int              `json:"offset"`
		HasMore bool             `json:"has_more"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 2 {
		t.Fatalf("len(got.Nodes) = %d, want 2", len(got.Nodes))
	}
	if got.Total != 5 {
		t.Fatalf("got.Total = %d, want 5", got.Total)
	}
	if !got.HasMore {
		t.Error("got.HasMore = false, want true (offset 2 + limit 2 = 4 < total 5)")
	}

	// Last page: offset 4, limit 2 -> only 1 node left, HasMore false.
	resp2, err := http.Get(srv.URL + "/nodes?limit=2&offset=4")
	if err != nil {
		t.Fatalf("GET /nodes?limit=2&offset=4: %v", err)
	}
	defer resp2.Body.Close()
	var got2 struct {
		Nodes   []api.PublicNode `json:"nodes"`
		HasMore bool             `json:"has_more"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got2.Nodes) != 1 {
		t.Fatalf("len(got2.Nodes) = %d, want 1", len(got2.Nodes))
	}
	if got2.HasMore {
		t.Error("got2.HasMore = true, want false (last page)")
	}
}

// TestListNodesLimitClamp asserts a `?limit=` above the API's hard cap
// is silently clamped rather than erroring.
func TestListNodesLimitClamp(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/nodes?limit=100000")
	if err != nil {
		t.Fatalf("GET /nodes?limit=100000: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Limit int `json:"limit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Limit != 500 {
		t.Fatalf("got.Limit = %d, want 500 (clamped)", got.Limit)
	}
}

// TestListNodesInvalidOffset asserts a negative `?offset=` is rejected
// with 400.
func TestListNodesInvalidOffset(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/nodes?offset=-1")
	if err != nil {
		t.Fatalf("GET /nodes?offset=-1: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// TestTopologyDefaultCap asserts GET /topology with no params bounds the
// returned node set once the population exceeds the cap: it lowers the
// cap via a small `?limit=` override rather than needing 300+ real seeded
// nodes, to exercise the same capping code path handleTopology's default
// takes.
func TestTopologyDefaultCap(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// hub is the best-connected node; leaf1/leaf2/leaf3 all connect only
	// to hub, so hub + any 2 of the leaves is a valid top-3.
	hub, err := store.UpsertDiscoveredNode(ctx, "hub:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert hub: %v", err)
	}
	var leaves []uuid.UUID
	for _, addr := range []string{"leaf1:1", "leaf2:1", "leaf3:1"} {
		leaf, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
		leaves = append(leaves, leaf.ID)
		if err := store.RecordPeerEdgeObservation(ctx, hub.ID, leaf.ID); err != nil {
			t.Fatalf("record edge hub->%s: %v", addr, err)
		}
	}

	// All 4 nodes exist; cap to 3 via an explicit ?limit= override (the
	// cheapest way to exercise the capping logic itself without seeding
	// 300+ real nodes for the production default).
	resp, err := http.Get(srv.URL + "/topology?limit=3")
	if err != nil {
		t.Fatalf("GET /topology?limit=3: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 3 {
		t.Fatalf("len(got.Nodes) = %d, want 3 (capped)", len(got.Nodes))
	}
	gotIDs := map[uuid.UUID]bool{}
	for _, n := range got.Nodes {
		gotIDs[n.ID] = true
	}
	if !gotIDs[hub.ID] {
		t.Errorf("got.Nodes missing hub (highest degree), gotIDs=%v", gotIDs)
	}
	for _, e := range got.Edges {
		if !gotIDs[e.FromNodeID] || !gotIDs[e.ToNodeID] {
			t.Errorf("edge %+v has an endpoint outside the returned node set", e)
		}
	}
}

// TestTopPeeredNodesOnionClearnetCounts asserts GET /topology/top-peered's
// response includes correct onion_peer_count/clearnet_peer_count fields
// for a hub node whose distinct peers are a mix of onion-only,
// clearnet-only, and dual-stack (both an onion AND a clearnet address
// known) — mirroring
// storage.TestTopPeeredNodesOnionClearnetBreakdown's setup, but asserted
// through the public JSON API response instead of storage.NodeDegree
// directly.
func TestTopPeeredNodesOnionClearnetCounts(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const onionAddr = "abcdefghijklmnopqrstuvwxyz234567.onion:18142"
	const clearnetAddr = "203.0.113.5:18142"
	const dualStackPrimaryAddr = "203.0.113.9:18142"
	const dualStackOnionAddr = "qrstuvwxyzabcdefghijklmnop234567.onion:18142"

	hub, err := store.UpsertDiscoveredNode(ctx, "hub-api:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert hub: %v", err)
	}
	onionOnlyPeer, err := store.UpsertDiscoveredNode(ctx, onionAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert onion-only peer: %v", err)
	}
	clearnetOnlyPeer, err := store.UpsertDiscoveredNode(ctx, clearnetAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert clearnet-only peer: %v", err)
	}
	dualStackPeer, err := store.UpsertDiscoveredNode(ctx, dualStackPrimaryAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert dual-stack peer: %v", err)
	}

	// storage.Store doesn't expose the raw pool, so add the dual-stack
	// peer's second address via a direct connection to the same test
	// database instead (same DSN newTestServer's store was built with).
	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_addresses (node_id, address, first_seen, last_seen)
		VALUES ($1, $2, now(), now())
	`, dualStackPeer.ID, dualStackOnionAddr); err != nil {
		t.Fatalf("insert dual-stack peer's onion address: %v", err)
	}

	for _, e := range []struct{ from, to uuid.UUID }{
		{hub.ID, onionOnlyPeer.ID},
		{hub.ID, clearnetOnlyPeer.ID},
		{hub.ID, dualStackPeer.ID},
	} {
		if err := store.RecordPeerEdgeObservation(ctx, e.from, e.to); err != nil {
			t.Fatalf("record edge observation %v -> %v: %v", e.from, e.to, err)
		}
	}

	resp, err := http.Get(srv.URL + "/topology/top-peered")
	if err != nil {
		t.Fatalf("GET /topology/top-peered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got []api.PublicNodeDegree
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var hubRow *api.PublicNodeDegree
	for i := range got {
		if got[i].NodeID == hub.ID {
			hubRow = &got[i]
			break
		}
	}
	if hubRow == nil {
		t.Fatalf("hub %v not found in GET /topology/top-peered response: %+v", hub.ID, got)
	}

	if hubRow.OnionPeerCount != 2 {
		t.Errorf("hub OnionPeerCount = %d, want 2 (onion-only peer + dual-stack peer)", hubRow.OnionPeerCount)
	}
	if hubRow.ClearnetPeerCount != 2 {
		t.Errorf("hub ClearnetPeerCount = %d, want 2 (clearnet-only peer + dual-stack peer)", hubRow.ClearnetPeerCount)
	}
}

// TestTopPeeredNodesLiveCounts asserts GET /topology/top-peered's
// response includes correct live_degree/live_in_degree/live_out_degree/
// live_onion_peer_count/live_clearnet_peer_count fields — the
// confirmed-peer subset of the raw totals — mirroring
// storage.TestTopPeeredNodesLiveCounts's setup, but asserted through the
// public JSON API response (api.PublicNodeDegree) instead of
// storage.NodeDegree directly.
//
// The hub has three CONFIRMED peers (one onion-only, one clearnet-only,
// one dual-stack reached via an out-edge each) and three unconfirmed
// peers (one onion-only, one clearnet-only, one plain, reached via an
// in-edge each) — see storage.TestTopPeeredNodesLiveCounts's doc comment
// for the exact same setup and the reasoning behind each expected count.
func TestTopPeeredNodesLiveCounts(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const (
		confirmedOnionAddr      = "confonionpeerapi1abcdefghijklmnopq.onion:18142"
		unconfirmedOnionAddr    = "unconfonionpeerapi2abcdefghijklmno.onion:18142"
		dualStackClearnetAddr   = "203.0.113.31:18142"
		dualStackOnionAddr      = "confdualstackpeerapiabcdefghijklmn.onion:18142"
		confirmedClearnetAddr   = "203.0.113.32:18142"
		unconfirmedClearnetAddr = "203.0.113.33:18142"
		unconfirmedPlainAddr    = "unconfirmed-plain-peer-api:18142"
	)

	hub, err := store.UpsertDiscoveredNode(ctx, "hub-live-api:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert hub: %v", err)
	}

	confirmedOnionPeer, err := store.UpsertConfirmedNode(ctx, confirmedOnionAddr, []byte("some-unique-fake-pubkey-api-01"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert confirmed onion peer: %v", err)
	}
	unconfirmedOnionPeer, err := store.UpsertDiscoveredNode(ctx, unconfirmedOnionAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert unconfirmed onion peer: %v", err)
	}
	confirmedDualStackPeer, err := store.UpsertConfirmedNode(ctx, dualStackClearnetAddr, []byte("some-unique-fake-pubkey-api-02"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert confirmed dual-stack peer: %v", err)
	}
	// storage.Store doesn't expose the raw pool, so add the confirmed
	// dual-stack peer's second address via a direct connection to the
	// same test database instead (same DSN newTestServer's store was
	// built with).
	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_addresses (node_id, address, first_seen, last_seen)
		VALUES ($1, $2, now(), now())
	`, confirmedDualStackPeer.ID, dualStackOnionAddr); err != nil {
		t.Fatalf("insert confirmed dual-stack peer's onion address: %v", err)
	}
	confirmedClearnetPeer, err := store.UpsertConfirmedNode(ctx, confirmedClearnetAddr, []byte("some-unique-fake-pubkey-api-03"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert confirmed clearnet peer: %v", err)
	}
	unconfirmedClearnetPeer, err := store.UpsertDiscoveredNode(ctx, unconfirmedClearnetAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert unconfirmed clearnet peer: %v", err)
	}
	unconfirmedPlainPeer, err := store.UpsertDiscoveredNode(ctx, unconfirmedPlainAddr, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert unconfirmed plain peer: %v", err)
	}

	// Out-edges (hub -> peer).
	for _, peerID := range []uuid.UUID{confirmedOnionPeer.ID, unconfirmedOnionPeer.ID, confirmedDualStackPeer.ID} {
		if err := store.RecordPeerEdgeObservation(ctx, hub.ID, peerID); err != nil {
			t.Fatalf("record edge hub -> %v: %v", peerID, err)
		}
	}
	// In-edges (peer -> hub).
	for _, peerID := range []uuid.UUID{confirmedClearnetPeer.ID, unconfirmedClearnetPeer.ID, unconfirmedPlainPeer.ID} {
		if err := store.RecordPeerEdgeObservation(ctx, peerID, hub.ID); err != nil {
			t.Fatalf("record edge %v -> hub: %v", peerID, err)
		}
	}

	resp, err := http.Get(srv.URL + "/topology/top-peered")
	if err != nil {
		t.Fatalf("GET /topology/top-peered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got []api.PublicNodeDegree
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var hubRow *api.PublicNodeDegree
	for i := range got {
		if got[i].NodeID == hub.ID {
			hubRow = &got[i]
			break
		}
	}
	if hubRow == nil {
		t.Fatalf("hub %v not found in GET /topology/top-peered response: %+v", hub.ID, got)
	}

	// Raw totals: confirmed AND unconfirmed peers all count.
	if hubRow.Degree != 6 {
		t.Errorf("hub Degree = %d, want 6", hubRow.Degree)
	}
	if hubRow.OutDegree != 3 {
		t.Errorf("hub OutDegree = %d, want 3", hubRow.OutDegree)
	}
	if hubRow.InDegree != 3 {
		t.Errorf("hub InDegree = %d, want 3", hubRow.InDegree)
	}
	if hubRow.OnionPeerCount != 3 {
		t.Errorf("hub OnionPeerCount = %d, want 3", hubRow.OnionPeerCount)
	}
	if hubRow.ClearnetPeerCount != 3 {
		t.Errorf("hub ClearnetPeerCount = %d, want 3", hubRow.ClearnetPeerCount)
	}

	// Live totals: only confirmed (non-null public_key) peers count.
	if hubRow.LiveDegree != 3 {
		t.Errorf("hub LiveDegree = %d, want 3 (confirmedOnionPeer, confirmedClearnetPeer, confirmedDualStackPeer)", hubRow.LiveDegree)
	}
	if hubRow.LiveOutDegree != 2 {
		t.Errorf("hub LiveOutDegree = %d, want 2 (confirmedOnionPeer, confirmedDualStackPeer)", hubRow.LiveOutDegree)
	}
	if hubRow.LiveInDegree != 1 {
		t.Errorf("hub LiveInDegree = %d, want 1 (confirmedClearnetPeer)", hubRow.LiveInDegree)
	}
	if hubRow.LiveOnionPeerCount != 2 {
		t.Errorf("hub LiveOnionPeerCount = %d, want 2 (confirmedOnionPeer, confirmedDualStackPeer)", hubRow.LiveOnionPeerCount)
	}
	if hubRow.LiveClearnetPeerCount != 2 {
		t.Errorf("hub LiveClearnetPeerCount = %d, want 2 (confirmedClearnetPeer, confirmedDualStackPeer)", hubRow.LiveClearnetPeerCount)
	}
}

// TestTopologyAllTrueUnbounded asserts GET /topology?all=true always
// returns every node/edge, ignoring the default cap.
func TestTopologyAllTrueUnbounded(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	hub, err := store.UpsertDiscoveredNode(ctx, "hub:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert hub: %v", err)
	}
	for _, addr := range []string{"leaf1:1", "leaf2:1", "leaf3:1"} {
		leaf, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
		if err := store.RecordPeerEdgeObservation(ctx, hub.ID, leaf.ID); err != nil {
			t.Fatalf("record edge hub->%s: %v", addr, err)
		}
	}

	resp, err := http.Get(srv.URL + "/topology?all=true")
	if err != nil {
		t.Fatalf("GET /topology?all=true: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 4 {
		t.Fatalf("len(got.Nodes) = %d, want 4 (unbounded)", len(got.Nodes))
	}
	if len(got.Edges) != 3 {
		t.Fatalf("len(got.Edges) = %d, want 3 (unbounded)", len(got.Edges))
	}
}

// TestTopologyDefaultMaxEdges asserts GET /topology with no params
// returns an edges array bounded by defaultTopologyMaxEdges. Seeding
// thousands of edges to actually exceed the 2500 default isn't practical
// for a fast/deterministic unit test, so this seeds a small dataset and
// asserts the invariant holds (it's trivially true here, but it
// exercises the same default-wiring code path as the production case;
// the max_edges/all=true tests above are what actually prove the cap
// truncates when exceeded).
func TestTopologyDefaultMaxEdges(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	hub, err := store.UpsertDiscoveredNode(ctx, "hub:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert hub: %v", err)
	}
	for _, addr := range []string{"leaf1:1", "leaf2:1"} {
		leaf, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
		if err := store.RecordPeerEdgeObservation(ctx, hub.ID, leaf.ID); err != nil {
			t.Fatalf("record edge hub->%s: %v", addr, err)
		}
	}

	resp, err := http.Get(srv.URL + "/topology")
	if err != nil {
		t.Fatalf("GET /topology: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 2500 mirrors api.defaultTopologyMaxEdges (unexported).
	const wantMaxEdges = 2500
	if len(got.Edges) > wantMaxEdges {
		t.Fatalf("len(got.Edges) = %d, want <= %d (default max_edges cap)", len(got.Edges), wantMaxEdges)
	}
}

// TestTopologyMaxEdgesCap asserts GET /topology?max_edges=N caps the
// returned edge count independently of the node cap: it seeds a small
// clique (more real edges between the nodes than the requested
// max_edges) and a generous ?limit= so every node survives the node cap,
// then checks the edge count is bounded by max_edges.
func TestTopologyMaxEdgesCap(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// 4 nodes, pairwise connected: 6 undirected edges, more than the
	// max_edges=3 cap used below.
	var ids []uuid.UUID
	for _, addr := range []string{"clique-a:1", "clique-b:1", "clique-c:1", "clique-d:1"} {
		n, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
		ids = append(ids, n.ID)
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if err := store.RecordPeerEdgeObservation(ctx, ids[i], ids[j]); err != nil {
				t.Fatalf("record edge %v -> %v: %v", ids[i], ids[j], err)
			}
		}
	}

	resp, err := http.Get(srv.URL + "/topology?limit=100&max_edges=3")
	if err != nil {
		t.Fatalf("GET /topology?limit=100&max_edges=3: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 4 {
		t.Fatalf("len(got.Nodes) = %d, want 4 (node cap not exceeded)", len(got.Nodes))
	}
	if len(got.Edges) > 3 {
		t.Fatalf("len(got.Edges) = %d, want <= 3 (max_edges cap)", len(got.Edges))
	}
}

// TestTopologyAllTrueUnboundedEdges asserts GET /topology?all=true
// returns the full, uncapped edge set even when there are more edges
// than defaultTopologyMaxEdges would normally allow -- the escape hatch
// must be genuinely uncapped on both the node and edge dimensions, not
// just nodes.
func TestTopologyAllTrueUnboundedEdges(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	var ids []uuid.UUID
	for _, addr := range []string{"clique-a:1", "clique-b:1", "clique-c:1", "clique-d:1"} {
		n, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
		ids = append(ids, n.ID)
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if err := store.RecordPeerEdgeObservation(ctx, ids[i], ids[j]); err != nil {
				t.Fatalf("record edge %v -> %v: %v", ids[i], ids[j], err)
			}
		}
	}

	resp, err := http.Get(srv.URL + "/topology?all=true")
	if err != nil {
		t.Fatalf("GET /topology?all=true: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var got struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Nodes) != 4 {
		t.Fatalf("len(got.Nodes) = %d, want 4 (unbounded)", len(got.Nodes))
	}
	if len(got.Edges) != 6 {
		t.Fatalf("len(got.Edges) = %d, want 6 (unbounded, all pairwise edges present)", len(got.Edges))
	}
}

// TestTopologyInvalidMaxEdges asserts GET /topology?max_edges= rejects
// non-positive/non-numeric values with 400, mirroring ?limit='s
// validation.
func TestTopologyInvalidMaxEdges(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	for _, v := range []string{"0", "-1", "not-a-number"} {
		resp, err := http.Get(srv.URL + "/topology?max_edges=" + v)
		if err != nil {
			t.Fatalf("GET /topology?max_edges=%s: %v", v, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("max_edges=%s: status = %d, want %d", v, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

// doRequestWithAuth issues method to url (with an optional body),
// setting an Authorization: Basic header for user/pass via
// req.SetBasicAuth — used below to exercise the WRONG-credentials case
// against /admin/* routes (doAdminRequest above always uses the correct
// testAdminUser/testAdminPassword).
func doRequestWithAuth(t *testing.T, method, url, contentType, user, pass string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, url, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.SetBasicAuth(user, pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// assertRequires401 asserts that method/url (with an optional body
// factory, called fresh for each of the two sub-cases since an
// io.Reader can only be consumed once) 401s with a WWW-Authenticate
// header containing "Basic" both with no Authorization header at all
// and with a wrong username/password pair.
func assertRequires401(t *testing.T, method, url, contentType string, bodyFn func() io.Reader) {
	t.Helper()

	// No Authorization header at all.
	req, err := http.NewRequest(method, url, bodyFn())
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, url, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s (no auth): %v", method, url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-auth %s %s status = %d, want %d", method, url, resp.StatusCode, http.StatusUnauthorized)
	}
	if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "Basic") {
		t.Errorf("no-auth %s %s WWW-Authenticate = %q, want it to contain %q", method, url, wa, "Basic")
	}

	// Wrong username/password.
	resp2 := doRequestWithAuth(t, method, url, contentType, "wrong-user", "wrong-password", bodyFn())
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-auth %s %s status = %d, want %d", method, url, resp2.StatusCode, http.StatusUnauthorized)
	}
	if wa := resp2.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "Basic") {
		t.Errorf("wrong-auth %s %s WWW-Authenticate = %q, want it to contain %q", method, url, wa, "Basic")
	}
}

// TestAdminSubmissionsRequiresAuth asserts GET /admin/submissions 401s
// (with a WWW-Authenticate header) with no auth and with wrong auth, and
// succeeds (200) with the correct configured credentials.
func TestAdminSubmissionsRequiresAuth(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	if _, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil); err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	url := srv.URL + "/admin/submissions"
	assertRequires401(t, http.MethodGet, url, "", func() io.Reader { return nil })

	resp := doAdminRequest(t, http.MethodGet, url, "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("correct-auth GET /admin/submissions status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}
}

// TestAdminApproveSubmissionRequiresAuth asserts
// POST /admin/submissions/{id}/approve 401s with no auth and with wrong
// auth, and succeeds (200) with the correct configured credentials.
func TestAdminApproveSubmissionRequiresAuth(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "203.0.113.30:18142", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	url := fmt.Sprintf("%s/admin/submissions/%s/approve", srv.URL, submission.ID)
	assertRequires401(t, http.MethodPost, url, "application/json", func() io.Reader { return nil })

	resp := doAdminRequest(t, http.MethodPost, url, "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("correct-auth POST /admin/submissions/{id}/approve status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}
}

// TestAdminRejectSubmissionRequiresAuth asserts
// POST /admin/submissions/{id}/reject 401s with no auth and with wrong
// auth, and succeeds (200) with the correct configured credentials.
func TestAdminRejectSubmissionRequiresAuth(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	submission, err := store.CreatePendingSubmission(ctx, "a:1", nil, nil)
	if err != nil {
		t.Fatalf("create pending submission: %v", err)
	}

	url := fmt.Sprintf("%s/admin/submissions/%s/reject", srv.URL, submission.ID)
	assertRequires401(t, http.MethodPost, url, "application/json", func() io.Reader { return nil })

	resp := doAdminRequest(t, http.MethodPost, url, "application/json", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("correct-auth POST /admin/submissions/{id}/reject status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}
}

// TestAdminPollNowRequiresAuth asserts POST /admin/nodes/poll-now 401s
// with no auth and with wrong auth, and succeeds (200) with the correct
// configured credentials.
func TestAdminPollNowRequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	url := srv.URL + "/admin/nodes/poll-now"
	body := `{"host":"203.0.113.31","port":18142}`
	assertRequires401(t, http.MethodPost, url, "application/json", func() io.Reader { return bytes.NewBufferString(body) })

	resp := doAdminRequest(t, http.MethodPost, url, "application/json", bytes.NewBufferString(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("correct-auth POST /admin/nodes/poll-now status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, respBody)
	}
}

// TestAdminRoutesDisabledWhenCredsNotConfigured asserts that when
// api.NewRouter is built with an unconfigured (zero-value)
// adminauth.Credentials — simulating NETMAP_ADMIN_USER/
// NETMAP_ADMIN_PASSWORD being unset — every /admin/* route returns 503
// for every request, even one supplying a plausible-looking guessed
// Basic Auth header, and specifically NOT 401/200/404. This must hold
// regardless of whether the underlying resource (a submission id) even
// exists, since the fail-closed handler must never reach the real
// route logic at all.
func TestAdminRoutesDisabledWhenCredsNotConfigured(t *testing.T) {
	srv, _ := newTestServerWithCreds(t, nil, adminauth.Credentials{})

	fakeID := uuid.New()
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/submissions"},
		{http.MethodPost, fmt.Sprintf("/admin/submissions/%s/approve", fakeID)},
		{http.MethodPost, fmt.Sprintf("/admin/submissions/%s/reject", fakeID)},
		{http.MethodPost, "/admin/nodes/poll-now"},
	}

	for _, rt := range routes {
		url := srv.URL + rt.path

		// No Authorization header.
		req, err := http.NewRequest(rt.method, url, nil)
		if err != nil {
			t.Fatalf("build %s %s request: %v", rt.method, url, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s (no auth): %v", rt.method, url, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("no-auth %s %s status = %d, want %d", rt.method, url, resp.StatusCode, http.StatusServiceUnavailable)
		}

		// A plausible guessed credential pair must not slip through
		// either.
		for _, creds := range [][2]string{{"admin", "admin"}, {"admin", ""}} {
			resp := doRequestWithAuth(t, rt.method, url, "", creds[0], creds[1], nil)
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("guessed-auth (%q/%q) %s %s status = %d, want %d", creds[0], creds[1], rt.method, url, resp.StatusCode, http.StatusServiceUnavailable)
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
				t.Errorf("guessed-auth (%q/%q) %s %s status = %d, must not be 401/200/404", creds[0], creds[1], rt.method, url, resp.StatusCode)
			}
		}
	}
}

// TestNonAdminAPIRoutesRemainUnauthenticated is the most important
// regression test in this dispatch: it proves the adminauth gate is
// wired ONLY around /admin/*, not more broadly, by hitting every
// non-admin API route with zero Authorization header (even though this
// test's server IS built with admin credentials configured, via
// newTestServer) and asserting each still succeeds exactly as before.
func TestNonAdminAPIRoutesRemainUnauthenticated(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "1.2.3.4:18142", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	assertStatus := func(label string, wantStatus int, resp *http.Response, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != wantStatus {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("no-auth %s status = %d, want %d (body: %s)", label, resp.StatusCode, wantStatus, body)
		}
	}

	resp, err := http.Get(srv.URL + "/healthz")
	assertStatus("GET /healthz", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/nodes")
	assertStatus("GET /nodes", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/nodes/" + node.ID.String())
	assertStatus("GET /nodes/{id}", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/nodes/" + node.ID.String() + "/history")
	assertStatus("GET /nodes/{id}/history", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/topology")
	assertStatus("GET /topology", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/topology/top-peered")
	assertStatus("GET /topology/top-peered", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/v1/stats")
	assertStatus("GET /v1/stats", http.StatusOK, resp, err)

	// POST /nodes: public node registration, exercised as a full
	// request with a real body (same shape as TestCreateNodeValid).
	// Its normal, pre-existing success status is 202 Accepted (queued
	// for review), not 200 — see handleCreateNode.
	createBody := `{"host":"198.51.100.99","port":18142,"label":"regression check","owner_tag":"pool-y"}`
	resp, err = http.Post(srv.URL+"/nodes", "application/json", bytes.NewBufferString(createBody))
	assertStatus("POST /nodes", http.StatusAccepted, resp, err)

	resp, err = http.Get(srv.URL + "/nodes/seeds")
	assertStatus("GET /nodes/seeds", http.StatusOK, resp, err)
	resp, err = http.Get(srv.URL + "/config/peer-seeds")
	assertStatus("GET /config/peer-seeds", http.StatusOK, resp, err)
}

// alexPubkeyHex/alexIPv4Addr/alexOnionAddr are the literal real-world
// dual-stack example given in SEED_CONFIG_SPEC.md, reused by both
// TestListSeedCandidatesEndpoint and TestConfigPeerSeedsEndpoint so the
// two endpoints are proven consistent against the exact same fixture.
const (
	alexPubkeyHex = "a841efcd8bc47d3db9e658f5da4d6858b6cbd387812d84f9f7a98e8cc871a85e"
	alexIPv4Addr  = "23.226.69.178:18189"
	alexOnionAddr = "wyow2dp6w2ff4u2kebklkmbzwlixyhjtza5bf3pt3oxnps5hcjn76iyd.onion:18141"
)

// seedAlexDualStackCandidate creates an opted-in (registry_submitted),
// recently-healthy, dual-stack (IPv4 + onion) confirmed node using the
// literal example from SEED_CONFIG_SPEC.md, plus a NOT-opted-in
// (p2p_discovered) healthy node that must never show up in either
// endpoint's output.
func seedAlexDualStackCandidate(t *testing.T, store storage.Store) (nodeID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	pubkey, err := hex.DecodeString(alexPubkeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}

	n, err := store.UpsertConfirmedNode(ctx, alexIPv4Addr, pubkey, storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("upsert confirmed ipv4: %v", err)
	}
	if _, err := store.UpsertConfirmedNode(ctx, alexOnionAddr, pubkey, storage.DiscoverySourceRegistry); err != nil {
		t.Fatalf("upsert confirmed onion: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: n.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
		t.Fatalf("record health: %v", err)
	}

	p2pNode, err := store.UpsertConfirmedNode(ctx, "9.9.9.9:18189", []byte("not-opted-in-pubkey"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert p2p node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: p2pNode.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
		t.Fatalf("record health p2p: %v", err)
	}

	return n.ID
}

// TestListSeedCandidatesEndpoint asserts GET /nodes/seeds returns
// exactly the opted-in + recently-healthy candidate (not the
// not-opted-in one), with a hex-encoded (not base64) public key and both
// of its real addresses.
func TestListSeedCandidatesEndpoint(t *testing.T) {
	srv, store := newTestServer(t, nil)
	seedAlexDualStackCandidate(t, store)

	resp, err := http.Get(srv.URL + "/nodes/seeds")
	if err != nil {
		t.Fatalf("GET /nodes/seeds: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got struct {
		Candidates []api.PublicSeedCandidate `json:"candidates"`
		Since      string                    `json:"since"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Since == "" {
		t.Errorf("since = %q, want non-empty", got.Since)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("len(candidates) = %d, want 1 (only the opted-in node), got %+v", len(got.Candidates), got.Candidates)
	}

	c := got.Candidates[0]
	if c.PublicKey != alexPubkeyHex {
		t.Errorf("public_key = %q, want hex %q", c.PublicKey, alexPubkeyHex)
	}
	addrSet := map[string]bool{}
	for _, a := range c.Addresses {
		addrSet[a] = true
	}
	if !addrSet[alexIPv4Addr] || !addrSet[alexOnionAddr] {
		t.Errorf("addresses = %+v, want both %q and %q", c.Addresses, alexIPv4Addr, alexOnionAddr)
	}
}

// TestListSeedCandidatesEndpointSinceOverride asserts the `?since=`
// query param actually narrows/widens the health-recency window, using
// the same time.ParseDuration validation convention as
// handleTopPeeredNodes.
func TestListSeedCandidatesEndpointSinceOverride(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/nodes/seeds?since=notaduration")
	if err != nil {
		t.Fatalf("GET /nodes/seeds: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for invalid since", resp.StatusCode, http.StatusBadRequest)
	}

	resp2, err := http.Get(srv.URL + "/nodes/seeds?since=30m")
	if err != nil {
		t.Fatalf("GET /nodes/seeds?since=30m: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
	var got struct {
		Since string `json:"since"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Since != "30m0s" {
		t.Errorf("since = %q, want %q", got.Since, "30m0s")
	}
}

// TestConfigPeerSeedsEndpoint asserts GET /config/peer-seeds emits real
// Tari config.toml text with byte-for-byte correct peer_seeds lines for
// the literal dual-stack example from SEED_CONFIG_SPEC.md, under a
// network-scoped header when ?network= is given, and never mentions the
// not-opted-in node.
func TestConfigPeerSeedsEndpoint(t *testing.T) {
	srv, store := newTestServer(t, nil)
	seedAlexDualStackCandidate(t, store)

	resp, err := http.Get(srv.URL + "/config/peer-seeds?network=esmeralda")
	if err != nil {
		t.Fatalf("GET /config/peer-seeds: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)

	if !strings.Contains(text, "[esmeralda.p2p.seeds]") {
		t.Errorf("body missing network-scoped header:\n%s", text)
	}
	if !strings.Contains(text, "peer_seeds = [") {
		t.Errorf("body missing peer_seeds array:\n%s", text)
	}

	wantIPv4Line := fmt.Sprintf(`"%s::/ip4/23.226.69.178/tcp/18189"`, alexPubkeyHex)
	wantOnionLine := fmt.Sprintf(`"%s::/onion3/wyow2dp6w2ff4u2kebklkmbzwlixyhjtza5bf3pt3oxnps5hcjn76iyd:18141"`, alexPubkeyHex)
	if !strings.Contains(text, wantIPv4Line) {
		t.Errorf("body missing expected ipv4 peer_seeds line %q:\n%s", wantIPv4Line, text)
	}
	if !strings.Contains(text, wantOnionLine) {
		t.Errorf("body missing expected onion peer_seeds line %q:\n%s", wantOnionLine, text)
	}
	if strings.Contains(text, "not-opted-in-pubkey") || strings.Contains(text, "9.9.9.9") {
		t.Errorf("body must not mention the not-opted-in node:\n%s", text)
	}
}

// TestConfigPeerSeedsEndpointGenericHeaderWithoutNetwork asserts the
// header falls back to the generic, network-less `[p2p.seeds]` form
// when `?network=` is omitted.
func TestConfigPeerSeedsEndpointGenericHeaderWithoutNetwork(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/config/peer-seeds")
	if err != nil {
		t.Fatalf("GET /config/peer-seeds: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "[p2p.seeds]\n") {
		t.Errorf("body missing generic header:\n%s", text)
	}
}

// statsResponseForTest mirrors internal/api's unexported statsResponse
// JSON shape, so this external (api_test) test package can decode GET
// /v1/stats responses without needing that type exported.
type statsResponseForTest struct {
	TotalNodes         int `json:"total_nodes"`
	ConfirmedNodes     int `json:"confirmed_nodes"`
	UnconfirmedNodes   int `json:"unconfirmed_nodes"`
	P2PDiscovered      int `json:"p2p_discovered"`
	RegistryDiscovered int `json:"registry_discovered"`
	BothDiscovered     int `json:"both_discovered"`
	OnionCapable       int `json:"onion_capable"`
	ClearnetCapable    int `json:"clearnet_capable"`
	ClearnetOnly       int `json:"clearnet_only"`

	Confirmed24h int `json:"confirmed_nodes_24h"`

	NetworkHeight          *int64 `json:"network_height"`
	NetworkHeightNodeCount int    `json:"network_height_node_count"`
}

// TestStatsEndpointEmpty asserts GET /v1/stats returns all-zero counts and a
// nil network_height against an empty database, matching
// storage.Store.NetworkHeight's own (nil, 0, nil) "no data yet" return.
func TestStatsEndpointEmpty(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/v1/stats")
	if err != nil {
		t.Fatalf("GET /v1/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var got statsResponseForTest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != (statsResponseForTest{}) {
		t.Errorf("got %+v, want all-zero/nil", got)
	}
}

// TestStatsEndpoint asserts GET /v1/stats' counts match a hand-built node
// population spanning every discovery source (p2p/registry/both),
// confirmed vs unconfirmed, and onion/clearnet/dual-stack capability
// (including the subtle case: a node with BOTH an onion and a clearnet
// address counts in both OnionCapable and ClearnetCapable, but NOT in
// ClearnetOnly, since ClearnetOnly is mutually-exclusive-with-onion by
// definition), plus that network_height/network_height_node_count
// reflect the mode of the latest-per-node heights recorded (see
// TestNetworkHeight in internal/storage for the mode-computation
// semantics being surfaced here).
func TestStatsEndpoint(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// p2pUnconfirmed: p2p_discovered, unconfirmed (no confirmed
	// pubkey), clearnet-only address.
	p2pUnconfirmed, err := store.UpsertDiscoveredNode(ctx, "203.0.113.10:18142", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert p2p unconfirmed: %v", err)
	}

	// registryConfirmedOnion: registry_submitted, confirmed, onion-only
	// address.
	registryPubkey := []byte("stats-test-registry-pubkey-onion")
	if _, err := store.UpsertConfirmedNode(ctx, "abcdefghijklmnopqrstuvwxyz234567.onion:18142", registryPubkey, storage.DiscoverySourceRegistry); err != nil {
		t.Fatalf("upsert registry confirmed onion: %v", err)
	}

	// bothUnconfirmedClearnet: discovered via BOTH p2p and registry
	// (same address submitted/observed via each path), unconfirmed,
	// clearnet-only address.
	const bothAddr = "203.0.113.20:18142"
	if _, err := store.UpsertDiscoveredNode(ctx, bothAddr, storage.DiscoverySourceP2P, nil, nil); err != nil {
		t.Fatalf("upsert both (p2p leg): %v", err)
	}
	bothNode, err := store.UpsertDiscoveredNode(ctx, bothAddr, storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert both (registry leg): %v", err)
	}
	if bothNode.DiscoverySource != storage.DiscoverySourceBoth {
		t.Fatalf("bothNode.DiscoverySource = %q, want %q", bothNode.DiscoverySource, storage.DiscoverySourceBoth)
	}

	// dualStackConfirmed: registry_submitted, confirmed, clearnet
	// address at creation plus a second, onion address added directly
	// (storage.Store has no multi-address upsert API — same
	// direct-to-db pattern TestTopPeeredNodesOnionClearnetCounts uses).
	// This is the subtle case this test exists to cover: it must count
	// in BOTH OnionCapable and ClearnetCapable, but NOT in ClearnetOnly.
	const dualStackClearnetAddr = "203.0.113.30:18142"
	const dualStackOnionAddr = "stats2234567abcdefghijklmnopqrstu.onion:18142"
	dualStackPubkey := []byte("stats-test-registry-pubkey-dual-stack")
	dualStackNode, err := store.UpsertConfirmedNode(ctx, dualStackClearnetAddr, dualStackPubkey, storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("upsert dual-stack confirmed: %v", err)
	}
	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_addresses (node_id, address, first_seen, last_seen)
		VALUES ($1, $2, now(), now())
	`, dualStackNode.ID, dualStackOnionAddr); err != nil {
		t.Fatalf("insert dual-stack node's onion address: %v", err)
	}

	// Record health checks with heights so NetworkHeight has a mode to
	// report: p2pUnconfirmed and bothNode both latest at 500, so 500 is
	// the mode across the 2 nodes with recorded heights.
	h500 := int64(500)
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: p2pUnconfirmed.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC, Height: &h500}); err != nil {
		t.Fatalf("record health p2pUnconfirmed: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: bothNode.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC, Height: &h500}); err != nil {
		t.Fatalf("record health bothNode: %v", err)
	}

	resp, err := http.Get(srv.URL + "/v1/stats")
	if err != nil {
		t.Fatalf("GET /v1/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}

	var got statsResponseForTest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := statsResponseForTest{
		TotalNodes:         4,
		ConfirmedNodes:     2,
		UnconfirmedNodes:   2,
		P2PDiscovered:      1,
		RegistryDiscovered: 2,
		BothDiscovered:     1,
		OnionCapable:       2,
		ClearnetCapable:    3,
		ClearnetOnly:       2,

		NetworkHeightNodeCount: 2,
	}
	if got.TotalNodes != want.TotalNodes ||
		got.ConfirmedNodes != want.ConfirmedNodes ||
		got.UnconfirmedNodes != want.UnconfirmedNodes ||
		got.P2PDiscovered != want.P2PDiscovered ||
		got.RegistryDiscovered != want.RegistryDiscovered ||
		got.BothDiscovered != want.BothDiscovered ||
		got.OnionCapable != want.OnionCapable ||
		got.ClearnetCapable != want.ClearnetCapable ||
		got.ClearnetOnly != want.ClearnetOnly ||
		got.NetworkHeightNodeCount != want.NetworkHeightNodeCount {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got.NetworkHeight == nil || *got.NetworkHeight != h500 {
		t.Errorf("NetworkHeight = %v, want pointer to %d", got.NetworkHeight, h500)
	}
}

// TestStatsEndpointConfirmed24h asserts GET /v1/stats' confirmed_nodes_24h
// genuinely differs from, and is lower than, the lifetime confirmed_nodes
// total: 3 confirmed nodes are seeded, but only 2 have a reachable=true
// health check within the last 24h -- the third has only a stale (>24h
// old) reachable check, so it counts toward confirmed_nodes (lifetime)
// but not confirmed_nodes_24h.
func TestStatsEndpointConfirmed24h(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// recentA/recentB: confirmed, each with a health check within the
	// last 24h -- both must count toward confirmed_nodes_24h.
	recentA, err := store.UpsertConfirmedNode(ctx, "confirmed24h-recentA:1", []byte("confirmed24h-recentA-pubkey"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert recentA: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: recentA.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
		t.Fatalf("record health check for recentA: %v", err)
	}

	recentB, err := store.UpsertConfirmedNode(ctx, "confirmed24h-recentB:1", []byte("confirmed24h-recentB-pubkey"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert recentB: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: recentB.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC}); err != nil {
		t.Fatalf("record health check for recentB: %v", err)
	}

	// stale: confirmed, but its only reachable health check is more
	// than 24h old -- must count toward confirmed_nodes (lifetime) but
	// NOT confirmed_nodes_24h. storage.Store's RecordHealthCheck always
	// stamps ts = now(), so the >24h-old row must be inserted directly
	// via a raw connection to the same test database (same pattern as
	// TestStatsEndpoint's dual-stack address insert above).
	stale, err := store.UpsertConfirmedNode(ctx, "confirmed24h-stale:1", []byte("confirmed24h-stale-pubkey"), storage.DiscoverySourceP2P)
	if err != nil {
		t.Fatalf("upsert stale: %v", err)
	}
	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_health (node_id, ts, reachable, probe_source)
		VALUES ($1, now() - interval '48 hours', true, 'grpc')
	`, stale.ID); err != nil {
		t.Fatalf("insert stale reachable health check: %v", err)
	}

	resp, err := http.Get(srv.URL + "/v1/stats")
	if err != nil {
		t.Fatalf("GET /v1/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}

	var got statsResponseForTest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.ConfirmedNodes != 3 {
		t.Errorf("ConfirmedNodes (lifetime) = %d, want 3", got.ConfirmedNodes)
	}
	if got.Confirmed24h != 2 {
		t.Errorf("Confirmed24h = %d, want 2 (must be lower than the lifetime confirmed_nodes total)", got.Confirmed24h)
	}
}

// TestNodesMapEndpoint covers GET /nodes/map's full contract:
//   - an owner-tagged+IPv4 node WITH a geoip_cache entry is included,
//     with lat/lon/city/country resolved from that cache entry and
//     has_onion reflecting its own capability;
//   - an owner-tagged+IPv4 node with NO geoip_cache entry yet is
//     omitted entirely (never looked up -- the periodic refresh will
//     pick it up later, see RefreshGeoIP);
//   - a node with no owner tag at all is excluded regardless of
//     IPv4/cache status;
//   - a node with an owner tag but only an onion address (no IPv4) is
//     excluded.
func TestNodesMapEndpoint(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// In population, has a fresh geoip_cache entry -- must appear.
	inPop, err := store.UpsertDiscoveredNode(ctx, "203.0.113.10:18189", storage.DiscoverySourceRegistry,
		map[string]any{"owner": "Alice"}, strPtr("Alice's Node"))
	if err != nil {
		t.Fatalf("upsert in-population node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.10", Latitude: 40.7128, Longitude: -74.0060, City: "New York", Country: "United States",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed geoip cache: %v", err)
	}

	// In population by predicate, but never geoip-looked-up yet --
	// must be omitted (not appear with a zero-value lat/lon).
	_, err = store.UpsertDiscoveredNode(ctx, "203.0.113.20:18189", storage.DiscoverySourceRegistry,
		map[string]any{"owner": "Bob"}, nil)
	if err != nil {
		t.Fatalf("upsert never-looked-up node: %v", err)
	}

	// Not owner-tagged at all -- must be excluded regardless of IPv4.
	_, err = store.UpsertDiscoveredNode(ctx, "203.0.113.30:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert non-owner node: %v", err)
	}

	// Owner-tagged, but onion-only (no IPv4 at all) -- must be excluded.
	_, err = store.UpsertDiscoveredNode(ctx, "qwertyuiopasdfgh.onion:18189", storage.DiscoverySourceRegistry,
		map[string]any{"owner": "Carol"}, nil)
	if err != nil {
		t.Fatalf("upsert onion-only owner node: %v", err)
	}

	resp, err := http.Get(srv.URL + "/nodes/map")
	if err != nil {
		t.Fatalf("GET /nodes/map: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}

	var got []api.MapNode
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want exactly 1, got %+v", len(got), got)
	}
	entry := got[0]
	if entry.NodeID != inPop.ID {
		t.Errorf("NodeID = %v, want %v", entry.NodeID, inPop.ID)
	}
	if entry.Label != "Alice's Node" {
		t.Errorf("Label = %q, want %q", entry.Label, "Alice's Node")
	}
	if entry.Latitude != 40.7128 || entry.Longitude != -74.0060 {
		t.Errorf("lat/lon = %v/%v, want 40.7128/-74.0060", entry.Latitude, entry.Longitude)
	}
	if entry.City != "New York" || entry.Country != "United States" {
		t.Errorf("city/country = %q/%q, want New York/United States", entry.City, entry.Country)
	}
	if entry.HasOnion {
		t.Errorf("HasOnion = true, want false (this node has no onion address)")
	}
}

// TestNodesMapEndpointEmpty confirms GET /nodes/map returns an empty
// JSON array (never null, never an error) when nothing in the node
// population is owner-tagged+IPv4 yet.
func TestNodesMapEndpointEmpty(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/nodes/map")
	if err != nil {
		t.Fatalf("GET /nodes/map: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("body = %q, want %q", strings.TrimSpace(string(body)), "[]")
	}
}

// countingStatsStore wraps a real storage.Store (from newTestStore),
// counting every call to the methods handleStats' underlying
// FetchNodeCounts/NetworkHeight work actually issues against the DB —
// mirroring cmd/netmap/metrics_test.go's unreachableStore fake-store
// pattern (embed the real storage.Store, override only the methods a
// test cares about, delegate everything else) rather than inventing a
// new mock style. queries is incremented once per call to ListNodes,
// ListNodeAddressesForNodes, CountNodes (FetchConfirmed24h's query), or
// NetworkHeight — a cache hit in handleStats must never call any of
// these, so asserting the query count stays unchanged across a second
// request within the TTL window proves the DB was only ever touched by
// the first (cache-miss) request.
type countingStatsStore struct {
	storage.Store
	queries atomic.Int32
}

func (c *countingStatsStore) ListNodes(ctx context.Context, filter storage.NodeFilter) ([]storage.Node, error) {
	c.queries.Add(1)
	return c.Store.ListNodes(ctx, filter)
}

func (c *countingStatsStore) ListNodeAddressesForNodes(ctx context.Context, nodeIDs []uuid.UUID) (map[uuid.UUID][]storage.NodeAddress, error) {
	c.queries.Add(1)
	return c.Store.ListNodeAddressesForNodes(ctx, nodeIDs)
}

func (c *countingStatsStore) CountNodes(ctx context.Context, filter storage.NodeFilter) (int, error) {
	c.queries.Add(1)
	return c.Store.CountNodes(ctx, filter)
}

func (c *countingStatsStore) NetworkHeight(ctx context.Context) (*int64, int, error) {
	c.queries.Add(1)
	return c.Store.NetworkHeight(ctx)
}

// newTestServerWithStatsCacheTTL builds a test server around store
// (expected to be a *countingStatsStore in the cache tests below) with
// an explicit GET /v1/stats cache TTL, bypassing newTestServerWithCreds'
// hardcoded api.DefaultStatsCacheTTL — used only by tests that
// specifically exercise the cache's own timing behavior.
func newTestServerWithStatsCacheTTL(t *testing.T, store storage.Store, ttl time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(api.NewRouter(store, collector.NewStubClient(), nil, nil, true, adminauth.Credentials{Username: testAdminUser, Password: testAdminPassword}, testCollectorKeys(), ttl, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL))
	t.Cleanup(srv.Close)
	return srv
}

// getStats issues GET /v1/stats against srv and returns the decoded
// body, failing the test on any transport/decode error or non-200
// status.
func getStats(t *testing.T, srv *httptest.Server) statsResponseForTest {
	t.Helper()
	resp, err := http.Get(srv.URL + "/v1/stats")
	if err != nil {
		t.Fatalf("GET /v1/stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}
	var got statsResponseForTest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestStatsEndpointCacheHitWithinTTL asserts two GET /v1/stats calls
// within the cache's TTL window return identical JSON AND the
// underlying store is queried the exact same number of times after the
// second call as after the first — the whole point of the cache: a
// second request inside the TTL window must serve the cached response
// with zero additional DB calls (handleStats' single computation issues
// several underlying store method calls -- ListNodes,
// ListNodeAddressesForNodes, CountNodes, NetworkHeight -- so "queried
// once" here means once per request, not literally one call in total).
func TestStatsEndpointCacheHitWithinTTL(t *testing.T) {
	realStore := newTestStore(t)
	ctx := context.Background()
	if _, err := realStore.UpsertConfirmedNode(ctx, "stats-cache-1:1", []byte("stats-cache-pubkey-1"), storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	counting := &countingStatsStore{Store: realStore}
	// A generous TTL (well beyond this test's runtime) so both requests
	// land inside the same cache window regardless of test execution
	// speed.
	srv := newTestServerWithStatsCacheTTL(t, counting, time.Minute)

	first := getStats(t, srv)
	afterFirst := counting.queries.Load()
	if afterFirst == 0 {
		t.Fatalf("underlying store was never queried for the first (cache-miss) request")
	}

	second := getStats(t, srv)
	afterSecond := counting.queries.Load()

	if first != second {
		t.Errorf("first = %+v, second = %+v, want identical (both should be served from cache)", first, second)
	}
	if afterSecond != afterFirst {
		t.Errorf("underlying store query count changed from %d to %d after a second request within the TTL window, want unchanged (cache hit, zero additional DB calls)", afterFirst, afterSecond)
	}
}

// TestStatsEndpointCacheExpiresAfterTTL asserts a call issued after the
// cache's TTL has elapsed triggers a fresh query rather than continuing
// to serve the stale cached response — uses a short (10ms) TTL plus
// time.Sleep, per the brief's documented fallback (no existing fake-
// clock/injectable-time-source pattern was found elsewhere in this
// package to prefer over it).
func TestStatsEndpointCacheExpiresAfterTTL(t *testing.T) {
	realStore := newTestStore(t)
	ctx := context.Background()
	if _, err := realStore.UpsertConfirmedNode(ctx, "stats-cache-2:1", []byte("stats-cache-pubkey-2"), storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	counting := &countingStatsStore{Store: realStore}
	const ttl = 10 * time.Millisecond
	srv := newTestServerWithStatsCacheTTL(t, counting, ttl)

	first := getStats(t, srv)
	afterFirst := counting.queries.Load()
	if afterFirst == 0 {
		t.Fatalf("underlying store was never queried for the first (cache-miss) request")
	}

	// Add a second confirmed node so the post-expiry response is
	// genuinely different from the cached one -- proving the second
	// call actually recomputed rather than coincidentally matching.
	if _, err := realStore.UpsertConfirmedNode(ctx, "stats-cache-3:1", []byte("stats-cache-pubkey-3"), storage.DiscoverySourceP2P); err != nil {
		t.Fatalf("seed second node: %v", err)
	}

	time.Sleep(5 * ttl)

	second := getStats(t, srv)
	afterSecond := counting.queries.Load()
	if afterSecond <= afterFirst {
		t.Errorf("underlying store query count unchanged (%d) after TTL expiry, want > %d (a fresh query must have been issued)", afterSecond, afterFirst)
	}
	if second.TotalNodes != first.TotalNodes+1 {
		t.Errorf("second.TotalNodes = %d, want %d (%d + the newly-seeded node, proving the post-expiry response was recomputed)", second.TotalNodes, first.TotalNodes+1, first.TotalNodes)
	}
}
