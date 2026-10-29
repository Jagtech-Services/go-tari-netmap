package api_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// doCollectorReportRequest POSTs body to srv's /internal/collectors/report route with the
// given X-Collector-Key header value (empty means "send no header at all").
func doCollectorReportRequest(t *testing.T, srv string, key, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv+"/internal/collectors/report", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Collector-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /internal/collectors/report: %v", err)
	}
	return resp
}

// TestCollectorReportRequiresValidKey asserts the endpoint rejects a request with no
// X-Collector-Key header, and one with a key that doesn't match any configured collector,
// both with 401 -- and never applies any write in either case.
func TestCollectorReportRequiresValidKey(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	body := `{"self_identity":["203.0.113.9:18189"],"confirmed_nodes":[],"discovered_nodes":[],"health_checks":[],"peer_edges":[]}`

	resp := doCollectorReportRequest(t, srv.URL, "", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no key: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	resp2 := doCollectorReportRequest(t, srv.URL, "not-the-configured-key", body)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong key: status = %d, want %d", resp2.StatusCode, http.StatusUnauthorized)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("len(nodes) = %d, want 0 (unauthorized requests must never apply writes)", len(nodes))
	}
}

// TestCollectorReportDisabledWhenUnconfigured asserts that with an empty collector-keys map
// (NETMAP_COLLECTOR_KEYS unset, mirroring adminauth's own fail-closed convention), the route
// unconditionally 503s -- even with what would otherwise be a valid key.
func TestCollectorReportDisabledWhenUnconfigured(t *testing.T) {
	store := newTestStore(t)
	srv := httptest.NewServer(api.NewRouter(t.Context(), store, nil, nil, nil, true, adminauth.Credentials{Username: testAdminUser, Password: testAdminPassword}, nil, api.DefaultStatsCacheTTL, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL))
	t.Cleanup(srv.Close)

	body := `{"self_identity":[],"confirmed_nodes":[],"discovered_nodes":[],"health_checks":[],"peer_edges":[]}`
	resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// TestCollectorReportAppliesBatch is the end-to-end happy path: a full batch (self_identity,
// confirmed_nodes, discovered_nodes, health_checks referencing both a confirmed_nodes address
// and a brand-new address, and a peer_edges pair) is applied via the exact same storage.Store
// methods the local collector/responder use, and self_identity tagging lands on exactly the
// right node and nothing else.
func TestCollectorReportAppliesBatch(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const (
		selfAddr       = "203.0.113.9:18189"
		confirmedAddr  = "198.51.100.7:18189"
		discoveredAddr = "198.51.100.8:18189"
		pubkeyHex      = "aa" + "bb"
	)
	if _, err := hex.DecodeString(pubkeyHex); err != nil {
		t.Fatalf("decode pubkey fixture: %v", err)
	}

	reqBody := map[string]any{
		"self_identity": []string{selfAddr},
		"confirmed_nodes": []map[string]any{
			{"address": confirmedAddr, "public_key": pubkeyHex, "discovery_source": "p2p_discovered"},
		},
		"discovered_nodes": []map[string]any{
			{"address": discoveredAddr},
		},
		"health_checks": []map[string]any{
			{"address": confirmedAddr, "reachable": true, "probe_source": "p2p"},
			{"address": discoveredAddr, "reachable": false, "probe_source": "p2p"},
		},
		"peer_edges": []map[string]any{
			{"from_address": confirmedAddr, "to_address": discoveredAddr},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, string(raw))
	defer resp.Body.Close()
	body, _ := readAllForTest(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, body)
	}

	var got struct {
		ConfirmedNodesApplied  int `json:"confirmed_nodes_applied"`
		DiscoveredNodesApplied int `json:"discovered_nodes_applied"`
		HealthChecksApplied    int `json:"health_checks_applied"`
		PeerEdgesApplied       int `json:"peer_edges_applied"`
		SelfIdentityTagged     int `json:"self_identity_tagged"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response %s: %v", body, err)
	}
	if got.ConfirmedNodesApplied != 1 || got.DiscoveredNodesApplied != 1 || got.HealthChecksApplied != 2 || got.PeerEdgesApplied != 1 || got.SelfIdentityTagged != 1 {
		t.Fatalf("unexpected counts: %+v", got)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	byAddress := make(map[string]storage.Node, len(nodes))
	for _, n := range nodes {
		byAddress[n.Address] = n
	}

	confirmed, ok := byAddress[confirmedAddr]
	if !ok {
		t.Fatalf("confirmed node %s not found", confirmedAddr)
	}
	if hex.EncodeToString(confirmed.PublicKey) != pubkeyHex {
		t.Errorf("confirmed node public key = %x, want %s", confirmed.PublicKey, pubkeyHex)
	}
	if _, tagged := confirmed.Tags["role"]; tagged {
		t.Errorf("confirmed node must NOT be tagged role=collector, tags=%v", confirmed.Tags)
	}

	discovered, ok := byAddress[discoveredAddr]
	if !ok {
		t.Fatalf("discovered node %s not found", discoveredAddr)
	}
	if _, tagged := discovered.Tags["role"]; tagged {
		t.Errorf("discovered node must NOT be tagged role=collector, tags=%v", discovered.Tags)
	}

	self, ok := byAddress[selfAddr]
	if !ok {
		t.Fatalf("self-identity node %s not found", selfAddr)
	}
	if role, _ := self.Tags["role"].(string); role != "collector" {
		t.Errorf("self-identity node tags[role] = %v, want %q", self.Tags["role"], "collector")
	}

	history, err := store.GetNodeHistory(ctx, confirmed.ID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(history) != 1 || !history[0].Reachable {
		t.Fatalf("confirmed node history = %+v, want exactly one reachable=true entry", history)
	}

	edges, err := store.ListNodeEdges(ctx, confirmed.ID, 10)
	if err != nil {
		t.Fatalf("list node edges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("len(edges) = %d, want 1", len(edges))
	}
}

// TestCollectorReportMalformedPayloadRejected400 asserts a variety of malformed payloads are
// rejected with 400, not 500, and never apply any write.
func TestCollectorReportMalformedPayloadRejected400(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"invalid json", `{not valid json`},
		{"missing confirmed address", `{"confirmed_nodes":[{"public_key":"aabb","discovery_source":"p2p_discovered"}]}`},
		{"invalid hex pubkey", `{"confirmed_nodes":[{"address":"1.2.3.4:1","public_key":"not-hex","discovery_source":"p2p_discovered"}]}`},
		{"invalid discovery_source", `{"confirmed_nodes":[{"address":"1.2.3.4:1","public_key":"aabb","discovery_source":"bogus"}]}`},
		{"missing discovered address", `{"discovered_nodes":[{}]}`},
		{"invalid probe_source", `{"health_checks":[{"address":"1.2.3.4:1","probe_source":"bogus"}]}`},
		{"missing peer edge address", `{"peer_edges":[{"from_address":"1.2.3.4:1"}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, store := newTestServer(t, nil)
			ctx := context.Background()

			resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				body, _ := readAllForTest(t, resp)
				t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, body)
			}

			nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
			if err != nil {
				t.Fatalf("list nodes: %v", err)
			}
			if len(nodes) != 0 {
				t.Fatalf("len(nodes) = %d, want 0 (malformed batch must not partially apply)", len(nodes))
			}
		})
	}
}

// TestSeedsAndTopologyExcludeCollectorRoleTaggedNode asserts every recommendation route
// filters out a role=collector-tagged node, while leaving GET /nodes (plain listing) showing
// it -- exercising GET /nodes/seeds, GET /nodes/seed_list, GET /config/peer-seeds, GET
// /nodes/seed_list_tari, GET /topology, and GET /topology/top-peered in one fixture.
func TestSeedsAndTopologyExcludeCollectorRoleTaggedNode(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const collectorAddr = "192.0.2.50:18189"
	pubkey := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	collectorNode, err := store.UpsertConfirmedNode(ctx, collectorAddr, pubkey, storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("upsert confirmed collector node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: collectorNode.ID, Reachable: true, ProbeSource: storage.ProbeSourceP2P}); err != nil {
		t.Fatalf("record health check: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, collectorAddr, storage.DiscoverySourceRegistry, map[string]any{"role": "collector"}, nil); err != nil {
		t.Fatalf("tag collector node: %v", err)
	}

	// A normal, non-collector node also opted-in/reachable, plus a peer edge between the
	// two so the topology test can assert the edge is dropped alongside the node.
	const normalAddr = "192.0.2.51:18189"
	normalNode, err := store.UpsertConfirmedNode(ctx, normalAddr, []byte{0x01, 0x02, 0x03, 0x04}, storage.DiscoverySourceRegistry)
	if err != nil {
		t.Fatalf("upsert confirmed normal node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{NodeID: normalNode.ID, Reachable: true, ProbeSource: storage.ProbeSourceP2P}); err != nil {
		t.Fatalf("record health check: %v", err)
	}
	if err := store.RecordPeerEdgeObservation(ctx, normalNode.ID, collectorNode.ID); err != nil {
		t.Fatalf("record peer edge: %v", err)
	}

	assertBodyExcludes := func(url, mustNotContain, mustContain string) {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := readAllForTest(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, body=%s", url, resp.StatusCode, body)
		}
		if strings.Contains(string(body), mustNotContain) {
			t.Errorf("GET %s: body unexpectedly contains %q:\n%s", url, mustNotContain, body)
		}
		if mustContain != "" && !strings.Contains(string(body), mustContain) {
			t.Errorf("GET %s: body missing expected %q:\n%s", url, mustContain, body)
		}
	}

	for _, path := range []string{"/nodes/seeds", "/nodes/seed_list"} {
		assertBodyExcludes(srv.URL+path, collectorAddr, normalAddr)
	}
	for _, path := range []string{"/config/peer-seeds", "/nodes/seed_list_tari"} {
		assertBodyExcludes(srv.URL+path, "192.0.2.50", "/ip4/192.0.2.51/tcp/18189")
	}

	// GET /topology must exclude the collector node's id (its address is never in the
	// scrubbed response body anyway for a p2p-only view, so assert on node count/edges via
	// decoded JSON instead of a raw substring check).
	resp, err := http.Get(srv.URL + "/topology")
	if err != nil {
		t.Fatalf("GET /topology: %v", err)
	}
	defer resp.Body.Close()
	var topo struct {
		Nodes []api.PublicNode   `json:"nodes"`
		Edges []storage.PeerEdge `json:"edges"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&topo); err != nil {
		t.Fatalf("decode topology: %v", err)
	}
	for _, n := range topo.Nodes {
		if n.ID == collectorNode.ID {
			t.Errorf("topology nodes unexpectedly include role=collector node %s", n.ID)
		}
	}
	for _, e := range topo.Edges {
		if e.FromNodeID == collectorNode.ID || e.ToNodeID == collectorNode.ID {
			t.Errorf("topology edges unexpectedly reference role=collector node %s: %+v", collectorNode.ID, e)
		}
	}

	// GET /topology/top-peered must likewise exclude it.
	respTP, err := http.Get(srv.URL + "/topology/top-peered")
	if err != nil {
		t.Fatalf("GET /topology/top-peered: %v", err)
	}
	defer respTP.Body.Close()
	var degrees []api.PublicNodeDegree
	if err := json.NewDecoder(respTP.Body).Decode(&degrees); err != nil {
		t.Fatalf("decode top-peered: %v", err)
	}
	for _, d := range degrees {
		if d.NodeID == collectorNode.ID {
			t.Errorf("top-peered unexpectedly includes role=collector node %s", collectorNode.ID)
		}
	}

	// GET /nodes (plain listing) must still show it -- this filter must NOT apply there.
	respNodes, err := http.Get(srv.URL + "/nodes?limit=500")
	if err != nil {
		t.Fatalf("GET /nodes: %v", err)
	}
	defer respNodes.Body.Close()
	var listed struct {
		Nodes []api.PublicNode `json:"nodes"`
	}
	if err := json.NewDecoder(respNodes.Body).Decode(&listed); err != nil {
		t.Fatalf("decode /nodes: %v", err)
	}
	found := false
	for _, n := range listed.Nodes {
		if n.ID == collectorNode.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("GET /nodes must still list the role=collector node (plain listing routes are out of scope for this filter)")
	}
}

// TestCollectorReportForcesDiscoverySourceToP2P proves Fix 6(a): a collector report claiming
// discovery_source=registry_submitted for a confirmed node, combined with a reachable=true
// health check in the same batch, must NOT mint a fully opted-in seed candidate -- the central
// handler must force discovery_source to p2p_discovered regardless of what the report claims,
// so the node never appears in ListSeedCandidates without going through the same
// pending_submissions review gate the public POST /nodes path uses.
func TestCollectorReportForcesDiscoverySourceToP2P(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const addr = "198.51.100.220:18189"
	const pubkeyHex = "aabbccdd"

	reqBody := map[string]any{
		"confirmed_nodes": []map[string]any{
			{"address": addr, "public_key": pubkeyHex, "discovery_source": "registry_submitted"},
		},
		"health_checks": []map[string]any{
			{"address": addr, "reachable": true, "probe_source": "p2p"},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, string(raw))
	defer resp.Body.Close()
	body, _ := readAllForTest(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, body)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	var got storage.Node
	found := false
	for _, n := range nodes {
		if n.Address == addr {
			got, found = n, true
		}
	}
	if !found {
		t.Fatalf("node %s not found", addr)
	}
	if got.DiscoverySource != storage.DiscoverySourceP2P {
		t.Errorf("discovery_source = %q, want %q (must be forced regardless of the claimed value)", got.DiscoverySource, storage.DiscoverySourceP2P)
	}

	candidates, err := store.ListSeedCandidates(ctx, storage.DefaultSeedHealthWindow)
	if err != nil {
		t.Fatalf("list seed candidates: %v", err)
	}
	for _, c := range candidates {
		if c.NodeID == got.ID {
			t.Errorf("node %s (%s) unexpectedly appears in ListSeedCandidates -- a collector report must never mint an opted-in seed candidate without human review", got.ID, addr)
		}
	}
}

// TestCollectorReportRejectsPrivateReservedAddresses proves Fix 6(b): every address field in
// a collector report (self_identity and every "observed" address) is rejected with 400 -- not
// silently accepted -- when it's a private/loopback/reserved IP, mirroring
// validate_test.go's existing coverage for the public POST /nodes path. No write is applied
// for any of these malformed-per-trust-boundary payloads.
func TestCollectorReportRejectsPrivateReservedAddresses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"self_identity loopback", `{"self_identity":["127.0.0.1:18189"]}`},
		{"self_identity private RFC1918", `{"self_identity":["192.168.1.5:18189"]}`},
		{"confirmed_nodes address private", `{"confirmed_nodes":[{"address":"10.0.0.5:18189","public_key":"aabb","discovery_source":"p2p_discovered"}]}`},
		{"discovered_nodes address loopback", `{"discovered_nodes":[{"address":"127.0.0.1:18189"}]}`},
		{"health_checks address link-local", `{"health_checks":[{"address":"169.254.1.1:18189","reachable":true,"probe_source":"p2p"}]}`},
		{"peer_edges from_address private", `{"peer_edges":[{"from_address":"10.1.2.3:18189","to_address":"198.51.100.1:18189"}]}`},
		{"peer_edges to_address private", `{"peer_edges":[{"from_address":"198.51.100.1:18189","to_address":"172.16.0.1:18189"}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, store := newTestServer(t, nil)
			ctx := context.Background()

			resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				body, _ := readAllForTest(t, resp)
				t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusBadRequest, body)
			}

			nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
			if err != nil {
				t.Fatalf("list nodes: %v", err)
			}
			if len(nodes) != 0 {
				t.Fatalf("len(nodes) = %d, want 0 (a private/reserved address must reject the whole batch, not partially apply)", len(nodes))
			}
		})
	}
}

// TestCollectorReportSelfIdentityRequiresAllowlistedAddress proves Fix 6(c): a self_identity
// address NOT present in the authenticated collector's configured SelfAddresses allowlist is
// skipped (not tagged role=collector), while the rest of an otherwise-valid batch still
// applies successfully (200, not 400/500) -- self_identity tagging is constrained to
// addresses the operator has independently confirmed this collector controls, it cannot mint
// arbitrary role=collector suppression.
func TestCollectorReportSelfIdentityRequiresAllowlistedAddress(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// NOT in testCollectorSelfAddresses -- see api_test.go.
	const disallowedAddr = "203.0.113.99:18189"
	const discoveredAddr = "198.51.100.230:18189"

	reqBody := map[string]any{
		"self_identity": []string{disallowedAddr},
		"discovered_nodes": []map[string]any{
			{"address": discoveredAddr},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, string(raw))
	defer resp.Body.Close()
	body, _ := readAllForTest(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, body)
	}

	var got struct {
		DiscoveredNodesApplied int `json:"discovered_nodes_applied"`
		SelfIdentityTagged     int `json:"self_identity_tagged"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response %s: %v", body, err)
	}
	if got.DiscoveredNodesApplied != 1 {
		t.Errorf("discovered_nodes_applied = %d, want 1 (rest of the batch must still apply)", got.DiscoveredNodesApplied)
	}
	if got.SelfIdentityTagged != 0 {
		t.Errorf("self_identity_tagged = %d, want 0 (disallowed address must not be tagged)", got.SelfIdentityTagged)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	for _, n := range nodes {
		if n.Address == disallowedAddr {
			if role, _ := n.Tags["role"].(string); role == "collector" {
				t.Errorf("disallowed self_identity address %s was tagged role=collector despite not being in the collector's configured allowlist", disallowedAddr)
			}
		}
	}
}

// TestCollectorReportRecordsAttribution proves Fix 4: every node_health/peer_edge_observations
// row a collector report writes is stamped with reported_by_collector = the authenticated
// collector's name. reported_by_collector is deliberately not exposed via storage.Store's read
// methods (see HealthCheckInput.ReportedByCollector's doc comment: it's queryable directly for
// incident response, not part of any public API response), so this test queries the
// underlying table directly via a raw connection to the same test database newTestServer's
// store was built with.
func TestCollectorReportRecordsAttribution(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const confirmedAddr = "198.51.100.240:18189"
	const peerAddr = "198.51.100.241:18189"
	const pubkeyHex = "aabbccddee"

	reqBody := map[string]any{
		"confirmed_nodes": []map[string]any{
			{"address": confirmedAddr, "public_key": pubkeyHex, "discovery_source": "p2p_discovered"},
		},
		"health_checks": []map[string]any{
			{"address": confirmedAddr, "reachable": true, "probe_source": "p2p"},
		},
		"peer_edges": []map[string]any{
			{"from_address": confirmedAddr, "to_address": peerAddr},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, string(raw))
	defer resp.Body.Close()
	body, _ := readAllForTest(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, body)
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	var confirmedID uuid.UUID
	found := false
	for _, n := range nodes {
		if n.Address == confirmedAddr {
			confirmedID, found = n.ID, true
		}
	}
	if !found {
		t.Fatalf("confirmed node %s not found", confirmedAddr)
	}

	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()

	var healthAttribution *string
	if err := pool.QueryRow(ctx, `SELECT reported_by_collector FROM node_health WHERE node_id = $1`, confirmedID).Scan(&healthAttribution); err != nil {
		t.Fatalf("query node_health.reported_by_collector: %v", err)
	}
	if healthAttribution == nil || *healthAttribution != testCollectorName {
		t.Errorf("node_health.reported_by_collector = %v, want %q", healthAttribution, testCollectorName)
	}

	var edgeAttribution *string
	if err := pool.QueryRow(ctx, `SELECT reported_by_collector FROM peer_edge_observations WHERE from_node_id = $1`, confirmedID).Scan(&edgeAttribution); err != nil {
		t.Fatalf("query peer_edge_observations.reported_by_collector: %v", err)
	}
	if edgeAttribution == nil || *edgeAttribution != testCollectorName {
		t.Errorf("peer_edge_observations.reported_by_collector = %v, want %q", edgeAttribution, testCollectorName)
	}
}

// TestCollectorReportRetryWithIdenticalBodyIsIdempotent proves the server-side half of Fix 3:
// POSTing the exact same request body twice (simulating internal/remotestore's own retry of a
// byte-identical sub-batch after a client-side failure -- see flush.go's flushOnce/splitBatch)
// applies the health check and peer edge exactly ONCE, not twice, even though both are
// append-only writes with no natural primary key to upsert against.
func TestCollectorReportRetryWithIdenticalBodyIsIdempotent(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	const confirmedAddr = "198.51.100.250:18189"
	const peerAddr = "198.51.100.251:18189"
	const pubkeyHex = "aabbccddeeff"

	reqBody := map[string]any{
		"confirmed_nodes": []map[string]any{
			{"address": confirmedAddr, "public_key": pubkeyHex, "discovery_source": "p2p_discovered"},
		},
		"health_checks": []map[string]any{
			{"address": confirmedAddr, "reachable": true, "probe_source": "p2p"},
		},
		"peer_edges": []map[string]any{
			{"from_address": confirmedAddr, "to_address": peerAddr},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	// Send the IDENTICAL body twice -- simulating a client-side retry of the same sub-batch.
	for i := 0; i < 2; i++ {
		resp := doCollectorReportRequest(t, srv.URL, testCollectorAPIKey, string(raw))
		body, _ := readAllForTest(t, resp)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("attempt #%d: status = %d, want %d, body=%s", i+1, resp.StatusCode, http.StatusOK, body)
		}
	}

	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	var confirmedID uuid.UUID
	found := false
	for _, n := range nodes {
		if n.Address == confirmedAddr {
			confirmedID, found = n.ID, true
		}
	}
	if !found {
		t.Fatalf("confirmed node %s not found", confirmedAddr)
	}

	history, err := store.GetNodeHistory(ctx, confirmedID, 10)
	if err != nil {
		t.Fatalf("get node history: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("len(history) = %d, want 1 (identical retry must not duplicate the health check row)", len(history))
	}

	edges, err := store.ListNodeEdges(ctx, confirmedID, 10)
	if err != nil {
		t.Fatalf("list node edges: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("len(edges) = %d, want 1 (identical retry must not duplicate the peer edge row)", len(edges))
	}
}

// readAllForTest reads and returns resp.Body's full contents, failing the test on error.
func readAllForTest(t *testing.T, resp *http.Response) ([]byte, error) {
	t.Helper()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf.Bytes(), nil
}
