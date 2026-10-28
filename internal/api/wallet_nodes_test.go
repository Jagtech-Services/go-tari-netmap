package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// newTestServerWithWalletHTTP builds a test server with the SEPARATE wallet-node
// registration flow wired to walletClient (may be nil) and gated by walletHTTPEnabled --
// mirrors newTestServerWithCreds' shape but lets these tests control the two parameters
// specific to this feature that newTestServer/newTestServerWithCreds hardcode (nil
// walletHTTPClient, walletHTTPEnabled=true).
func newTestServerWithWalletHTTP(t *testing.T, walletClient collector.NodeClient, walletHTTPEnabled bool) (*httptest.Server, storage.Store) {
	t.Helper()
	store := newTestStore(t)
	srv := httptest.NewServer(api.NewRouter(store, nil, nil, walletClient, walletHTTPEnabled,
		adminauth.Credentials{Username: testAdminUser, Password: testAdminPassword}, testCollectorKeys(), api.DefaultStatsCacheTTL, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL))
	t.Cleanup(srv.Close)
	return srv, store
}

// postWalletNode issues POST /wallet-nodes with the given raw JSON body and returns the
// response for the caller to assert on.
func postWalletNode(t *testing.T, srv *httptest.Server, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(srv.URL+"/wallet-nodes", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /wallet-nodes: %v", err)
	}
	return resp
}

// TestCreateWalletNodeSubmissionRejectsMissingPort verifies wallet_http_port is REQUIRED
// on this endpoint -- unlike the old, reworked-away bundled draft's optional field on
// POST /nodes, a missing/zero value is rejected outright (400), never silently accepted.
func TestCreateWalletNodeSubmissionRejectsMissingPort(t *testing.T) {
	srv, _ := newTestServerWithWalletHTTP(t, nil, true)

	resp := postWalletNode(t, srv, `{"host":"203.0.113.5"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusBadRequest, body)
	}
}

// TestCreateWalletNodeSubmissionRejectsOutOfRangePort verifies an explicit but
// out-of-range port (e.g. 99999) is also rejected with 400.
func TestCreateWalletNodeSubmissionRejectsOutOfRangePort(t *testing.T) {
	srv, _ := newTestServerWithWalletHTTP(t, nil, true)

	resp := postWalletNode(t, srv, `{"host":"203.0.113.5","wallet_http_port":99999}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusBadRequest, body)
	}
}

// TestCreateWalletNodeSubmissionRejectsSSRFInvalidHost verifies the same SSRF-hardening
// host validation POST /nodes already applies (validateSubmittedHost) is also enforced
// here -- a private/loopback IP is rejected with 400, even before any node-lookup happens.
func TestCreateWalletNodeSubmissionRejectsSSRFInvalidHost(t *testing.T) {
	srv, _ := newTestServerWithWalletHTTP(t, nil, true)

	resp := postWalletNode(t, srv, `{"host":"127.0.0.1","wallet_http_port":9000}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusBadRequest, body)
	}
}

// TestCreateWalletNodeSubmissionRejectsUnknownHost verifies directive #2's "link via
// public IP only" requirement enforced at submission time: a well-formed, syntactically
// valid host that doesn't match ANY node netmap already knows about is rejected (404) --
// this endpoint never creates a new node record.
func TestCreateWalletNodeSubmissionRejectsUnknownHost(t *testing.T) {
	srv, _ := newTestServerWithWalletHTTP(t, nil, true)

	resp := postWalletNode(t, srv, `{"host":"203.0.113.5","wallet_http_port":9000}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusNotFound, body)
	}
}

// TestCreateWalletNodeSubmissionAcceptedForKnownHost verifies the happy path: a
// wallet_http_port + a host that matches an already-known node's own address (by host
// alone -- the submitter never references the node's internal id or base P2P port) is
// accepted (202) and queued 'pending'.
func TestCreateWalletNodeSubmissionAcceptedForKnownHost(t *testing.T) {
	srv, store := newTestServerWithWalletHTTP(t, nil, true)
	ctx := context.Background()

	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.5:18142", storage.DiscoverySourceRegistry, nil, nil); err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	resp := postWalletNode(t, srv, `{"host":"203.0.113.5","wallet_http_port":9000}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusAccepted, body)
	}

	var submission storage.PendingWalletSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submission); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if submission.Host != "203.0.113.5" {
		t.Errorf("submission.host = %q, want %q", submission.Host, "203.0.113.5")
	}
	if submission.WalletHTTPPort != 9000 {
		t.Errorf("submission.wallet_http_port = %d, want 9000", submission.WalletHTTPPort)
	}
	if submission.Status != storage.SubmissionStatusPending {
		t.Errorf("submission.status = %q, want %q", submission.Status, storage.SubmissionStatusPending)
	}

	listed, err := store.ListPendingWalletSubmissions(ctx, "")
	if err != nil {
		t.Fatalf("list pending wallet submissions: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != submission.ID {
		t.Fatalf("listed = %+v, want just %v", listed, submission.ID)
	}
}

// fakeWalletHTTPClient is an in-memory fixture collector.NodeClient for these tests, mirroring
// fakeClient's shape (used elsewhere in this package for gRPC/P2P) but as its own type so
// this file doesn't need to touch/share that one's map (each test builds its own small
// fixture, addressed by "host:port").
type fakeWalletHTTPClient struct {
	info map[string]collector.NodeInfo
}

func (f *fakeWalletHTTPClient) GetPeers(ctx context.Context, addr string) ([]collector.DiscoveredPeer, error) {
	return nil, nil
}

func (f *fakeWalletHTTPClient) GetInfo(ctx context.Context, addr string) (collector.NodeInfo, error) {
	info, ok := f.info[addr]
	if !ok {
		return collector.NodeInfo{}, fmt.Errorf("api_test: wallet-http probe %s: connection refused (no fixture)", addr)
	}
	return info, nil
}

// TestApproveWalletSubmissionProbeFailureRejectsAndDoesNotWritePort is the single most
// important test in this feature (per its dispatch brief): an approval attempt against a
// port whose sanity probe FAILS must be rejected AND must NOT write wallet_http_port onto
// the node -- the submission stays pending.
func TestApproveWalletSubmissionProbeFailureRejectsAndDoesNotWritePort(t *testing.T) {
	// Deliberately empty fixture map: GetInfo returns an error for every address,
	// simulating an unreachable/non-responding wallet-HTTP endpoint.
	client := &fakeWalletHTTPClient{info: map[string]collector.NodeInfo{}}
	srv, store := newTestServerWithWalletHTTP(t, client, true)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "203.0.113.6:18142", storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	resp := postWalletNode(t, srv, `{"host":"203.0.113.6","wallet_http_port":9000}`)
	var submission storage.PendingWalletSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submission); err != nil {
		t.Fatalf("decode submission: %v", err)
	}
	resp.Body.Close()

	approveResp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/wallet-submissions/%s/approve", srv.URL, submission.ID), "application/json", nil)
	defer approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("approve status = %d, want %d (body: %s)", approveResp.StatusCode, http.StatusConflict, body)
	}

	// The node must NOT have gained a wallet_http_port.
	persistedNode, err := store.GetNode(ctx, node.ID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if persistedNode.WalletHTTPPort != nil {
		t.Fatalf("node.wallet_http_port = %v, want nil -- a failed sanity probe must never write this", *persistedNode.WalletHTTPPort)
	}

	// The submission must stay exactly 'pending', not silently rejected/approved.
	persistedSubmission, err := store.GetPendingWalletSubmission(ctx, submission.ID)
	if err != nil {
		t.Fatalf("get pending wallet submission: %v", err)
	}
	if persistedSubmission.Status != storage.SubmissionStatusPending {
		t.Fatalf("submission.status = %q, want %q (a failed probe must leave it pending for a human to retry/reject)", persistedSubmission.Status, storage.SubmissionStatusPending)
	}
	if persistedSubmission.ProbeSucceeded != nil {
		t.Fatalf("submission.probe_succeeded = %v, want nil -- the permissions matrix must only ever be written on a SUCCESSFUL approval-gating probe", *persistedSubmission.ProbeSucceeded)
	}
}

// TestApproveWalletSubmissionSuccessWritesPortAndMatrix is this feature's happy-path
// approval test: a submission whose approval-gating probe SUCCEEDS gets its
// wallet_http_port written onto the linked node, promoted_node_id set, and the
// "permissions matrix" fields (probe_succeeded/probe_is_synced/probe_height) recorded.
func TestApproveWalletSubmissionSuccessWritesPortAndMatrix(t *testing.T) {
	height := int64(555)
	synced := true
	target := "203.0.113.7:9000"
	client := &fakeWalletHTTPClient{info: map[string]collector.NodeInfo{
		target: {Reachable: true, Height: &height, IsSynced: &synced},
	}}
	srv, store := newTestServerWithWalletHTTP(t, client, true)
	ctx := context.Background()

	node, err := store.UpsertDiscoveredNode(ctx, "203.0.113.7:18142", storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	resp := postWalletNode(t, srv, `{"host":"203.0.113.7","wallet_http_port":9000}`)
	var submission storage.PendingWalletSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submission); err != nil {
		t.Fatalf("decode submission: %v", err)
	}
	resp.Body.Close()

	approveResp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/wallet-submissions/%s/approve", srv.URL, submission.ID), "application/json", nil)
	defer approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("approve status = %d, want %d (body: %s)", approveResp.StatusCode, http.StatusOK, body)
	}

	var approved struct {
		Node       storage.Node                    `json:"node"`
		Submission storage.PendingWalletSubmission `json:"submission"`
	}
	if err := json.NewDecoder(approveResp.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if approved.Node.WalletHTTPPort == nil || *approved.Node.WalletHTTPPort != 9000 {
		t.Errorf("response node.wallet_http_port = %v, want 9000", approved.Node.WalletHTTPPort)
	}

	persistedNode, err := store.GetNode(ctx, node.ID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if persistedNode.WalletHTTPPort == nil || *persistedNode.WalletHTTPPort != 9000 {
		t.Fatalf("persisted node.wallet_http_port = %v, want 9000", persistedNode.WalletHTTPPort)
	}

	persistedSubmission, err := store.GetPendingWalletSubmission(ctx, submission.ID)
	if err != nil {
		t.Fatalf("get pending wallet submission: %v", err)
	}
	if persistedSubmission.Status != storage.SubmissionStatusApproved {
		t.Errorf("submission.status = %q, want %q", persistedSubmission.Status, storage.SubmissionStatusApproved)
	}
	if persistedSubmission.PromotedNodeID == nil || *persistedSubmission.PromotedNodeID != node.ID {
		t.Errorf("submission.promoted_node_id = %v, want %v", persistedSubmission.PromotedNodeID, node.ID)
	}
	if persistedSubmission.ProbeSucceeded == nil || !*persistedSubmission.ProbeSucceeded {
		t.Errorf("submission.probe_succeeded = %v, want true", persistedSubmission.ProbeSucceeded)
	}
	if persistedSubmission.ProbeIsSynced == nil || !*persistedSubmission.ProbeIsSynced {
		t.Errorf("submission.probe_is_synced = %v, want true", persistedSubmission.ProbeIsSynced)
	}
	if persistedSubmission.ProbeHeight == nil || *persistedSubmission.ProbeHeight != height {
		t.Errorf("submission.probe_height = %v, want %d", persistedSubmission.ProbeHeight, height)
	}
	if persistedSubmission.ProbeCheckedAt == nil {
		t.Error("submission.probe_checked_at = nil, want a timestamp")
	}
}

// TestRejectWalletSubmission mirrors handleRejectSubmission's own test shape (see
// TestRejectSubmission elsewhere in this package): rejecting a pending wallet submission
// records a rejection_reason and marks it rejected, without ever touching a node.
func TestRejectWalletSubmission(t *testing.T) {
	srv, store := newTestServerWithWalletHTTP(t, nil, true)
	ctx := context.Background()

	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.8:18142", storage.DiscoverySourceRegistry, nil, nil); err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	resp := postWalletNode(t, srv, `{"host":"203.0.113.8","wallet_http_port":9000}`)
	var submission storage.PendingWalletSubmission
	if err := json.NewDecoder(resp.Body).Decode(&submission); err != nil {
		t.Fatalf("decode submission: %v", err)
	}
	resp.Body.Close()

	rejectResp := doAdminRequest(t, http.MethodPost, fmt.Sprintf("%s/admin/wallet-submissions/%s/reject", srv.URL, submission.ID), "application/json", bytes.NewBufferString(`{"reason":"port doesn't look right"}`))
	defer rejectResp.Body.Close()
	if rejectResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rejectResp.Body)
		t.Fatalf("reject status = %d, want %d (body: %s)", rejectResp.StatusCode, http.StatusOK, body)
	}

	persisted, err := store.GetPendingWalletSubmission(ctx, submission.ID)
	if err != nil {
		t.Fatalf("get pending wallet submission: %v", err)
	}
	if persisted.Status != storage.SubmissionStatusRejected {
		t.Errorf("status = %q, want %q", persisted.Status, storage.SubmissionStatusRejected)
	}
	if persisted.RejectionReason == nil || *persisted.RejectionReason != "port doesn't look right" {
		t.Errorf("rejection_reason = %v, want %q", persisted.RejectionReason, "port doesn't look right")
	}
}

// TestWalletHTTPFeatureFlagDisabledRoutesUnreachable is this feature's mainnet-only gating
// test at the HTTP-route level: with walletHTTPEnabled=false (mirroring
// -wallet-http-enabled's default), POST /wallet-nodes and every /admin/wallet-submissions/*
// route are unreachable (404 -- not registered on the mux at all), even with valid admin
// credentials.
func TestWalletHTTPFeatureFlagDisabledRoutesUnreachable(t *testing.T) {
	srv, _ := newTestServerWithWalletHTTP(t, nil, false)

	resp := postWalletNode(t, srv, `{"host":"203.0.113.9","wallet_http_port":9000}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /wallet-nodes status = %d, want %d (body: %s)", resp.StatusCode, http.StatusNotFound, body)
	}

	listResp := doAdminRequest(t, http.MethodGet, srv.URL+"/admin/wallet-submissions", "", nil)
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("GET /admin/wallet-submissions status = %d, want %d (body: %s)", listResp.StatusCode, http.StatusNotFound, body)
	}

	approveResp := doAdminRequest(t, http.MethodPost, srv.URL+"/admin/wallet-submissions/"+randomUUIDString()+"/approve", "application/json", nil)
	defer approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("POST /admin/wallet-submissions/{id}/approve status = %d, want %d (body: %s)", approveResp.StatusCode, http.StatusNotFound, body)
	}
}

// randomUUIDString returns a syntactically valid-looking UUID string for building a URL
// path in a test that doesn't care whether a real row exists behind it (the 404 this test
// asserts on comes from the ROUTE not being registered at all, never reached by
// PathValue-parsing logic that would care about a real id).
func randomUUIDString() string { return "00000000-0000-0000-0000-000000000000" }
