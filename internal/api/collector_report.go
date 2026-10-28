package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// This file implements the trusted-collector ingestion channel: POST
// /internal/collectors/report. A remote collector satellite (see
// cmd/netmap-p2p-responder, retrofitted to run against internal/remotestore instead of a
// direct Postgres connection) batches up everything it observed since its last flush --
// confirmed nodes, placeholder-discovered nodes, health checks, and peer edges, all keyed by
// address rather than an internal node UUID (a satellite has no central node IDs of its own)
// -- and POSTs it here. The handler applies each item via the EXACT SAME storage.Store methods
// the local collector/responder already use when talking to Postgres directly
// (UpsertDiscoveredNode/UpsertConfirmedNode/RecordHealthCheck/RecordPeerEdgeObservation): this
// is a new entrypoint into the same storage logic, not a parallel write path.
//
// This is a fundamentally different trust model from POST /nodes (see handleCreateNode): that
// endpoint is reachable by untrusted public submitters and queues to pending_submissions for
// human review. This endpoint is a small, operator-configured, single-operator (Alex) trusted
// channel -- writes are applied immediately, with no review queue, gated by a simple
// per-collector API key (see collector_auth.go) rather than adminauth's HTTP Basic Auth (a
// distinct concern from the human-operated /admin/* area).

// collectorReportRequest is the POST /internal/collectors/report request body.
type collectorReportRequest struct {
	// SelfIdentity is this collector's OWN advertised P2P address(es) -- the address(es) it
	// advertises via its own -public-tcp-addr/-onion3-addr equivalent (see
	// internal/remotestore's Config.SelfAddresses) -- used ONLY to tag that specific node
	// row with tags.role = "collector" (see applyCollectorReport's tagging step). This must
	// be explicit, never inferred from ConfirmedNodes/DiscoveredNodes/PeerEdges below, even
	// if one of their addresses happens to coincide with a self-identity address.
	SelfIdentity []string `json:"self_identity"`

	// ConfirmedNodes are nodes this collector directly confirmed (a real pubkey recovered
	// from a handshake or gRPC probe) since its last flush.
	ConfirmedNodes []collectorReportConfirmedNode `json:"confirmed_nodes"`

	// DiscoveredNodes are placeholder addresses seen via a peer walk, not yet confirmed.
	DiscoveredNodes []collectorReportDiscoveredNode `json:"discovered_nodes"`

	// HealthChecks reference addresses, not internal node UUIDs -- this collector has no
	// central node IDs of its own, so the handler resolves address -> node ID server-side
	// via the same upsert calls used elsewhere in this repo (see resolveReportedNodeID).
	HealthChecks []collectorReportHealthCheck `json:"health_checks"`

	// PeerEdges are directed (from_address, to_address) pairs this collector observed via
	// its own peer-graph walk.
	PeerEdges []collectorReportPeerEdge `json:"peer_edges"`
}

type collectorReportConfirmedNode struct {
	Address string `json:"address"`
	// PublicKey is hex-encoded, matching this repo's other hex-over-the-wire pubkey
	// convention (see PublicSeedCandidate.PublicKey).
	PublicKey       string `json:"public_key"`
	DiscoverySource string `json:"discovery_source"`
}

type collectorReportDiscoveredNode struct {
	Address string `json:"address"`
}

type collectorReportHealthCheck struct {
	Address               string     `json:"address"`
	Reachable             bool       `json:"reachable"`
	ProbeSource           string     `json:"probe_source"`
	Height                *int64     `json:"height,omitempty"`
	ChainTipHeight        *int64     `json:"chain_tip_height,omitempty"`
	Version               *string    `json:"version,omitempty"`
	LatencyMS             *int       `json:"latency_ms,omitempty"`
	RxtHashrate           *float64   `json:"rxt_hashrate,omitempty"`
	C29Hashrate           *float64   `json:"c29_hashrate,omitempty"`
	Sha3xHashrate         *float64   `json:"sha3x_hashrate,omitempty"`
	PeerIdentityUpdatedAt *time.Time `json:"peer_identity_updated_at,omitempty"`
}

type collectorReportPeerEdge struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

// collectorReportResponse is the POST /internal/collectors/report response body: a count of
// how many of each batch item were successfully applied, for the reporting collector's own
// observability (see internal/remotestore, which logs these counts on a successful flush).
type collectorReportResponse struct {
	ConfirmedNodesApplied  int `json:"confirmed_nodes_applied"`
	DiscoveredNodesApplied int `json:"discovered_nodes_applied"`
	HealthChecksApplied    int `json:"health_checks_applied"`
	PeerEdgesApplied       int `json:"peer_edges_applied"`
	SelfIdentityTagged     int `json:"self_identity_tagged"`
}

// validCollectorReportDiscoverySources is the closed set of storage.DiscoverySource values a
// reported confirmed node may declare on the wire, mirroring the CHECK constraint
// nodes.discovery_source itself enforces at the database level (see 0001_init.sql), validated
// here up front so a malformed value 400s instead of surfacing as an opaque 500 from the
// storage layer.
//
// IMPORTANT (trust-boundary fix, see this repo's readiness-review follow-up, Fix 6(a)): this
// set is validated for wire well-formedness ONLY. applyCollectorReport below ALWAYS applies a
// confirmed_nodes entry with discoverySource forced to storage.DiscoverySourceP2P, regardless
// of what a report claims here -- a satellite must never be able to mint a fully opted-in
// (registry_submitted/both) seed candidate merely by claiming that discovery_source and
// pairing it with a reachable=true health check in the same batch, since that would bypass
// the pending_submissions human-review queue the public POST /nodes path enforces for the
// exact same outcome. A previously-registry_submitted node (approved via that public path)
// that a satellite also observes still correctly becomes "both" -- UpsertConfirmedNode's own
// merge semantics (CASE WHEN discovery_source = $1 THEN discovery_source ELSE 'both' END)
// already handle that without this package needing to pass through the satellite's claim.
var validCollectorReportDiscoverySources = map[string]bool{
	string(storage.DiscoverySourceP2P):      true,
	string(storage.DiscoverySourceRegistry): true,
	string(storage.DiscoverySourceBoth):     true,
}

// validCollectorReportProbeSources is the closed set of storage.ProbeSource values a reported
// health check may declare, mirroring validCollectorReportDiscoverySources' role for
// storage.ProbeSource's own CHECK constraint.
var validCollectorReportProbeSources = map[string]bool{
	string(storage.ProbeSourceGRPC): true,
	string(storage.ProbeSourceP2P):  true,
}

// validateReportedAddress rejects a collector-reported "host:port" address that resolves to a
// private/reserved IP -- mirrors validateSubmittedHost's SSRF-hardening rejection (already
// applied to the public POST /nodes path) and cmd/netmap-p2p-responder's isClaimedAddressAllowed
// (already applied to self-claimed P2P identity addresses), for the exact same reason: this
// trusted-collector ingestion path's own UpsertDiscoveredNode/UpsertConfirmedNode calls feed
// straight into the same probe machinery that dials every address it's given, and
// "authenticated collector" is a DIFFERENT trust property from "safe address to dial" -- see
// this repo's readiness-review follow-up, Fix 6(b). Applied to every address field in a
// collector report (self_identity, confirmed_nodes/discovered_nodes/health_checks addresses,
// peer_edges from/to addresses) by validateCollectorReportRequest below.
//
// address is expected in this repo's "host:port" storage convention -- a bare host with no
// port (or any other unparseable value) is rejected outright, matching validateHostSyntax's
// own "syntactically well-formed or reject" discipline elsewhere in this package. A .onion
// host is never an IP -- net.ParseIP simply returns nil for it -- so it passes through
// unchanged, exactly like validateSubmittedHost's own onion handling.
func validateReportedAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if IsPrivateOrReservedIP(ip) {
		return fmt.Errorf("address %q is a private/reserved IP address, not allowed", address)
	}
	return nil
}

// validateCollectorReportRequest checks every item of req for well-formedness BEFORE any
// storage write is attempted -- see handleCollectorReport's doc comment for why this two-phase
// (validate everything, then apply) shape is used: a single malformed item must 400 the whole
// request rather than partially applying a batch and 500ing partway through.
func validateCollectorReportRequest(req collectorReportRequest) error {
	for i, addr := range req.SelfIdentity {
		if addr == "" {
			return fmt.Errorf("self_identity[%d]: address is required", i)
		}
		if err := validateReportedAddress(addr); err != nil {
			return fmt.Errorf("self_identity[%d]: %w", i, err)
		}
	}

	for i, n := range req.ConfirmedNodes {
		if n.Address == "" {
			return fmt.Errorf("confirmed_nodes[%d]: address is required", i)
		}
		if err := validateReportedAddress(n.Address); err != nil {
			return fmt.Errorf("confirmed_nodes[%d]: %w", i, err)
		}
		if n.PublicKey == "" {
			return fmt.Errorf("confirmed_nodes[%d]: public_key is required", i)
		}
		if _, err := hex.DecodeString(n.PublicKey); err != nil {
			return fmt.Errorf("confirmed_nodes[%d]: public_key is not valid hex: %w", i, err)
		}
		if !validCollectorReportDiscoverySources[n.DiscoverySource] {
			return fmt.Errorf("confirmed_nodes[%d]: invalid discovery_source %q", i, n.DiscoverySource)
		}
	}

	for i, n := range req.DiscoveredNodes {
		if n.Address == "" {
			return fmt.Errorf("discovered_nodes[%d]: address is required", i)
		}
		if err := validateReportedAddress(n.Address); err != nil {
			return fmt.Errorf("discovered_nodes[%d]: %w", i, err)
		}
	}

	for i, h := range req.HealthChecks {
		if h.Address == "" {
			return fmt.Errorf("health_checks[%d]: address is required", i)
		}
		if err := validateReportedAddress(h.Address); err != nil {
			return fmt.Errorf("health_checks[%d]: %w", i, err)
		}
		if !validCollectorReportProbeSources[h.ProbeSource] {
			return fmt.Errorf("health_checks[%d]: invalid probe_source %q", i, h.ProbeSource)
		}
	}

	for i, e := range req.PeerEdges {
		if e.FromAddress == "" {
			return fmt.Errorf("peer_edges[%d]: from_address is required", i)
		}
		if err := validateReportedAddress(e.FromAddress); err != nil {
			return fmt.Errorf("peer_edges[%d]: from_address: %w", i, err)
		}
		if e.ToAddress == "" {
			return fmt.Errorf("peer_edges[%d]: to_address is required", i)
		}
		if err := validateReportedAddress(e.ToAddress); err != nil {
			return fmt.Errorf("peer_edges[%d]: to_address: %w", i, err)
		}
	}

	return nil
}

// reportBatchIDNamespace is a fixed, arbitrary namespace UUID used only to derive a
// deterministic per-batch idempotency key from a collector report's raw request body bytes
// (see reportBatchIDFromBody below) -- mirrors internal/remotestore's own addressNamespace
// (identity.go) in spirit: a fixed namespace for a version-5 (SHA-1-based) UUID derivation,
// carrying no other meaning and never intended to change.
var reportBatchIDNamespace = uuid.MustParse("8f1a6b2e-2b8b-4b8e-9a4b-9a6e6b2e8f1a")

// reportBatchIDFromBody derives a deterministic idempotency key (see this repo's
// readiness-review follow-up, Fix 3) from a collector report's raw, undecoded JSON request
// body: a version-5 UUID over the exact bytes received. A byte-identical retry of the same
// buffered items (see internal/remotestore/flush.go's flushOnce, which marshals the exact
// same Go struct -- no map fields, so json.Marshal's field order is fixed -- for every retry
// of the same still-buffered slice) always produces byte-identical JSON, and therefore the
// exact same batch ID; genuinely different content (a different set of buffered items)
// produces a different one. This requires no wire-protocol change at all -- the server
// computes this from bytes it already received, entirely on its own.
func reportBatchIDFromBody(body []byte) uuid.UUID {
	return uuid.NewSHA1(reportBatchIDNamespace, body)
}

// handleCollectorReport applies a trusted remote collector satellite's batched observations
// via the same storage.Store methods the local collector/responder already use -- see this
// file's doc comment for the full contract and NewRouter's doc comment for how this route is
// authenticated/mounted.
//
// Validation happens in two phases: validateCollectorReportRequest checks every item for
// well-formedness up front, so a malformed payload 400s without partially applying anything;
// only once the whole batch validates does applyCollectorReport start issuing storage writes.
//
// The authenticated collector's identity (name + configured self_identity allowlist) is read
// from r.Context() -- attached by wrapCollectorAuth (see collector_auth.go's
// collectorContext/collectorFromContext) -- and threaded into applyCollectorReport for
// attribution (Fix 4) and self_identity constraint (Fix 6(c)) purposes; see that function's
// own doc comment. The raw request body is read up front (rather than decoded directly off
// r.Body) so reportBatchIDFromBody can derive this batch's idempotency key (Fix 3) from
// exactly the bytes received, before JSON-decoding them.
func handleCollectorReport(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxCollectorReportBodyBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("read request body: %w", err))
			return
		}

		var req collectorReportRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}

		if err := validateCollectorReportRequest(req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		cc, _ := collectorFromContext(r.Context())
		batchID := reportBatchIDFromBody(rawBody)

		resp, err := applyCollectorReport(r.Context(), store, req, cc, batchID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// maxCollectorReportBodyBytes bounds a single POST /internal/collectors/report request body
// -- a generous 32MiB, well above what even an unbounded pre-Fix-3 flush would have produced
// in any realistic deployment, but still a genuine, enforced ceiling (io.ReadAll above would
// otherwise buffer an arbitrarily large body in memory) rather than no cap at all.
const maxCollectorReportBodyBytes = 32 << 20

// reportNodeResolver resolves an address to the node.ID storage.Store assigned it, upserting a
// placeholder (UpsertDiscoveredNode with DiscoverySourceP2P) the first time a given address is
// seen within a single applyCollectorReport call, and caching that ID for every subsequent
// reference to the same address later in the SAME request (e.g. a health check or peer edge
// referencing an address already resolved by an earlier confirmed_nodes/discovered_nodes
// entry) -- exactly one upsert call per distinct address per request, never a redundant one.
type reportNodeResolver struct {
	ctx        context.Context
	store      storage.Store
	addressIDs map[string]storage.Node
}

func newReportNodeResolver(ctx context.Context, store storage.Store) *reportNodeResolver {
	return &reportNodeResolver{ctx: ctx, store: store, addressIDs: make(map[string]storage.Node)}
}

// resolve returns the storage.Node for address, from this request's own cache if already
// resolved, otherwise via UpsertDiscoveredNode (which is always safe to call even if address
// turns out to already be confirmed elsewhere -- see UpsertDiscoveredNode's own doc comment:
// it never downgrades an existing confirmed node, it only bumps last_seen/merges
// discovery_source/tags).
func (rr *reportNodeResolver) resolve(address string) (storage.Node, error) {
	if n, ok := rr.addressIDs[address]; ok {
		return n, nil
	}
	n, err := rr.store.UpsertDiscoveredNode(rr.ctx, address, storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		return storage.Node{}, fmt.Errorf("resolve address %s: %w", address, err)
	}
	rr.addressIDs[address] = n
	return n, nil
}

// remember records that address already resolves to n, without issuing any storage call --
// used right after a confirmed_nodes entry is applied via UpsertConfirmedNode, so a later
// reference to that same address (health_checks/peer_edges) reuses n.ID instead of resolving
// it again via UpsertDiscoveredNode.
func (rr *reportNodeResolver) remember(address string, n storage.Node) {
	rr.addressIDs[address] = n
}

// applyCollectorReport applies every item of a validated req via storage.Store, in this order:
//
//  1. ConfirmedNodes (UpsertConfirmedNode) -- remembered in resolver so later steps
//     referencing the same address (HealthChecks/PeerEdges) don't issue a redundant upsert.
//     discoverySource is ALWAYS forced to storage.DiscoverySourceP2P here, regardless of what
//     cn.DiscoverySource claims -- see validCollectorReportDiscoverySources' doc comment /
//     this repo's readiness-review follow-up, Fix 6(a), for why.
//  2. DiscoveredNodes (UpsertDiscoveredNode), same remember-in-resolver treatment.
//  3. SelfIdentity tagging (UpsertDiscoveredNode with tags={"role":"collector"}) -- applied
//     AFTER 1/2 so that if a self-identity address happens to already have been resolved
//     above (e.g. it was also reported as a confirmed node), tagging merges onto that same
//     row rather than racing it; UpsertDiscoveredNode's tags-merge semantics (tags = tags ||
//     $2) mean this never clobbers a pubkey/discovery_source set by an earlier step. This
//     tagging is applied ONLY to addresses explicitly listed in req.SelfIdentity -- never to
//     any address that merely happens to also appear in ConfirmedNodes/DiscoveredNodes/
//     PeerEdges, per this endpoint's governing brief. It is FURTHER constrained (Fix 6(c)) to
//     addresses in collector.SelfAddresses -- the operator-configured allowlist of this
//     specific authenticated collector's own address(es) (see CollectorConfig's doc comment)
//     -- any self_identity address not on that list is skipped and logged, not applied and
//     not erroring the whole batch: self_identity tagging is a nice-to-have on top of an
//     otherwise-valid report, not something a config mismatch should fail the entire report
//     over.
//  4. HealthChecks (RecordHealthCheck), resolving address -> node ID via the resolver (which
//     upserts a placeholder if the address wasn't already resolved by 1-3). Every recorded
//     row is stamped with collector.Name via HealthCheckInput.ReportedByCollector (Fix 4)
//     and batchID via HealthCheckInput.ReportBatchID (Fix 3 idempotency).
//  5. PeerEdges (RecordPeerEdgeObservation), same resolution as 4, same collector.Name/
//     batchID attribution via storage.PeerEdgeReportMeta.
//
// batchID is a deterministic idempotency key derived from this exact request's raw body
// bytes (see reportBatchIDFromBody) -- a byte-identical retry of this same batch (e.g. after
// a client-side timeout on a request the server actually finished applying) carries the same
// batchID, letting RecordHealthCheck/RecordPeerEdgeObservation recognize and skip rows they
// already applied instead of duplicating them (Fix 3).
func applyCollectorReport(ctx context.Context, store storage.Store, req collectorReportRequest, collector collectorContext, batchID uuid.UUID) (collectorReportResponse, error) {
	var resp collectorReportResponse
	resolver := newReportNodeResolver(ctx, store)

	allowedSelfAddresses := make(map[string]bool, len(collector.SelfAddresses))
	for _, a := range collector.SelfAddresses {
		allowedSelfAddresses[a] = true
	}

	for _, cn := range req.ConfirmedNodes {
		pubkey, err := hex.DecodeString(cn.PublicKey)
		if err != nil {
			// Already validated by validateCollectorReportRequest -- unreachable in
			// practice, but fail loudly rather than silently skip if it somehow isn't.
			return collectorReportResponse{}, fmt.Errorf("confirmed_nodes: re-decode public_key for %s: %w", cn.Address, err)
		}
		// discoverySource is deliberately NOT storage.DiscoverySource(cn.DiscoverySource)
		// -- see this function's doc comment / validCollectorReportDiscoverySources' doc
		// comment for the Fix 6(a) trust-boundary rationale.
		n, err := store.UpsertConfirmedNode(ctx, cn.Address, pubkey, storage.DiscoverySourceP2P)
		if err != nil {
			return collectorReportResponse{}, fmt.Errorf("confirmed_nodes: upsert %s: %w", cn.Address, err)
		}
		resolver.remember(cn.Address, n)
		resp.ConfirmedNodesApplied++
	}

	for _, dn := range req.DiscoveredNodes {
		n, err := store.UpsertDiscoveredNode(ctx, dn.Address, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			return collectorReportResponse{}, fmt.Errorf("discovered_nodes: upsert %s: %w", dn.Address, err)
		}
		resolver.remember(dn.Address, n)
		resp.DiscoveredNodesApplied++
	}

	// SelfIdentity tagging: see this function's doc comment for why this is a distinct,
	// explicit step rather than something folded into the loops above -- tags.role =
	// "collector" is applied ONLY to addresses named here AND present in
	// collector.SelfAddresses (Fix 6(c)), regardless of whether they also appear (by
	// coincidence or otherwise) in ConfirmedNodes/DiscoveredNodes/PeerEdges.
	for _, addr := range req.SelfIdentity {
		if !allowedSelfAddresses[addr] {
			log.Printf("api: collector %q reported self_identity address %q, which is not in its configured self-address allowlist -- skipping tagging (see NETMAP_COLLECTOR_SELF_ADDRESSES)", collector.Name, addr)
			continue
		}
		if _, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, map[string]any{"role": collectorRoleTagValue}, nil); err != nil {
			return collectorReportResponse{}, fmt.Errorf("self_identity: tag %s: %w", addr, err)
		}
		resp.SelfIdentityTagged++
	}

	// reportedByPtr/peerEdgeMeta carry collector.Name/batchID in the two shapes
	// HealthCheckInput/storage.PeerEdgeReportMeta respectively need -- computed once here,
	// not per-iteration, since both are fixed for the whole call (Fix 4 attribution, Fix 3
	// idempotency). reportedByPtr is left nil when collector.Name is empty (should not
	// happen in practice -- handleCollectorReport only ever calls this with a value
	// populated by a successful wrapCollectorAuth match -- but guarded anyway rather than
	// ever writing an empty-string attribution). batchID itself is always set (the caller
	// always derives one from the request body), so peerEdgeMeta.ReportBatchID is always
	// non-nil.
	var reportedByPtr *string
	if collector.Name != "" {
		reportedByPtr = &collector.Name
	}
	peerEdgeMeta := storage.PeerEdgeReportMeta{ReportBatchID: &batchID}
	if collector.Name != "" {
		peerEdgeMeta.ReportedByCollector = collector.Name
	}

	for _, hc := range req.HealthChecks {
		n, err := resolver.resolve(hc.Address)
		if err != nil {
			return collectorReportResponse{}, fmt.Errorf("health_checks: %w", err)
		}
		if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{
			NodeID:                n.ID,
			Reachable:             hc.Reachable,
			ProbeSource:           storage.ProbeSource(hc.ProbeSource),
			Height:                hc.Height,
			ChainTipHeight:        hc.ChainTipHeight,
			Version:               hc.Version,
			LatencyMS:             hc.LatencyMS,
			RxtHashrate:           hc.RxtHashrate,
			C29Hashrate:           hc.C29Hashrate,
			Sha3xHashrate:         hc.Sha3xHashrate,
			PeerIdentityUpdatedAt: hc.PeerIdentityUpdatedAt,
			ReportedByCollector:   reportedByPtr,
			ReportBatchID:         &batchID,
		}); err != nil {
			return collectorReportResponse{}, fmt.Errorf("health_checks: record for %s: %w", hc.Address, err)
		}
		resp.HealthChecksApplied++
	}

	for _, pe := range req.PeerEdges {
		fromNode, err := resolver.resolve(pe.FromAddress)
		if err != nil {
			return collectorReportResponse{}, fmt.Errorf("peer_edges: %w", err)
		}
		toNode, err := resolver.resolve(pe.ToAddress)
		if err != nil {
			return collectorReportResponse{}, fmt.Errorf("peer_edges: %w", err)
		}
		if err := store.RecordPeerEdgeObservation(ctx, fromNode.ID, toNode.ID, peerEdgeMeta); err != nil {
			return collectorReportResponse{}, fmt.Errorf("peer_edges: record %s -> %s: %w", pe.FromAddress, pe.ToAddress, err)
		}
		resp.PeerEdgesApplied++
	}

	return resp, nil
}
