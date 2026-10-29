// Package api exposes an HTTP API for topology/health data: node registry
// submission and listing, per-node health history, and the topology graph.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// asyncCheckTimeout bounds the best-effort health check kicked off when a
// node is submitted via POST /nodes.
//
// This must stay >= collector.dialTimeout (internal/collector/grpc_client.go,
// currently 180s to accommodate real-world network/Tor-circuit latency)
// plus a small buffer for HTTP request/response overhead on top of the
// probe itself — otherwise this timeout would prematurely truncate a
// probe that the underlying dial timeout would otherwise have kept
// trying, undermining the whole point of raising dialTimeout in the
// first place.
const asyncCheckTimeout = 190 * time.Second

// MaxPendingSubmissions caps the number of unreviewed ('pending')
// submissions the review queue will hold at once — abuse mitigation
// against unbounded queue growth from spam, distinct from the per-IP rate
// limit (this caps total outstanding queue size regardless of how many
// distinct source IPs contribute to it). 100 is a generous cap for a
// human-reviewed queue (in normal operation it should rarely get anywhere
// near this) while still bounding worst-case storage/listing cost. It's
// an exported var, not a const, specifically so tests can temporarily
// lower it (rather than actually creating 100 real rows to exercise the
// cap) — see internal/api/api_test.go's queue-cap test.
var MaxPendingSubmissions = 100

// NewRouter returns the HTTP handler for the API. store persists topology
// and health data; grpcClient and p2pClient are used to kick off an async,
// non-blocking health check via each configured transport when a new node
// is registered via POST /nodes. Either may be nil — collector.PollOnce
// skips a nil client's probe entirely rather than erroring. walletHTTPClient
// is the analogous wallet-sync-HTTP transport (see internal/collector's
// wallet_http_client.go) — also optional/nilable, and, unlike
// grpcClient/p2pClient, only ever actually dialed for a node whose
// storage.Node.WalletHTTPPort is non-nil (see collector.PollOnce's doc
// comment). walletHTTPEnabled gates the ENTIRE separate wallet-node
// registration flow (POST /wallet-nodes and every /admin/wallet-submissions/*
// route, registered further down in this function's body) mainnet-only, per
// this feature's operator directive that it must not be reachable/active on a
// testnet deployment at all — sourced from cmd/netmap/main.go's
// -wallet-http-enabled flag (default false). When false, those routes are
// simply never registered on the mux at all (a real 404, not a
// registered-but-failing route — see this function's body, at those routes'
// registration sites, for why that convention was chosen over the
// adminCreds/collectors "route registered but fails closed 503" convention
// used elsewhere in this function). adminCreds
// configures the HTTP Basic Auth gate in front of every /admin/* route
// (the submission review queue and the poll-now admin tool) — see
// internal/adminauth.Wrap's doc comment for the fail-closed-503 behavior
// when adminCreds isn't fully configured. collectors configures the
// X-Collector-Key gate in front of the single /internal/collectors/report
// route (the trusted remote-collector-satellite ingestion channel, see
// collector_report.go) — a map of collector_name -> CollectorConfig (see
// its own doc comment for the API-key + self_identity-allowlist shape),
// sourced from NETMAP_COLLECTOR_KEYS/NETMAP_COLLECTOR_SELF_ADDRESSES in
// cmd/netmap/main.go; see wrapCollectorAuth's doc comment for the
// fail-closed-503 behavior when it's empty/unconfigured, mirroring
// adminCreds' own fail-closed convention. statsCacheTTL
// configures GET /v1/stats' in-process response cache (see stats.go's
// statsCache/handleStats/DefaultStatsCacheTTL) — callers that don't care
// can pass DefaultStatsCacheTTL. directoryCacheTTL configures GET
// /v1/directory's own in-process, per-query-param-combination response
// cache (see directory.go's directoryCache/handleDirectory/
// DefaultDirectoryCacheTTL) — callers that don't care can pass
// DefaultDirectoryCacheTTL. extendedMapCacheTTL configures GET
// /nodes/map/extended's own in-process, whole-response cache (see
// mapextended.go's extendedMapCache/handleNodesMapExtended/
// DefaultExtendedMapCacheTTL) -- callers that don't care can pass
// DefaultExtendedMapCacheTTL.
func NewRouter(store storage.Store, grpcClient, p2pClient, walletHTTPClient collector.NodeClient, walletHTTPEnabled bool, adminCreds adminauth.Credentials, collectors map[string]CollectorConfig, statsCacheTTL, directoryCacheTTL, extendedMapCacheTTL time.Duration) http.Handler {
	mux := http.NewServeMux()

	// Created once and shared across every POST /nodes call (NewRouter
	// itself is only called once, at process startup) — see
	// internal/api/ratelimit.go for both types' reasoning.
	limiter := newIPRateLimiter()
	lockouts := newInvalidSubmissionTracker()

	// Shared, bounded worker pool for the best-effort, non-blocking submission
	// probes kicked off by handleCreateNode and handleCreateWalletNodeSubmission
	// below (see asyncpool.go's doc comment for the full rationale and the
	// prod incident this fixes) -- one instance per NewRouter call, matching
	// limiter/lockouts' own process-lifetime convention.
	probePool := newAsyncProbePool()

	// pollWalletHTTPClient is what gets passed into collector.PollOnce at the two
	// OLD-flow call sites below (handleApproveSubmission's async post-approval poll,
	// handlePollNow's admin force-poll) -- deliberately nil'd out whenever
	// walletHTTPEnabled is false, so this mainnet-only feature gate ALSO covers those
	// two pre-existing call sites, not just the new wallet-node registration routes
	// registered further down. Without this, a node that already has a non-nil
	// WalletHTTPPort (e.g. set via NETMAP_OWNED_WALLET_HTTP_ADDRESSES, or a leftover
	// value from manual DB testing, or from before this flag was turned off on this
	// deployment) would still get dialed over this transport by an admin poll-now/
	// approval action even with the feature flag off -- this closes that gap, mirroring
	// the scheduled collector loop's own c.WalletHTTPEnabled gate (see collector.go).
	pollWalletHTTPClient := walletHTTPClient
	if !walletHTTPEnabled {
		pollWalletHTTPClient = nil
	}

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// OpenAPI spec + served Swagger UI (see internal/api/openapi.go and
	// internal/docs/openapi.yaml). Registered here (not under /admin or
	// /internal) so they end up at GET /api/spec / GET /api/docs after
	// cmd/netmap/main.go's "/api" http.StripPrefix mount — same public,
	// unauthenticated trust level as GET /v1/stats/GET /v1/directory above.
	mux.HandleFunc("GET /spec", handleAPISpec)
	mux.HandleFunc("GET /docs", handleAPIDocs)

	mux.HandleFunc("GET /nodes", handleListNodes(store))
	mux.HandleFunc("POST /nodes", handleCreateNode(store, grpcClient, p2pClient, limiter, lockouts, probePool))
	mux.HandleFunc("GET /nodes/{id}", handleGetNode(store))
	mux.HandleFunc("GET /nodes/{id}/history", handleGetNodeHistory(store))
	mux.HandleFunc("GET /nodes/{id}/edges", handleGetNodeEdges(store))
	mux.HandleFunc("GET /topology", handleTopology(store))
	mux.HandleFunc("GET /topology/top-peered", handleTopPeeredNodes(store))

	// GET /nodes/map backs the /map dashboard page's spike (see
	// BRIEF.md): the owner-tagged+has_ipv4 node population, geo-resolved
	// to lat/lon via storage's geoip_cache table. Same trust level as
	// the other read routes above (GET /nodes, GET /topology) --
	// deliberately NOT under /admin. See handleNodesMap's doc comment
	// for the "not a new privacy exposure" argument in full.
	mux.HandleFunc("GET /nodes/map", handleNodesMap(store))

	// GET /nodes/map/extended is an ADDITIVE extension of GET
	// /nodes/map above (see mapextended.go / BRIEF.md): the exact same
	// `attributed` population, plus a second, aggregate-only
	// `anonymous` array of city-level clusters for the non-owner-tagged
	// population. Same public, unauthenticated trust level -- NOT under
	// /admin. GET /nodes/map itself is completely unchanged by this
	// route's existence.
	mux.HandleFunc("GET /nodes/map/extended", handleNodesMapExtended(store, extendedMapCacheTTL))

	// Whole-population node counts + network-height snapshot (see
	// internal/api/stats.go). Same trust level as the other read
	// routes above — deliberately NOT under /admin. Versioned
	// (/v1/stats, served as /api/v1/stats via cmd/netmap's /api/
	// StripPrefix mount) per Alex: "no reason not to version" — this
	// is the API's first versioned route; future breaking changes to
	// its response shape get their own /v2/ route instead of breaking
	// existing callers in place.
	mux.HandleFunc("GET /v1/stats", handleStats(store, statsCacheTTL))

	// GET /v1/directory backs a third-party directory feed (TariTalk
	// Nodes, see directory.go's doc comment / BRIEF.md's background)
	// that splits the whole node population into `attributed`
	// (owner-tagged) and `anonymous` (city/country-only geo, never
	// lat/lon, never a real address) populations. Same trust level and
	// versioning rationale as GET /v1/stats above — public,
	// unauthenticated, deliberately NOT under /admin.
	mux.HandleFunc("GET /v1/directory", handleDirectory(store, directoryCacheTTL))

	// Seed-node suggestion + Tari config.toml peer_seeds generator. Same
	// trust level as the other read routes above (GET /nodes, GET
	// /topology) — deliberately NOT under /admin. These are opted-in,
	// health-verified nodes, so — unlike every other node-returning
	// route in this file — they are NOT run through ScrubNode/PublicNode
	// (see handleListSeedCandidates' doc comment for why real addresses
	// are the entire point here). Both are additionally filtered to
	// exclude role=collector-tagged nodes (see collectorrole.go) — a
	// remote collector satellite's own advertised identity must never be
	// recommended as a peer to connect to.
	//
	// GET /nodes/seed_list and GET /nodes/seed_list_tari are plain
	// aliases of GET /nodes/seeds and GET /config/peer-seeds
	// respectively, under the route name remote collector satellites
	// poll every ~60s to refresh their own local peer cache (see
	// internal/remotestore) — same handler, same underlying query, same
	// collector-role filtering, just a second route name. There is
	// deliberately no separate response shape or query logic for these:
	// the population a satellite should draw its peer cache from is
	// exactly the same "opted-in and recently reachable" set every
	// other seed-node consumer already gets.
	mux.HandleFunc("GET /nodes/seeds", handleListSeedCandidates(store))
	mux.HandleFunc("GET /nodes/seed_list", handleListSeedCandidates(store))
	mux.HandleFunc("GET /config/peer-seeds", handleConfigPeerSeeds(store))
	mux.HandleFunc("GET /nodes/seed_list_tari", handleConfigPeerSeeds(store))

	// POST /wallet-nodes: the SEPARATE, mainnet-only wallet-sync-HTTP-port registration
	// flow (see PendingWalletSubmission's doc comment and this feature's dispatch brief
	// for the full rationale for why this is NOT a field on POST /nodes above). Reuses
	// the SAME limiter/lockouts instances as POST /nodes (both are similar-risk-profile
	// public write routes -- spinning up a second independent rate limiter here would be
	// a double-standard with no real justification).
	//
	// Registered on the mux at all ONLY when walletHTTPEnabled -- i.e. an unregistered
	// pattern 404s when this feature is off, rather than a registered-but-503 route. This
	// (route-not-registered, not fail-closed-503) is a DIFFERENT convention than
	// adminCreds/collectors' "always registered, fails closed 503 if unconfigured" below
	// -- deliberately so: adminCreds/collectors represent "a required secret happens to be
	// unset", which this codebase already treats as an operational misconfiguration worth
	// a 503; walletHTTPEnabled represents "this whole feature is deliberately, permanently
	// off for this deployment" (testnet), which is better modeled as "this route doesn't
	// exist here at all" than "exists but always errors".
	if walletHTTPEnabled {
		mux.HandleFunc("POST /wallet-nodes", handleCreateWalletNodeSubmission(store, walletHTTPClient, limiter, lockouts, probePool))
	}

	// Every /admin/* route — the submission review queue (list/approve/
	// reject) and the poll-now admin tool — is registered on its own
	// sub-mux and gated behind adminauth.Wrap as a single unit, so the
	// HTTP Basic Auth (and fail-closed-503-when-unconfigured) behavior
	// applies uniformly across all of them rather than being wired
	// per-route. poll-now lives under /admin too, alongside the
	// submissions sub-resource routes, rather than scattered elsewhere:
	// it isn't a submissions sub-resource itself, but it's equally an
	// admin-only tool, and keeping a single /admin prefix is simpler
	// than introducing a second protected prefix for one route.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /admin/submissions", handleListSubmissions(store))
	adminMux.HandleFunc("POST /admin/submissions/{id}/approve", handleApproveSubmission(store, grpcClient, p2pClient, pollWalletHTTPClient))
	adminMux.HandleFunc("POST /admin/submissions/{id}/reject", handleRejectSubmission(store))
	adminMux.HandleFunc("POST /admin/nodes/poll-now", handlePollNow(store, grpcClient, p2pClient, pollWalletHTTPClient))
	// /admin/wallet-submissions/* — the wallet-node registration review queue — is added
	// to this SAME adminMux/adminauth.Wrap unit (per this feature's dispatch brief: "don't
	// create a second admin-auth wrapper"), gated by the identical walletHTTPEnabled
	// route-registration convention as POST /wallet-nodes above.
	if walletHTTPEnabled {
		adminMux.HandleFunc("GET /admin/wallet-submissions", handleListWalletSubmissions(store))
		adminMux.HandleFunc("POST /admin/wallet-submissions/{id}/approve", handleApproveWalletSubmission(store, walletHTTPClient))
		adminMux.HandleFunc("POST /admin/wallet-submissions/{id}/reject", handleRejectWalletSubmission(store))
	}
	mux.Handle("/admin/", adminauth.Wrap(adminCreds, adminMux))

	// The trusted remote-collector-satellite ingestion channel (see
	// collector_report.go/collector_auth.go) — a single route, gated by
	// wrapCollectorAuth as its own protected sub-mux, mirroring the
	// adminMux pattern above but with a distinct, simpler trust model
	// (a per-collector API key via X-Collector-Key, not HTTP Basic
	// Auth) — separate from /admin/* since this isn't a human-operated
	// area at all.
	collectorMux := http.NewServeMux()
	collectorMux.HandleFunc("POST /internal/collectors/report", handleCollectorReport(store))
	mux.Handle("/internal/", wrapCollectorAuth(collectors, collectorMux))

	return mux
}

// defaultNodeListLimit is the GET /nodes page size used when the caller
// doesn't specify a `?limit=`. 100 is a reasonable "just show me a
// useful chunk" default for a human paging through the registry via the
// dashboard or the API directly.
const defaultNodeListLimit = 100

// maxNodeListLimit caps `?limit=` on GET /nodes regardless of what the
// caller asks for — bounds worst-case response size/query cost per
// request while still allowing a much bigger page than the default when
// genuinely needed.
const maxNodeListLimit = 500

// listNodesResponse is the GET /nodes response body: a page of nodes
// plus enough pagination metadata (Total, Limit, Offset, HasMore) for a
// caller to walk every page without needing to guess page count from
// len(Nodes) alone.
type listNodesResponse struct {
	Nodes   []PublicNode `json:"nodes"`
	Total   int          `json:"total"`
	Limit   int          `json:"limit"`
	Offset  int          `json:"offset"`
	HasMore bool         `json:"has_more"`
}

func handleListNodes(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := defaultNodeListLimit
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				n = defaultNodeListLimit
			}
			limit = n
		}
		if limit > maxNodeListLimit {
			limit = maxNodeListLimit
		}

		offset := 0
		if v := r.URL.Query().Get("offset"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				writeError(w, http.StatusBadRequest, errors.New("invalid offset"))
				return
			}
			offset = n
		}

		filter := storage.NodeFilter{
			DiscoverySource: storage.DiscoverySource(r.URL.Query().Get("discovery_source")),
			Owner:           r.URL.Query().Get("owner"),
			Limit:           limit,
			Offset:          offset,
		}

		nodes, err := store.ListNodes(r.Context(), filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		total, err := store.CountNodes(r.Context(), filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		nodeIDs := make([]uuid.UUID, len(nodes))
		for i, n := range nodes {
			nodeIDs[i] = n.ID
		}
		addrsByNode, err := store.ListNodeAddressesForNodes(r.Context(), nodeIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		public := make([]PublicNode, len(nodes))
		for i, n := range nodes {
			public[i] = ScrubNode(n, addrsByNode[n.ID])
		}

		writeJSON(w, http.StatusOK, listNodesResponse{
			Nodes:   public,
			Total:   total,
			Limit:   limit,
			Offset:  offset,
			HasMore: offset+len(nodes) < total,
		})
	}
}

// createNodeRequest is the POST /nodes request body: a public GRPC node
// registration submission.
type createNodeRequest struct {
	Host     string   `json:"host"`
	Port     flexPort `json:"port"`
	Label    string   `json:"label"`
	OwnerTag string   `json:"owner_tag"`
}

// flexPort unmarshals a JSON number or a numeric JSON string into an int.
// The API contract is a JSON number, but the dashboard's htmx form submits
// via the json-enc extension, which encodes all form fields (including
// <input type="number">) as JSON strings — so both are accepted.
type flexPort int

func (p *flexPort) UnmarshalJSON(data []byte) error {
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*p = flexPort(n)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("port must be a number")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return errors.New("port must be a number")
	}
	*p = flexPort(n)
	return nil
}

func handleCreateNode(store storage.Store, grpcClient, p2pClient collector.NodeClient, limiter *ipRateLimiter, lockouts *invalidSubmissionTracker, probePool *asyncProbePool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createNodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}

		ip := clientIP(r)

		// Escalating lockout for repeatedly-invalid submitters is
		// checked before anything else, including the flat rate
		// limit — a locked-out source shouldn't even burn one of its
		// rate-limit tokens re-attempting.
		if locked, remaining := lockouts.IsLockedOut(ip); locked {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
			writeError(w, http.StatusTooManyRequests, errors.New("this source has been temporarily blocked after repeated invalid submissions"))
			return
		}

		if !limiter.Allow(ip) {
			w.Header().Set("Retry-After", "3600")
			writeError(w, http.StatusTooManyRequests, errors.New("too many submissions from this source, try again later"))
			return
		}

		if req.Host == "" {
			lockouts.RecordInvalidStrike(ip)
			writeError(w, http.StatusBadRequest, errors.New("host is required"))
			return
		}
		if req.Port < 1 || req.Port > 65535 {
			lockouts.RecordInvalidStrike(ip)
			writeError(w, http.StatusBadRequest, errors.New("port must be between 1 and 65535"))
			return
		}

		// Basic SSRF hardening: reject private/reserved IPs (this
		// service's own async health-check/probe machinery would
		// otherwise dial whatever's submitted here) and anything that
		// isn't a syntactically plausible public IP or .onion address.
		// See validateSubmittedHost's doc comment for the exact rules.
		if err := validateSubmittedHost(req.Host); err != nil {
			lockouts.RecordInvalidStrike(ip)
			writeError(w, http.StatusBadRequest, err)
			return
		}

		address := fmt.Sprintf("%s:%d", req.Host, req.Port)

		// A public submission of an address that's already publicly
		// opted-in (registry_submitted or both) must NOT be allowed to
		// silently merge into the existing node — that would let anyone
		// re-submit someone else's already-registered address and bump
		// its last_seen/merge tags/overwrite its label with zero
		// ownership check. Reject outright rather than queuing it for
		// review: there's nothing to review, the address already has an
		// owner of record. This is a well-formed, merely-conflicting
		// submission (not bad-faith malformed input), so no invalid
		// strike is recorded for it.
		optedIn, err := store.IsAddressPubliclyOptedIn(r.Context(), address)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if optedIn {
			writeError(w, http.StatusConflict, errors.New("this address is already publicly registered — contact the operator to update it"))
			return
		}

		// Hard cap on unreviewed queue size — a capacity problem, not a
		// fault of this particular submission, so no invalid strike
		// either.
		pendingCount, err := store.CountPendingSubmissions(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if pendingCount >= MaxPendingSubmissions {
			writeError(w, http.StatusServiceUnavailable, errors.New("submission queue is full, try again later"))
			return
		}

		var label *string
		if req.Label != "" {
			label = &req.Label
		}
		var ownerTag *string
		if req.OwnerTag != "" {
			ownerTag = &req.OwnerTag
		}

		// Submissions no longer auto-publish: they queue for human
		// review (see storage.PendingSubmission and
		// handleApproveSubmission/handleRejectSubmission below).
		// UpsertDiscoveredNode and the async health-check kickoff are
		// now deferred to approval time.
		submission, err := store.CreatePendingSubmission(r.Context(), address, label, ownerTag)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Best-effort, non-blocking connectivity probe for the human
		// reviewer's benefit — submitted to the shared, bounded probePool
		// (see asyncpool.go) rather than a bare `go`, so a flood of
		// submissions can never spawn unbounded probe goroutines/DB
		// connections. Uses its own context.Background()-derived timeout
		// (see probeSubmission's doc comment) since r.Context() is canceled
		// once this handler returns.
		probePool.Submit(func() {
			probeSubmission(store, grpcClient, p2pClient, submission.ID, address)
		})

		writeJSON(w, http.StatusAccepted, submission)
	}
}

// pollNowRequest is the POST /admin/nodes/poll-now request body: same host/port
// shape as createNodeRequest, minus the registry-submission-only fields
// (Label, OwnerTag) that don't apply to a forced admin probe.
type pollNowRequest struct {
	Host string   `json:"host"`
	Port flexPort `json:"port"`
}

// pollNowResponse is the POST /admin/nodes/poll-now response body. Unlike
// every other node-returning endpoint in this file, it returns the
// FULL, unscrubbed storage.Node (real address, real pubkey if
// confirmed) rather than going through ScrubNode/PublicNode — this
// endpoint is explicitly an internal admin/debugging tool operated
// directly by Alex on the private VLAN, not part of the public
// read API's privacy contract, and the whole point of this
// endpoint is giving him the real, current, post-probe node state
// to confirm things like a dual-stack merge actually happened.
type pollNowResponse struct {
	Node  storage.Node `json:"node"`
	Error string       `json:"error,omitempty"`
}

// handlePollNow forces a synchronous health-check probe of an
// address, bypassing the discovery/registry pipeline's usual async
// kickoff and review queue entirely. It validates that the submitted
// host is at least syntactically well-formed (validateHostSyntax), but
// deliberately does NOT call validateSubmittedHost — this is an
// internal admin-only endpoint (private VLAN, same trust model as the
// rest of the internal API, now additionally gated by HTTP Basic Auth
// via adminauth.Wrap in NewRouter above), and an admin must be able to
// force-poll local/private-network addresses for testing, so the
// private/reserved-IP SSRF check is skipped. Contrast with
// handleCreateNode's SSRF check above: that check exists because
// POST /nodes is reachable by untrusted public submitters, which is not
// the threat model here.
func handlePollNow(store storage.Store, grpcClient, p2pClient, walletHTTPClient collector.NodeClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req pollNowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}

		if req.Host == "" {
			writeError(w, http.StatusBadRequest, errors.New("host is required"))
			return
		}
		if req.Port < 1 || req.Port > 65535 {
			writeError(w, http.StatusBadRequest, errors.New("port must be between 1 and 65535"))
			return
		}

		// Syntax-only validation (must be a valid IP or a plausible
		// .onion address) — deliberately validateHostSyntax and NOT
		// validateSubmittedHost, since this endpoint intentionally
		// skips the latter's private/reserved-IP SSRF check (see this
		// handler's doc comment above).
		if err := validateHostSyntax(req.Host); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		address := fmt.Sprintf("%s:%d", req.Host, req.Port)

		node, err := store.UpsertDiscoveredNode(r.Context(), address, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Bounded probe timeout, same convention (and constant) as
		// the async health-check kickoff elsewhere in this file —
		// r.Context() alone has no deadline of its own here, and we
		// want this synchronous call to give up eventually rather
		// than hang on an unreachable node.
		ctx, cancel := context.WithTimeout(r.Context(), asyncCheckTimeout)
		defer cancel()

		// Synchronous, not launched via `go`: the whole point of this
		// endpoint is to force a probe and report back its result
		// immediately. A probe failure (unreachable node) is an
		// expected, useful result to report, not a fatal handler
		// error — PollOnce already records reachability failures as
		// rows, not via this returned error (see its doc comment), so
		// we don't abort on it; we still want to show the resulting
		// node state either way.
		pollErr := collector.PollOnce(ctx, grpcClient, p2pClient, walletHTTPClient, store, node)

		updated, err := store.GetNode(ctx, node.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		var errStr string
		if pollErr != nil {
			errStr = pollErr.Error()
		}
		writeJSON(w, http.StatusOK, pollNowResponse{Node: updated, Error: errStr})
	}
}

func handleListSubmissions(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")

		submissions, err := store.ListPendingSubmissions(r.Context(), status)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, submissions)
	}
}

// approveSubmissionResponse is the POST /admin/submissions/{id}/approve
// response body: the resulting promoted node alongside the now-approved
// submission.
type approveSubmissionResponse struct {
	Node       storage.Node              `json:"node"`
	Submission storage.PendingSubmission `json:"submission"`
}

func handleApproveSubmission(store storage.Store, grpcClient, p2pClient, walletHTTPClient collector.NodeClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid submission id"))
			return
		}

		submission, err := store.GetPendingSubmission(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, errors.New("submission not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if submission.Status != storage.SubmissionStatusPending {
			writeError(w, http.StatusConflict, fmt.Errorf("submission already reviewed (status=%s)", submission.Status))
			return
		}

		// Re-check opt-in status now, in case it changed since the
		// submission was originally queued (e.g. another submission for
		// the same address was approved in the meantime). If the
		// address has since become publicly opted-in, this approval is
		// rejected without mutating pending_submissions — it's left
		// pending so a human makes an explicit decision (reject it with
		// an accurate reason, since auto-rejecting on the reviewer's
		// behalf would hide why) rather than this silently flipping to
		// rejected on its own.
		optedIn, err := store.IsAddressPubliclyOptedIn(r.Context(), submission.Address)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if optedIn {
			writeError(w, http.StatusConflict, errors.New("this address has since become publicly registered — reject this submission instead of approving it"))
			return
		}

		tags := map[string]any{}
		if submission.OwnerTag != nil && *submission.OwnerTag != "" {
			tags["owner"] = *submission.OwnerTag
		}

		node, err := store.UpsertDiscoveredNode(r.Context(), submission.Address, storage.DiscoverySourceRegistry, tags, submission.Label)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		if err := store.ApprovePendingSubmission(r.Context(), id, node.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		submission.Status = storage.SubmissionStatusApproved
		submission.PromotedNodeID = &node.ID

		// Kick off an async health check, same pattern (and reasoning)
		// as the old handleCreateNode used to, just deferred to
		// approval time now.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), asyncCheckTimeout)
			defer cancel()
			_ = collector.PollOnce(ctx, grpcClient, p2pClient, walletHTTPClient, store, node)
		}()

		writeJSON(w, http.StatusOK, approveSubmissionResponse{Node: node, Submission: submission})
	}
}

// rejectSubmissionRequest is the optional POST /admin/submissions/{id}/reject
// request body.
type rejectSubmissionRequest struct {
	Reason string `json:"reason"`
}

func handleRejectSubmission(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid submission id"))
			return
		}

		var req rejectSubmissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}

		submission, err := store.GetPendingSubmission(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, errors.New("submission not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if submission.Status != storage.SubmissionStatusPending {
			writeError(w, http.StatusConflict, fmt.Errorf("submission already reviewed (status=%s)", submission.Status))
			return
		}

		var reason *string
		if req.Reason != "" {
			reason = &req.Reason
		}
		if err := store.RejectPendingSubmission(r.Context(), id, reason); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		submission.Status = storage.SubmissionStatusRejected
		submission.RejectionReason = reason

		writeJSON(w, http.StatusOK, submission)
	}
}

func handleGetNode(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid node id"))
			return
		}

		node, err := store.GetNode(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, errors.New("node not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		addrs, err := store.ListNodeAddresses(r.Context(), node.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, ScrubNode(node, addrs))
	}
}

func handleGetNodeHistory(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid node id"))
			return
		}

		limit := 20
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeError(w, http.StatusBadRequest, errors.New("invalid limit"))
				return
			}
			limit = n
		}

		history, err := store.GetNodeHistory(r.Context(), id, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, history)
	}
}

// nodeEdgesResponse is the GET /nodes/{id}/edges response body: every
// known peer_edges row touching the requested node, plus the
// privacy-scrubbed view of every distinct neighbor node those edges
// reference. This intentionally mirrors topologyResponse's {nodes, edges}
// shape (same convention as GET /topology) but gets its own named type
// since its docs describe a single node's neighborhood rather than the
// whole graph.
type nodeEdgesResponse struct {
	Nodes []PublicNode       `json:"nodes"`
	Edges []storage.PeerEdge `json:"edges"`
}

// handleGetNodeEdges powers the topology page's click-to-expand
// interaction (see topology.html.tmpl): given a node id, it returns that
// node's known peer edges plus a scrubbed view of every distinct neighbor
// node they reference, so the client can incrementally grow the
// force-directed graph outward from an initial small seed (the
// top-peered set from GET /topology/top-peered) instead of ever needing
// the full, unbounded GET /topology response.
//
// Deliberately does NOT 404 on an id with zero edges (or one that
// doesn't correspond to any real node at all) — ListNodeEdges's own doc
// comment confirms it returns an empty slice rather than erroring in
// that case, and mirroring that "empty, not an error" semantics here
// means the client-side expand logic doesn't need a special case for a
// leaf node with no (yet-discovered) peers.
//
// Confirmed-neighbors-only filtering (Alex's decision): both the
// returned nodes and edges are restricted to neighbors with a non-empty
// PublicKey (i.e. "confirmed" in the same sense as PublicNode's
// PublicKey doc comment / ScrubNode). Unconfirmed peers are noise here —
// only ~3% of the ~3100+ real nodes in the network are confirmed — and
// an unconfirmed node has no pubkey identity worth showing on the
// topology graph anyway. Any edge whose non-center endpoint is an
// unconfirmed (or otherwise filtered-out) neighbor is dropped too, so
// the response never contains a dangling edge reference to a node not
// present in its own nodes slice.
func handleGetNodeEdges(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid node id"))
			return
		}

		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeError(w, http.StatusBadRequest, errors.New("invalid limit"))
				return
			}
			limit = n
		}

		edges, err := store.ListNodeEdges(r.Context(), id, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Collect the set of distinct neighbor ids referenced by these
		// edges — every FromNodeID/ToNodeID that isn't the requested
		// node itself. A dedup map, not a slice, both to avoid loading
		// the same neighbor twice when multiple edges share it and to
		// naturally no-op on a (currently impossible, but not worth
		// crashing over) self-edge.
		neighborSet := make(map[uuid.UUID]struct{}, len(edges)*2)
		for _, e := range edges {
			if e.FromNodeID != id {
				neighborSet[e.FromNodeID] = struct{}{}
			}
			if e.ToNodeID != id {
				neighborSet[e.ToNodeID] = struct{}{}
			}
		}
		neighborIDs := make([]uuid.UUID, 0, len(neighborSet))
		for nid := range neighborSet {
			neighborIDs = append(neighborIDs, nid)
		}

		// Batch address lookup (same style as handleTopology's existing
		// node-loading loop) rather than N+1 ListNodeAddresses calls.
		addrsByNode, err := store.ListNodeAddressesForNodes(r.Context(), neighborIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// confirmedNeighborIDs tracks which neighbors made it into nodes
		// below (non-empty PublicKey only) — used afterward to filter
		// edges down to only those touching a confirmed neighbor.
		confirmedNeighborIDs := make(map[uuid.UUID]struct{}, len(neighborIDs))
		nodes := make([]PublicNode, 0, len(neighborIDs))
		for _, nid := range neighborIDs {
			n, err := store.GetNode(r.Context(), nid)
			if err != nil {
				// A neighbor referenced by an edge but since deleted
				// (deleted mid-flight) shouldn't fail the whole
				// request — just skip it and return what we can.
				if errors.Is(err, storage.ErrNotFound) {
					continue
				}
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if len(n.PublicKey) == 0 {
				// Unconfirmed — excluded, see doc comment above.
				continue
			}
			confirmedNeighborIDs[nid] = struct{}{}
			nodes = append(nodes, ScrubNode(n, addrsByNode[nid]))
		}

		// Filter edges down to only those whose non-center endpoint is a
		// confirmed neighbor, so the response never references a
		// neighbor that got excluded from nodes above.
		confirmedEdges := make([]storage.PeerEdge, 0, len(edges))
		for _, e := range edges {
			other := e.FromNodeID
			if other == id {
				other = e.ToNodeID
			}
			if _, ok := confirmedNeighborIDs[other]; ok {
				confirmedEdges = append(confirmedEdges, e)
			}
		}

		// edges carry only from_node_id/to_node_id UUIDs (see
		// storage.PeerEdge) — no address data, so no scrubbing needed,
		// same as handleTopology's edges.
		writeJSON(w, http.StatusOK, nodeEdgesResponse{Nodes: nodes, Edges: confirmedEdges})
	}
}

// defaultTopologyMaxNodes bounds the default GET /topology response to
// the top 300 best-connected nodes by peer-degree. Rationale: an
// unbounded topology response on a large network can run into the
// megabytes (observed ~4.8MB unpaginated in production) — well past what
// a client needs to render a useful graph. 300 nodes keeps the response
// size manageable while still showing the well-connected core of the
// network (the part mining-pool operators actually care about when
// picking peers). Callers that genuinely want everything can pass
// `?all=true`; callers that want a different explicit cap can pass
// `?limit=N`.
const defaultTopologyMaxNodes = 300

// defaultTopologyMaxEdges bounds the default GET /topology response's
// edge count independently of defaultTopologyMaxNodes. Rationale: even
// with the node cap in place, the edge count among the capped node set
// can still be large (observed ~11,616 edges / ~2.8MB in production).
// Alex's suggested range was 2000-3000; 2500 is the midpoint, keeping the
// response well below that previous measurement while still showing a
// meaningful subset of the core topology's edges. Callers that genuinely
// want everything can pass `?all=true`; callers that want a different
// explicit cap can pass `?max_edges=N`.
const defaultTopologyMaxEdges = 2500

// topologyResponse is the GET /topology response body.
type topologyResponse struct {
	Nodes []PublicNode       `json:"nodes"`
	Edges []storage.PeerEdge `json:"edges"`
}

func handleTopology(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		maxNodes := defaultTopologyMaxNodes
		maxEdges := defaultTopologyMaxEdges

		if v := r.URL.Query().Get("all"); v != "" {
			all, err := strconv.ParseBool(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New("invalid all"))
				return
			}
			if all {
				maxNodes = 0
				maxEdges = 0
			}
		}

		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeError(w, http.StatusBadRequest, errors.New("invalid limit"))
				return
			}
			maxNodes = n
		}

		if v := r.URL.Query().Get("max_edges"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeError(w, http.StatusBadRequest, errors.New("invalid max_edges"))
				return
			}
			maxEdges = n
		}

		nodes, edges, err := store.ListTopology(r.Context(), storage.TopologyFilter{MaxNodes: maxNodes, MaxEdges: maxEdges})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Exclude role=collector-tagged nodes (see collectorrole.go) — a remote collector
		// satellite's own advertised identity must never be recommended as a peer to
		// connect to via the topology graph. Edges are filtered alongside so the response
		// never dangles a reference to an excluded node, preserving ListTopology's own
		// "every edge's endpoints are both present in the returned node list" invariant.
		nodes = filterOutCollectorNodes(nodes)
		keptNodeIDs := make(map[uuid.UUID]bool, len(nodes))
		for _, n := range nodes {
			keptNodeIDs[n.ID] = true
		}
		filteredEdges := make([]storage.PeerEdge, 0, len(edges))
		for _, e := range edges {
			if keptNodeIDs[e.FromNodeID] && keptNodeIDs[e.ToNodeID] {
				filteredEdges = append(filteredEdges, e)
			}
		}
		edges = filteredEdges

		nodeIDs := make([]uuid.UUID, len(nodes))
		for i, n := range nodes {
			nodeIDs[i] = n.ID
		}
		addrsByNode, err := store.ListNodeAddressesForNodes(r.Context(), nodeIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		public := make([]PublicNode, len(nodes))
		for i, n := range nodes {
			public[i] = ScrubNode(n, addrsByNode[n.ID])
		}
		// edges only carry from_node_id/to_node_id UUIDs (see
		// storage.PeerEdge) — no address data, so no scrubbing needed.
		writeJSON(w, http.StatusOK, topologyResponse{Nodes: public, Edges: edges})
	}
}

func handleTopPeeredNodes(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		since := time.Hour
		if v := r.URL.Query().Get("since"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New("invalid since"))
				return
			}
			since = d
		}

		limit := 20
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeError(w, http.StatusBadRequest, errors.New("invalid limit"))
				return
			}
			limit = n
		}

		degrees, err := store.TopPeeredNodes(r.Context(), time.Now().Add(-since), limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		public := make([]PublicNodeDegree, 0, len(degrees))
		for _, d := range degrees {
			// Exclude role=collector-tagged nodes (see collectorrole.go) — a remote
			// collector satellite's own advertised identity must never be recommended
			// as a peer to connect to. This costs one extra GetNode lookup per result
			// beyond what ScrubNodeDegree already does (see its own doc comment on the
			// existing, accepted N+1 pattern here — TopPeeredNodes results are capped at
			// limit).
			n, err := store.GetNode(r.Context(), d.NodeID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if IsCollectorRole(n.Tags) {
				continue
			}

			pd, err := ScrubNodeDegree(r.Context(), store, d)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			public = append(public, pd)
		}
		writeJSON(w, http.StatusOK, public)
	}
}

// PublicSeedCandidate is the public-facing DTO for a storage.SeedCandidate,
// returned by GET /nodes/seeds and used internally by GET
// /config/peer-seeds. PublicKey is hex-encoded explicitly
// (hex.EncodeToString), NOT left to Go's default []byte JSON marshaling
// (which would base64-encode it) — this endpoint exists specifically to
// feed a config generator that needs the hex format Tari's real
// config.toml peer_seeds lines actually use. This is deliberately
// different from other []byte fields elsewhere in this codebase (e.g.
// PublicNode.PublicKey), which may use Go's default base64 marshaling
// for a different reason — do not "fix" those to match this one, and do
// not change this one to match those.
type PublicSeedCandidate struct {
	NodeID    uuid.UUID `json:"node_id"`
	PublicKey string    `json:"public_key"`
	Label     *string   `json:"label,omitempty"`
	Addresses []string  `json:"addresses"`
}

// listSeedCandidatesResponse is the GET /nodes/seeds response body: the
// candidate list plus the actual `since` window applied (helpful for a
// caller that didn't pass an explicit `?since=` and wants to know what
// default was used).
type listSeedCandidatesResponse struct {
	Candidates []PublicSeedCandidate `json:"candidates"`
	Since      string                `json:"since"`
}

// parseSeedSinceParam parses the optional `?since=` duration override
// shared by GET /nodes/seeds and GET /config/peer-seeds, defaulting to
// storage.DefaultSeedHealthWindow — same time.ParseDuration
// validation/error convention as handleTopPeeredNodes' `?since=`
// handling above.
func parseSeedSinceParam(r *http.Request) (time.Duration, error) {
	since := storage.DefaultSeedHealthWindow
	if v := r.URL.Query().Get("since"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, errors.New("invalid since")
		}
		since = d
	}
	return since, nil
}

// handleListSeedCandidates returns the JSON list of suggested Tari seed
// nodes: opted-in (registry_submitted/both) AND recently reachable (see
// storage.Store.ListSeedCandidates' doc comment for the exact gate).
// Deliberately does NOT run results through ScrubNode/PublicNode's
// privacy redaction — a candidate here is, by construction, both
// opted-in and health-verified, and showing its real address(es) is the
// entire point of this endpoint (a future reader must not "fix" this by
// adding scrubbing back in).
func handleListSeedCandidates(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		since, err := parseSeedSinceParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		candidates, err := store.ListSeedCandidates(r.Context(), since)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Exclude role=collector-tagged candidates (see collectorrole.go) — a remote
		// collector satellite's own advertised identity must never be recommended as a
		// seed peer, even if it happens to also be opted-in/recently-reachable.
		candidates = filterOutCollectorSeedCandidates(candidates)

		public := make([]PublicSeedCandidate, len(candidates))
		for i, c := range candidates {
			public[i] = PublicSeedCandidate{
				NodeID:    c.NodeID,
				PublicKey: hex.EncodeToString(c.PublicKey),
				Label:     c.Label,
				Addresses: c.Addresses,
			}
		}

		writeJSON(w, http.StatusOK, listSeedCandidatesResponse{
			Candidates: public,
			Since:      since.String(),
		})
	}
}

// renderPeerSeedsTOML builds the real Tari config.toml text (matching
// tari/common/config/presets/b_peer_seeds.toml's format) for candidates,
// under a `[<network>.p2p.seeds]` header if network is non-empty, or the
// generic placeholder `[p2p.seeds]` header otherwise (network is used
// ONLY for this cosmetic header text — no other network-specific
// dispatch logic is in scope here). Only peer_seeds is emitted (no
// dns_seeds — there is no DNS-seed data source yet, out of scope for
// v1). Each candidate contributes one peer_seeds entry per address
// (`pubkey_hex + "::" + multiaddr`); an address that fails
// addressToMultiaddr conversion is skipped (that one line only) rather
// than failing the whole response — candidates are guaranteed a non-nil
// PublicKey by ListSeedCandidates' own public_key IS NOT NULL filter.
// Each line is built with strconv.Quote so it's always a correctly
// escaped/quoted TOML string, even though real hex/IP/onion data is not
// expected to need any escaping in practice.
func renderPeerSeedsTOML(candidates []storage.SeedCandidate, network string) string {
	header := "[p2p.seeds]"
	if network != "" {
		header = fmt.Sprintf("[%s.p2p.seeds]", network)
	}

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	sb.WriteString("peer_seeds = [\n")
	for _, c := range candidates {
		pubkeyHex := hex.EncodeToString(c.PublicKey)
		for _, addr := range c.Addresses {
			ma, err := addressToMultiaddr(addr)
			if err != nil {
				// Skip just this address line — a single unparseable
				// address must not take down the whole generated
				// config (see this func's doc comment).
				continue
			}
			sb.WriteString("    ")
			sb.WriteString(strconv.Quote(pubkeyHex + "::" + ma))
			sb.WriteString(",\n")
		}
	}
	sb.WriteString("]\n")
	return sb.String()
}

// handleConfigPeerSeeds returns real, ready-to-paste Tari config.toml
// text for the [p2p.seeds]/peer_seeds section, built from the same
// opted-in + recently-reachable candidate set as GET /nodes/seeds (same
// `?since=` override, same default window). `?network=` is accepted
// purely to control the TOML section header text (e.g.
// `[esmeralda.p2p.seeds]`); it has no other effect. Content-Type is
// text/plain rather than application/toml, chosen so the response
// previews as plain text directly in a browser rather than prompting a
// download.
func handleConfigPeerSeeds(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		since, err := parseSeedSinceParam(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		network := r.URL.Query().Get("network")

		candidates, err := store.ListSeedCandidates(r.Context(), since)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Exclude role=collector-tagged candidates (see collectorrole.go), same as
		// handleListSeedCandidates above.
		candidates = filterOutCollectorSeedCandidates(candidates)

		body := renderPeerSeedsTOML(candidates, network)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
