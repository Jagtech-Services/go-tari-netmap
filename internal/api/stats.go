package api

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// NodeCounts is the whole-population node count summary shared by the
// HTML dashboard (internal/web's dashboardCounts, built from this) and
// the JSON GET /v1/stats endpoint (handleStats below). It mirrors exactly
// what buildNodeTableData (internal/web/web.go) used to compute inline
// before this was factored out — same fields, same semantics.
type NodeCounts struct {
	Total    int
	P2P      int
	Registry int
	Both     int

	Confirmed       int
	Unconfirmed     int
	OnionCapable    int
	ClearnetCapable int
	ClearnetOnly    int

	// Confirmed24h is the number of confirmed nodes reachable at least
	// once in the last 24 hours — a DB-backed count computed
	// separately by FetchConfirmed24h, never by ComputeNodeCounts
	// (which has no DB access and no reachability data available from
	// its in-memory nodes/addrsByNode inputs). Only FetchNodeCounts
	// populates this field; ComputeNodeCounts always leaves it zero.
	Confirmed24h int
}

// ComputeNodeCounts computes NodeCounts from an already-fetched slice of
// nodes and their addresses (see storage.Store.ListNodeAddressesForNodes
// for addrsByNode's shape). It takes already-loaded data rather than
// fetching internally so callers that also need nodes/addrsByNode for
// something else (like internal/web's buildNodeTableData, which needs
// them to render per-row table data too) can share a single
// ListNodes/ListNodeAddressesForNodes round trip instead of querying
// twice; handleStats below, which has no other use for that data, fetches
// it itself just for this call.
//
// Confirmed/OnionCapable/ClearnetCapable/ClearnetOnly are derived via
// ScrubNode — the same single source of truth the rest of this
// package's privacy contract runs through — rather than reimplementing
// that classification here.
func ComputeNodeCounts(nodes []storage.Node, addrsByNode map[uuid.UUID][]storage.NodeAddress) NodeCounts {
	var counts NodeCounts

	for _, n := range nodes {
		counts.Total++
		switch n.DiscoverySource {
		case storage.DiscoverySourceP2P:
			counts.P2P++
		case storage.DiscoverySourceRegistry:
			counts.Registry++
		case storage.DiscoverySourceBoth:
			counts.Both++
		}

		pn := ScrubNode(n, addrsByNode[n.ID])
		if len(pn.PublicKey) > 0 {
			counts.Confirmed++
		} else {
			counts.Unconfirmed++
		}
		if pn.HasOnion {
			counts.OnionCapable++
		}
		if pn.HasIPv4 || pn.HasIPv6 {
			counts.ClearnetCapable++
		}
		if (pn.HasIPv4 || pn.HasIPv6) && !pn.HasOnion {
			counts.ClearnetOnly++
		}
	}

	return counts
}

// FetchNodeCounts is ComputeNodeCounts's fetch-then-compute convenience
// wrapper for callers (handleStats below, and cmd/netmap's own Prometheus
// collector-metrics gauges, see cmd/netmap/metrics.go's netmapMetrics.refresh)
// that have no other use for the underlying nodes/addrsByNode data and just
// want the whole-population counts. Exported so cmd/netmap can reuse this
// exact query/computation for its known-node-count gauges rather than
// duplicating the ListNodes/ListNodeAddressesForNodes/ComputeNodeCounts
// round trip.
func FetchNodeCounts(ctx context.Context, store storage.Store) (NodeCounts, error) {
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		return NodeCounts{}, err
	}

	nodeIDs := make([]uuid.UUID, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}
	addrsByNode, err := store.ListNodeAddressesForNodes(ctx, nodeIDs)
	if err != nil {
		return NodeCounts{}, err
	}

	counts := ComputeNodeCounts(nodes, addrsByNode)

	confirmed24h, err := FetchConfirmed24h(ctx, store)
	if err != nil {
		return NodeCounts{}, err
	}
	counts.Confirmed24h = confirmed24h

	return counts, nil
}

// FetchConfirmed24h returns the number of nodes that are BOTH confirmed
// (non-empty PublicKey) AND reachable at least once in the last 24
// hours. Unlike Confirmed/Unconfirmed/OnionCapable/etc. above, this
// can't be derived from an already-fetched nodes/addrsByNode slice (the
// "reachable in the last 24h" condition depends on node_health rows,
// which ComputeNodeCounts' callers don't necessarily have loaded) — it
// always issues its own DB-backed store.CountNodes query, which is
// cheaper than a ListNodes-then-len() round trip since it never has to
// materialize the matching rows.
func FetchConfirmed24h(ctx context.Context, store storage.Store) (int, error) {
	confirmedTrue := true
	cutoff := time.Now().Add(-24 * time.Hour)
	return store.CountNodes(ctx, storage.NodeFilter{Confirmed: &confirmedTrue, ReachableSince: &cutoff})
}

// statsResponse is the GET /v1/stats response body: the same whole-
// population node counts shown on the HTML dashboard (see NodeCounts),
// plus the network-height context also shown there. NetworkHeight is
// nullable (*int64), matching storage.Store.NetworkHeight's own return —
// it is genuinely unknown until at least one health check with a height
// has been recorded.
type statsResponse struct {
	TotalNodes         int `json:"total_nodes"`
	ConfirmedNodes     int `json:"confirmed_nodes"`
	UnconfirmedNodes   int `json:"unconfirmed_nodes"`
	P2PDiscovered      int `json:"p2p_discovered"`
	RegistryDiscovered int `json:"registry_discovered"`
	BothDiscovered     int `json:"both_discovered"`
	OnionCapable       int `json:"onion_capable"`
	ClearnetCapable    int `json:"clearnet_capable"`
	ClearnetOnly       int `json:"clearnet_only"`

	// Confirmed24h is the number of confirmed nodes reachable at
	// least once in the last 24 hours (see NodeCounts.Confirmed24h /
	// FetchConfirmed24h). Distinct from, and always <=, ConfirmedNodes
	// above, which stays the lifetime, unfiltered confirmed count —
	// adding this field must never change ConfirmedNodes' meaning.
	Confirmed24h int `json:"confirmed_nodes_24h"`

	NetworkHeight          *int64 `json:"network_height"`
	NetworkHeightNodeCount int    `json:"network_height_node_count"`
}

// DefaultStatsCacheTTL is the default refresh interval
// handleStats' background-refresh cache (see BackgroundCache below) is
// built with when the caller doesn't override it — 60s, per Alex's
// explicit direction (bumped up from the previous 20s TTL as part of
// fixing the thundering-herd incident below: "make it a background
// task ... doesn't have to be super up to date all the time").
// cmd/netmap's -stats-cache-ttl flag defaults to this exact value;
// tests that don't care about cache timing specifically (i.e. every
// existing GET /v1/stats test, which each issue exactly one request
// per fresh server/store) also build their router with this default,
// since the background goroutine's own initial compute (not this TTL)
// is what their one request actually observes.
const DefaultStatsCacheTTL = 60 * time.Second

// handleStats' computed statsResponse is served from a
// BackgroundCache[statsResponse] (see backgroundcache.go) rather than
// the old on-demand, recompute-on-cache-miss TTL cache this type name
// used to be: a single long-lived goroutine (started in handleStats
// below) owns recomputing it on its own ttl-interval ticker, and every
// request only ever reads the last-computed value — there is no
// recompute path in the request handler at all anymore.
//
// Real prod incident this fixes (confirmed via a live SIGQUIT
// goroutine dump captured directly from the failing process, not
// inferred): the OLD on-demand cache's "accepted tradeoff" of not
// deduplicating concurrent cache-miss requests was wrong at this
// population size. Every process restart (cache always starts cold)
// plus real external polling traffic (Alex confirmed GET /v1/stats is
// polled by real Tari ecosystem apps) let 12 concurrent GET /v1/stats
// requests all miss at once, each independently running the full
// unfiltered whole-population ListNodes+ListNodeAddressesForNodes
// query (115,397 nodes in prod at the time) and each holding its own
// huge in-memory result set while blocked waiting on a saturated
// Postgres connection pool (jackc/puddle/pgxpool.Acquire) — that pile
// of simultaneous whole-population snapshots, not a goroutine leak,
// drove a multi-GB RSS spike and ~700% CPU within ~2 minutes of a
// clean restart. A background-refresh cache makes this pile-up
// structurally impossible: there is only ever one in-flight compute,
// ever, run by BackgroundCache's own goroutine, never by an HTTP
// request.
type statsCache = BackgroundCache[statsResponse]

// handleStats serves GET /v1/stats: a simple, read-only JSON snapshot of the
// whole node population's counts (same numbers as the HTML dashboard's
// summary cards, see internal/web's dashboardCounts) plus NetworkHeight
// context, for callers that want the dashboard's headline numbers without
// scraping HTML. No pagination/filtering — this is a single
// whole-population snapshot, not a list, same public trust level as the
// other non-admin routes in this file (no auth).
//
// The full computed statsResponse is served from a background-refresh
// statsCache (see its doc comment above, and BackgroundCache in
// backgroundcache.go) keyed off ctx's lifetime and cacheTTL
// (DefaultStatsCacheTTL if the caller doesn't care) — a single
// goroutine recomputes it (FetchNodeCounts + store.NetworkHeight) on
// its own ticker; this handler never recomputes anything itself, only
// reads the cache's last value via Get. This changes zero behavior/
// response shape/JSON field names from before — the only observable
// difference is a bounded staleness window (cacheTTL) instead of a
// per-request recompute-on-miss, and — the actual fix — no more
// concurrent-miss pile-up, since there is no "miss" in the request path
// at all anymore. ctx controls the background goroutine's lifetime
// (e.g. cmd/netmap/main.go's process-lifetime signal.NotifyContext
// ctx) — see NewRouter's doc comment.
func handleStats(ctx context.Context, store storage.Store, cacheTTL time.Duration) http.HandlerFunc {
	cache := NewBackgroundCache(ctx, "stats", cacheTTL, func(ctx context.Context) (statsResponse, error) {
		counts, err := FetchNodeCounts(ctx, store)
		if err != nil {
			return statsResponse{}, err
		}

		height, heightNodeCount, err := store.NetworkHeight(ctx)
		if err != nil {
			return statsResponse{}, err
		}

		return statsResponse{
			TotalNodes:         counts.Total,
			ConfirmedNodes:     counts.Confirmed,
			UnconfirmedNodes:   counts.Unconfirmed,
			P2PDiscovered:      counts.P2P,
			RegistryDiscovered: counts.Registry,
			BothDiscovered:     counts.Both,
			OnionCapable:       counts.OnionCapable,
			ClearnetCapable:    counts.ClearnetCapable,
			ClearnetOnly:       counts.ClearnetOnly,

			Confirmed24h: counts.Confirmed24h,

			NetworkHeight:          height,
			NetworkHeightNodeCount: heightNodeCount,
		}, nil
	})

	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := cache.Get(r.Context())
		if err != nil {
			// Only reachable if the very first background compute
			// hasn't completed yet AND the request's own context was
			// canceled/timed out while waiting for it (e.g. client
			// gave up, or the server is shutting down) — see
			// BackgroundCache.Get's doc comment. Every request after
			// the first successful compute never takes this path.
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
