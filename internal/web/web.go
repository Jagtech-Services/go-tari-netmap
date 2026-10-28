// Package web serves the go-tari-netmap dashboard: a server-rendered htmx +
// Go html/template UI. No separate JS framework, no frontend build step.
// Public, no auth gate by design — except the /admin/* sub-area (the
// submission review page), which is HTTP Basic Auth-gated via
// internal/adminauth; see NewHandler.
package web

import (
	"context"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

//go:embed static/*.css
var staticFS embed.FS

// shortHexLen is the number of hex characters of a confirmed node's
// PublicKey shown inline in tables/headers before the "…" ellipsis. The
// full hex is still available via the identity's FullHex field for a
// title="" tooltip.
const shortHexLen = 12

// identity is the privacy-aware, pubkey-first display identity of a node:
// never the raw address. A node with no confirmed PublicKey yet
// (Confirmed == false) has empty ShortHex/FullHex and is rendered as an
// "unconfirmed" badge by the templates instead.
type identity struct {
	Confirmed bool
	ShortHex  string
	FullHex   string
}

// buildIdentity derives an identity from a node's raw PublicKey bytes.
func buildIdentity(publicKey []byte) identity {
	if len(publicKey) == 0 {
		return identity{}
	}
	full := hex.EncodeToString(publicKey)
	short := full
	if len(short) > shortHexLen {
		short = short[:shortHexLen] + "…"
	}
	return identity{Confirmed: true, ShortHex: short, FullHex: full}
}

// capabilities mirrors api.PublicNode's HasIPv4/HasIPv6/HasOnion booleans:
// what transports a node is known to have, without revealing any real
// address string unless the node has opted in (see PublicAddresses on the
// row/detail types below).
type capabilities struct {
	HasIPv4  bool
	HasIPv6  bool
	HasOnion bool
}

// scrubbedView bundles the three privacy-scrubbed fields every node
// display type in this package needs, derived from api.ScrubNode — the
// same single source of truth the JSON API uses to decide whether a real
// address string is safe to show (see internal/api/privacy.go's doc
// comment on PublicNode). Reusing ScrubNode here, rather than
// reimplementing the classification rule, is what guarantees the web
// layer can never accidentally show a p2p_discovered node's raw address.
type scrubbedView struct {
	Identity        identity
	Capabilities    capabilities
	PublicAddresses []string
}

// scrubForDisplay builds a scrubbedView for n given its known addresses
// addrs (see api.ScrubNode's doc comment for addrs' semantics — nil/empty
// is fine and falls back to n.Address).
func scrubForDisplay(n storage.Node, addrs []storage.NodeAddress) scrubbedView {
	pn := api.ScrubNode(n, addrs)
	return scrubbedView{
		Identity:        buildIdentity(pn.PublicKey),
		Capabilities:    capabilities{HasIPv4: pn.HasIPv4, HasIPv6: pn.HasIPv6, HasOnion: pn.HasOnion},
		PublicAddresses: pn.Addresses,
	}
}

// dashboardCounts summarizes the node population by discovery source and
// by privacy-relevant capability for the dashboard header.
type dashboardCounts struct {
	Total    int
	P2P      int
	Registry int
	Both     int

	Confirmed       int
	Unconfirmed     int
	OnionCapable    int
	ClearnetCapable int
	ClearnetOnly    int

	// Confirmed24h is the number of confirmed nodes reachable at
	// least once in the last 24 hours (see api.NodeCounts.Confirmed24h
	// / api.FetchConfirmed24h) — a separate DB-backed count from
	// Confirmed above, which stays the lifetime, unfiltered confirmed
	// total. Populated by buildNodeTableData via its own
	// store.CountNodes call, independent of the reachableSince
	// parameter that filters the paginated table rows.
	Confirmed24h int
}

// dashboardNodeRow is one row of a node table (the dashboard's or
// /network's), combining node data with its most recent health-check
// result (if any) and its privacy-scrubbed display fields.
type dashboardNodeRow struct {
	storage.Node
	LatestHealth *storage.HealthCheck

	Identity        identity
	Capabilities    capabilities
	PublicAddresses []string

	// LikelyDead reuses handleNodeDetail's heuristic (see
	// computeLikelyDead) against whatever history buildNodeTableData
	// fetched for this row's historyLimit. The main dashboard passes
	// historyLimit == 1, so this is always false there (not enough
	// history to ever satisfy the >= 3 threshold) — it's only
	// meaningful on /network, which passes historyLimit == 3.
	LikelyDead bool
}

// topPeeredRow is one row of the dashboard's "top peered" panel: a node's
// privacy-scrubbed identity plus its connectivity stats from
// storage.TopPeeredNodes.
type topPeeredRow struct {
	ID                    uuid.UUID
	Identity              identity
	Capabilities          capabilities
	PublicAddresses       []string
	Degree                int
	InDegree              int
	OutDegree             int
	OnionPeerCount        int
	ClearnetPeerCount     int
	LiveDegree            int
	LiveInDegree          int
	LiveOutDegree         int
	LiveOnionPeerCount    int
	LiveClearnetPeerCount int
}

// dashboardData is the template data for index.html.tmpl.
type dashboardData struct {
	Counts                 dashboardCounts
	Nodes                  []dashboardNodeRow
	NetworkHeight          *int64
	NetworkHeightNodeCount int
	TopPeered              []topPeeredRow
	TopPeeredWindowLabel   string

	// Node table pagination metadata (see handleDashboard). NodeTotal is
	// the count of the reachable-within-window filtered set that the
	// table itself is paginating through (see dashboardReachableWindow),
	// NOT Counts.Total — the table only ever shows nodes from that
	// filtered set, so pagination math must be based on its size, not
	// the whole population's. Counts.Total (the "Total nodes" summary
	// card) intentionally keeps reflecting the whole population and can
	// disagree with NodeTotal.
	NodePage       int
	NodeLimit      int
	NodeTotal      int
	NodeRangeStart int
	NodeRangeEnd   int
	HasPrevPage    bool
	HasNextPage    bool
	PrevPage       int
	NextPage       int
}

// networkData is the template data for network.html.tmpl (GET /network —
// see handleFullNetwork). Same whole-population summary counts and node
// table shape as dashboardData, but deliberately has no TopPeered/
// TopPeeredWindowLabel fields — that panel stays exclusively on the main
// dashboard.
type networkData struct {
	Counts                 dashboardCounts
	Nodes                  []dashboardNodeRow
	NetworkHeight          *int64
	NetworkHeightNodeCount int

	// Node table pagination metadata (see handleFullNetwork and
	// buildNodeTableData). Unlike dashboardData's NodeTotal, this IS
	// the same as Counts.Total — /network's table has no
	// ReachableSince filter, so it's paginating through the whole
	// population.
	NodePage       int
	NodeLimit      int
	NodeTotal      int
	NodeRangeStart int
	NodeRangeEnd   int
	HasPrevPage    bool
	HasNextPage    bool
	PrevPage       int
	NextPage       int
}

// nodeTablePagination is the pagination metadata buildNodeTableData
// computes for a paginated node table — the shared shape copied into
// both dashboardData's and networkData's flat Node*/HasPrevPage/etc.
// fields by their respective handlers.
type nodeTablePagination struct {
	Page       int
	Limit      int
	Total      int
	RangeStart int
	RangeEnd   int

	HasPrevPage bool
	HasNextPage bool
	PrevPage    int
	NextPage    int
}

// peerEdgeRow is one row of a node detail page's "peer connections" table:
// the OTHER node's privacy-scrubbed identity (never an address), the
// direction of the observed edge relative to the page's node, and when it
// was first/last observed.
type peerEdgeRow struct {
	OtherNodeID   uuid.UUID
	OtherIdentity identity
	Direction     string
	FirstSeen     time.Time
	LastSeen      time.Time
}

// nodeDetailData is the template data for node_detail.html.tmpl.
type nodeDetailData struct {
	Node storage.Node

	// History is the unfiltered (reachable and unreachable alike) most
	// recent health checks for this node. It is used only for
	// computeLikelyDead below — it is not rendered directly by the
	// template anymore. See RecentSuccessfulChecks for what actually
	// backs the "Recent history" table.
	History []storage.HealthCheck

	// RecentSuccessfulChecks holds the newest few (up to 3)
	// successful-only health checks, used to populate the "Recent
	// history" table. Unlike History above, this excludes unreachable
	// probes entirely rather than showing them with blank fields, so
	// the table only shows rows with meaningful data.
	RecentSuccessfulChecks []storage.HealthCheck

	Identity        identity
	Capabilities    capabilities
	PublicAddresses []string
	PeerEdges       []peerEdgeRow

	// LikelyDead is a simple, deliberately non-aggregate-query heuristic
	// computed from the already-fetched History slice — see
	// computeLikelyDead for exactly how it's derived.
	LikelyDead bool

	// IdentityUpdatedAt is the peer's own self-reported
	// identity-signature timestamp (storage.HealthCheck's
	// PeerIdentityUpdatedAt field) from the most recent successful
	// health check, fetched separately via
	// store.GetRecentSuccessfulHealthChecks rather than derived from
	// History: History's newest row can be a failed probe with every
	// such field nil, which would otherwise make this flicker to "—"
	// between successful checks even though the peer's last-known
	// identity timestamp hasn't actually changed. Nil if this node has
	// no successful health check on record yet, or none carried a
	// PeerIdentityUpdatedAt (e.g. every successful check so far was
	// over gRPC, which has no equivalent concept).
	IdentityUpdatedAt *time.Time

	// LastKnownVersion is the node's self-reported client version
	// (storage.HealthCheck's Version field) from the same most-recent
	// successful health check used for IdentityUpdatedAt above, for
	// the same reason: History's newest row can be a failed probe with
	// Version nil, which would otherwise make this flicker to "—"
	// between successful checks even though the last-known version
	// hasn't actually changed. Nil if this node has no successful
	// health check on record yet, or that check didn't carry a
	// Version.
	LastKnownVersion *string
}

// topPeeredWindow is the lookback window used to compute the dashboard's
// "top peered" panel: nodes with the most distinct peers observed within
// the last hour.
const topPeeredWindow = 1 * time.Hour

// topPeeredLimit caps the number of rows shown in the dashboard's "top
// peered" panel.
const topPeeredLimit = 10

// dashboardNodePageSize is the default page size for the dashboard's node
// table (`?page=` is 1-indexed; offset = (page-1)*limit).
const dashboardNodePageSize = 50

// dashboardNodeMaxPageSize caps a caller-supplied `?limit=` on the
// dashboard's node table.
const dashboardNodeMaxPageSize = 200

// nodeEdgesLimit caps the number of rows shown in a node detail page's
// "peer connections" table.
const nodeEdgesLimit = 50

// dashboardRowHistoryLimit is the number of history rows
// buildNodeTableData fetches per row on the main dashboard — just
// enough for LatestHealth, and deliberately too few (< 3) for
// computeLikelyDead to ever flag a row true there (see
// dashboardNodeRow.LikelyDead's doc comment).
const dashboardRowHistoryLimit = 1

// networkRowHistoryLimit is the number of history rows
// buildNodeTableData fetches per row on /network — enough to also
// compute computeLikelyDead's "3+ probes, zero successes" heuristic per
// row, at the cost of a slightly larger per-row GetNodeHistory call
// (still one query per visible row, same as the dashboard's, just with
// a bigger LIMIT).
const networkRowHistoryLimit = 3

// dashboardReachableWindow is the display-layer cutoff for "reachable
// recently enough to show in the main Nodes table" on the dashboard. It
// only affects what's rendered on this one page — nodes outside this
// window stay in the database and keep being probed by the collector
// exactly as before; they just aren't shown in the main table until
// they're reachable again. The whole-population summary cards
// (dashboardCounts) are deliberately unaffected by this window (see
// handleDashboard).
const dashboardReachableWindow = 24 * time.Hour

// windowLabel formats a lookback duration like topPeeredWindow into a
// short human string (e.g. "(last 1h)") for display next to a panel
// header, so the label stays in sync with the constant instead of being
// hardcoded separately. Unlike time.Duration.String() (which would
// render 1*time.Hour as "1h0m0s"), this drops zero-valued trailing
// units.
func windowLabel(d time.Duration) string {
	return "(last " + formatDuration(d) + ")"
}

// formatDuration renders d as a compact "1h", "30m", "1h30m"-style
// string, omitting any zero-valued hours/minutes/seconds components.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	out := ""
	if h > 0 {
		out += fmt.Sprintf("%dh", h)
	}
	if m > 0 {
		out += fmt.Sprintf("%dm", m)
	}
	if s > 0 {
		out += fmt.Sprintf("%ds", s)
	}
	return out
}

// computeLikelyDead delegates to storage.IsLikelyDead (see that
// function's doc comment for the full "3+ probes, zero successes"
// heuristic and rationale) — kept as a thin wrapper, rather than calling
// storage.IsLikelyDead directly at every call site below, purely so this
// file's existing doc comments/call sites (handleNodeDetail's
// nodeDetailData.LikelyDead, buildNodeTableData's per-row
// dashboardNodeRow.LikelyDead) didn't need to change name. Previously
// this and internal/collector's collectorLikelyDead were two
// independently-maintained copies of the same logic, kept in sync only
// by doc-comment cross-reference; both now share storage.IsLikelyDead
// instead.
func computeLikelyDead(history []storage.HealthCheck) bool {
	return storage.IsLikelyDead(history)
}

// DefaultDashboardCountsCacheTTL is the default TTL dashboardCountsCache
// is built with when the caller doesn't override it — 20s, matching
// internal/api's DefaultStatsCacheTTL (see PR #48's GET /v1/stats
// cache) for consistency: both caches bound the exact same underlying
// whole-population ListNodes/ListNodeAddressesForNodes query cost, just
// for different consumers (the JSON GET /v1/stats endpoint there, the
// HTML GET / and GET /network dashboard routes here).
// cmd/netmap's -dashboard-cache-ttl flag defaults to this exact value.
const DefaultDashboardCountsCacheTTL = 20 * time.Second

// dashboardCountsCache is a small in-process TTL cache for the
// whole-population dashboardCounts plus the addrsByNode map that feeds
// both it and every node table row's privacy-scrubbed capability
// fields (see buildNodeTableData) — the single unfiltered
// store.ListNodes(ctx, storage.NodeFilter{}) + ListNodeAddressesForNodes
// round trip that GET / (handleDashboard) and GET /network
// (handleFullNetwork) both compute today, unpaginated and identical
// regardless of which route triggered it. It also caches
// store.NetworkHeight's result (height + node count) alongside those
// counts, sharing this same entry/TTL/mutex rather than a second,
// independent cache — see networkHeight/networkHeightNodeCount fields
// below. Both handleDashboard and handleFullNetwork call
// store.NetworkHeight every request (see their own doc comments); prior
// to this, that call was NOT covered by this cache at all (unlike
// internal/api's GET /v1/stats' statsCache, which has always wrapped
// FetchNodeCounts and NetworkHeight together), so repeated GET //GET
// /network requests within the TTL window saw no speedup on this call
// even though the counts fetch was already being served from cache.
//
// One instance is created per NewHandler call (i.e. once per process,
// at router construction time) and passed to BOTH handleDashboard and
// handleFullNetwork — this is deliberately ONE shared cache entry, not
// two: a cache hit on GET / populates it for a subsequent GET /network
// within the same TTL window, and vice versa, since both routes would
// otherwise recompute the exact same queries.
//
// Guarded by a sync.RWMutex, mirroring internal/api/stats.go's
// statsCache (see PR #48) for consistency rather than inventing a
// second in-process caching pattern in this codebase.
//
// Accepted tradeoff (deliberately NOT implemented), same as
// statsCache: concurrent cache-miss requests are not deduplicated
// ("singleflight"-style) — two requests that both miss at the same
// moment will both recompute and both re-store the result. Acceptable
// given this query's low cost relative to request volume and
// read-mostly access pattern; see statsCache's doc comment for the
// full reasoning, which applies identically here.
type dashboardCountsCache struct {
	ttl time.Duration

	mu                     sync.RWMutex
	counts                 dashboardCounts
	addrsByNode            map[uuid.UUID][]storage.NodeAddress
	networkHeight          *int64
	networkHeightNodeCount int
	computedAt             time.Time
	valid                  bool
}

// get returns the cached whole-population counts, addrsByNode map, and
// NetworkHeight result (height + node count), and true, if the cache
// holds a value computed within the last ttl; otherwise it returns the
// zero value and false (cache miss/expiry — the caller must recompute
// and call set).
func (c *dashboardCountsCache) get() (dashboardCounts, map[uuid.UUID][]storage.NodeAddress, *int64, int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.valid || time.Since(c.computedAt) >= c.ttl {
		return dashboardCounts{}, nil, nil, 0, false
	}
	return c.counts, c.addrsByNode, c.networkHeight, c.networkHeightNodeCount, true
}

// set stores counts/addrsByNode/networkHeight/networkHeightNodeCount as
// the new cached value, stamped with the current time — the starting
// point for the next get's TTL check.
func (c *dashboardCountsCache) set(counts dashboardCounts, addrsByNode map[uuid.UUID][]storage.NodeAddress, networkHeight *int64, networkHeightNodeCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = counts
	c.addrsByNode = addrsByNode
	c.networkHeight = networkHeight
	c.networkHeightNodeCount = networkHeightNodeCount
	c.computedAt = time.Now()
	c.valid = true
}

// computeWholePopulationCounts performs the actual whole-population
// ListNodes/ListNodeAddressesForNodes/CountNodes round trip that
// dashboardCountsCache wraps — called only on a cache miss/expiry (see
// buildNodeTableData below). Unchanged from what this package always
// did inline before the cache was added: same queries, same
// ComputeNodeCounts computation, same Confirmed24h CountNodes call.
// Returns addrsByNode too since buildNodeTableData's per-row rendering
// needs it for whichever nodes end up in the current page — its keys
// are a superset of every possible page's node IDs, so it's cached and
// reused across both the whole-population counts pass and every
// paginated request within the TTL window, never reintroducing a
// per-node ListNodeAddresses N+1.
func computeWholePopulationCounts(ctx context.Context, store storage.Store) (dashboardCounts, map[uuid.UUID][]storage.NodeAddress, error) {
	var counts dashboardCounts

	// Unpaginated: dashboardCounts must reflect the WHOLE population,
	// never just the current page or any ReachableSince filter. This is
	// a separate query from the paginated one used for the rows in
	// buildNodeTableData, deliberately NOT reusing its
	// LIMIT/OFFSET/ReachableSince.
	allNodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		return counts, nil, err
	}

	allNodeIDs := make([]uuid.UUID, len(allNodes))
	for i, n := range allNodes {
		allNodeIDs[i] = n.ID
	}
	addrsByNode, err := store.ListNodeAddressesForNodes(ctx, allNodeIDs)
	if err != nil {
		return counts, nil, err
	}

	// Shared with the JSON GET /api/v1/stats endpoint (internal/api's
	// ComputeNodeCounts) rather than reimplementing this
	// counts-by-discovery-source/confirmation/capability loop here —
	// see its doc comment.
	nc := api.ComputeNodeCounts(allNodes, addrsByNode)
	counts = dashboardCounts{
		Total:    nc.Total,
		P2P:      nc.P2P,
		Registry: nc.Registry,
		Both:     nc.Both,

		Confirmed:       nc.Confirmed,
		Unconfirmed:     nc.Unconfirmed,
		OnionCapable:    nc.OnionCapable,
		ClearnetCapable: nc.ClearnetCapable,
		ClearnetOnly:    nc.ClearnetOnly,
	}

	// Confirmed24h: confirmed nodes reachable at least once in the
	// last 24 hours. Same DB-backed approach as internal/api/stats.go's
	// FetchConfirmed24h — a dedicated store.CountNodes call, using its
	// own cutoff24h local var, deliberately independent of any
	// per-request ReachableSince filter (which only ever filters the
	// paginated table rows, never this whole-population summary
	// count).
	confirmedTrue := true
	cutoff24h := time.Now().Add(-24 * time.Hour)
	confirmed24h, err := store.CountNodes(ctx, storage.NodeFilter{Confirmed: &confirmedTrue, ReachableSince: &cutoff24h})
	if err != nil {
		return counts, nil, err
	}
	counts.Confirmed24h = confirmed24h

	return counts, addrsByNode, nil
}

// buildNodeTableData fetches the whole-population dashboardCounts
// (Total/P2P/Registry/Both/Confirmed/Unconfirmed/OnionCapable/
// ClearnetCapable/ClearnetOnly — always unfiltered, regardless of
// reachableSince), store.NetworkHeight's result (height + node count),
// plus a paginated page of dashboardNodeRow for a node table.
// reachableSince nil means no filter (the full node population, for
// /network); non-nil applies that cutoff (the main dashboard's
// dashboardReachableWindow liveness view). page/limit/offset drive the
// SQL-level LIMIT/OFFSET of the paginated page; historyLimit controls
// how many HealthCheck rows are fetched per row (see
// dashboardRowHistoryLimit/networkRowHistoryLimit) — LatestHealth only
// ever needs the most recent one, but computeLikelyDead needs at least
// 3 to ever return true.
//
// This is shared, extract-don't-change logic behind both
// handleDashboard and handleFullNetwork: same whole-population counts
// and NetworkHeight queries, same per-row scrub+history+pagination-math
// shape, differing only in the ReachableSince filter and historyLimit
// each passes in.
//
// The whole-population counts/addrsByNode/NetworkHeight fetch
// (computeWholePopulationCounts + store.NetworkHeight) is served from
// cache when possible — see dashboardCountsCache's doc comment —
// falling back to a fresh fetch (which populates the cache for
// subsequent callers, including the OTHER route sharing this same
// cache instance) on a miss/expiry. On a cache hit, store.NetworkHeight
// is skipped entirely, same as ListNodes/ListNodeAddressesForNodes. The
// paginated LIMIT/OFFSET row fetch below is completely untouched by
// this cache either way.
func buildNodeTableData(ctx context.Context, store storage.Store, cache *dashboardCountsCache, reachableSince *time.Time, page, limit, offset, historyLimit int) (dashboardCounts, []dashboardNodeRow, nodeTablePagination, *int64, int, error) {
	var pagination nodeTablePagination

	counts, addrsByNode, networkHeight, networkHeightNodeCount, ok := cache.get()
	if !ok {
		var err error
		counts, addrsByNode, err = computeWholePopulationCounts(ctx, store)
		if err != nil {
			return counts, nil, pagination, nil, 0, err
		}
		networkHeight, networkHeightNodeCount, err = store.NetworkHeight(ctx)
		if err != nil {
			return counts, nil, pagination, nil, 0, err
		}
		cache.set(counts, addrsByNode, networkHeight, networkHeightNodeCount)
	}

	// Paginated: the actual SQL-level LIMIT/OFFSET query backing the
	// node table rows shown on this page, restricted to reachableSince
	// if non-nil. This is a display-only cut when non-nil — the
	// whole-population counts above are deliberately built from the
	// unfiltered allNodes query and never use this filter.
	pageNodes, err := store.ListNodes(ctx, storage.NodeFilter{ReachableSince: reachableSince, Limit: limit, Offset: offset})
	if err != nil {
		return counts, nil, pagination, nil, 0, err
	}

	var rows []dashboardNodeRow
	for _, n := range pageNodes {
		view := scrubForDisplay(n, addrsByNode[n.ID])
		row := dashboardNodeRow{
			Node:            n,
			Identity:        view.Identity,
			Capabilities:    view.Capabilities,
			PublicAddresses: view.PublicAddresses,
		}
		history, err := store.GetNodeHistory(ctx, n.ID, historyLimit)
		if err != nil {
			return counts, nil, pagination, nil, 0, err
		}
		if len(history) > 0 {
			row.LatestHealth = &history[0]
		}
		row.LikelyDead = computeLikelyDead(history)
		rows = append(rows, row)
	}

	// filteredTotal is the size of the SAME reachableSince-filtered set
	// pageNodes is a page of, used only for its len() as pagination
	// metadata below. When reachableSince is nil, that set IS the whole
	// population, so counts.Total (already computed above) can be
	// reused directly instead of firing a second identical query.
	filteredTotal := counts.Total
	if reachableSince != nil {
		filteredNodes, err := store.ListNodes(ctx, storage.NodeFilter{ReachableSince: reachableSince})
		if err != nil {
			return counts, nil, pagination, nil, 0, err
		}
		filteredTotal = len(filteredNodes)
	}

	pagination.Page = page
	pagination.Limit = limit
	pagination.Total = filteredTotal
	if len(pageNodes) > 0 {
		pagination.RangeStart = offset + 1
		pagination.RangeEnd = offset + len(pageNodes)
	}
	pagination.HasPrevPage = page > 1
	pagination.PrevPage = page - 1
	pagination.HasNextPage = offset+len(pageNodes) < filteredTotal
	pagination.NextPage = page + 1

	return counts, rows, pagination, networkHeight, networkHeightNodeCount, nil
}

// parseNodeTablePageParams parses the `?page=`/`?limit=` query params
// shared by both the dashboard's and /network's node tables, applying
// the same 1-indexed-page/default-page-size/max-page-size conventions
// (dashboardNodePageSize/dashboardNodeMaxPageSize) to both. Returns the
// resolved page, limit, and the SQL OFFSET derived from them.
func parseNodeTablePageParams(r *http.Request) (page, limit, offset int) {
	page = 1
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	limit = dashboardNodePageSize
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > dashboardNodeMaxPageSize {
		limit = dashboardNodeMaxPageSize
	}
	offset = (page - 1) * limit
	return page, limit, offset
}

// truncateAddress returns addr unchanged if it's at most maxLen
// characters, otherwise the first maxLen characters plus a "…" ellipsis.
// Mirrors buildIdentity's ShortHex/FullHex truncation convention for
// pubkeys, applied here to the top-peered panel's (potentially long,
// especially for onion v3) address strings — the full address is still
// available via a title="" tooltip in the template, same pattern as
// buildIdentity's FullHex.
func truncateAddress(addr string, maxLen int) string {
	if len(addr) <= maxLen {
		return addr
	}
	return addr[:maxLen] + "…"
}

// NewHandler returns an http.Handler serving the dashboard: a homepage
// summary + node table (with a registry-submission form posted via htmx
// directly to the /api/nodes JSON API), a per-node detail/history page,
// the static CSS stylesheet backing both, and the HTTP Basic Auth-gated
// /admin/submissions review page. adminCreds configures that gate — see
// internal/adminauth.Wrap's doc comment for the fail-closed-503 behavior
// when adminCreds isn't fully configured. dashboardCountsCacheTTL
// configures GET /'s and GET /network's shared in-process
// whole-population counts cache (see dashboardCountsCache/
// buildNodeTableData/DefaultDashboardCountsCacheTTL) — callers that
// don't care can pass DefaultDashboardCountsCacheTTL. walletHTTPEnabled
// mirrors internal/api.NewRouter's identically-named parameter (sourced from the same
// cmd/netmap/main.go -wallet-http-enabled flag) — when false, GET /wallet-nodes still
// renders (200, not 404 -- this is a read-only dashboard page, not a write endpoint, so
// there's no abuse-surface reason to hide its existence) but always shows the empty/
// disabled state (see handleWalletNodes), never querying storage.Store.ListNodes at all.
func NewHandler(store storage.Store, adminCreds adminauth.Credentials, dashboardCountsCacheTTL time.Duration, walletHTTPEnabled bool) (http.Handler, error) {
	// derefBool is registered as a template func because Go's
	// text/template `{{if}}` truth test on a pointer only checks
	// non-nil-ness, not the pointed-to value — a *bool pointing at
	// false would otherwise render as "true" in
	// submissions.html.tmpl's probe-result cell. Used to distinguish
	// nil (not yet probed) from a genuine false (unreachable).
	tmpl, err := template.New("web").Funcs(template.FuncMap{
		"derefBool":       func(b *bool) bool { return b != nil && *b },
		"truncateAddress": truncateAddress,
		// formatUptime renders a walletNodeRow.UptimePercent (*float64, 0-100, nil if
		// no samples yet) as "NN.N%" -- needed because a raw {{printf "%.1f%%" .}} on a
		// *float64 would print the pointer, not the pointed-to value (text/template
		// does not auto-dereference for Printf-style verbs).
		"formatUptime": func(pct *float64) string {
			if pct == nil {
				return "—"
			}
			return fmt.Sprintf("%.1f%%", *pct)
		},
	}).ParseFS(templatesFS, "templates/*.tmpl")
	if err != nil {
		return nil, err
	}

	// Shared by handleDashboard and handleFullNetwork — see
	// dashboardCountsCache's doc comment for why this must be ONE
	// instance, not one per handler.
	countsCache := &dashboardCountsCache{ttl: dashboardCountsCacheTTL}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleDashboard(tmpl, store, countsCache))
	mux.HandleFunc("GET /nodes/{id}", handleNodeDetail(tmpl, store))
	mux.HandleFunc("GET /topology", handleTopologyGraph(tmpl))
	mux.HandleFunc("GET /network", handleFullNetwork(tmpl, store, countsCache))
	mux.HandleFunc("GET /map", handleMapPage(tmpl))
	mux.HandleFunc("GET /wallet-nodes", handleWalletNodes(tmpl, store, walletHTTPEnabled))
	mux.HandleFunc("GET /static/style.css", handleStaticCSS)

	// The submission review page moved under /admin/* (see this
	// package's and internal/api's NewRouter doc comments) — it's the
	// only web-layer admin route today, but registered on its own
	// sub-mux (rather than directly on the top-level mux) so the
	// adminauth.Wrap gate below covers the whole /admin/ prefix
	// uniformly, matching internal/api.NewRouter's structure.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /admin/submissions", handleSubmissions(tmpl, store))
	mux.Handle("/admin/", adminauth.Wrap(adminCreds, adminMux))

	return mux, nil
}

func handleStaticCSS(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/style.css")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(data)
}

func handleDashboard(tmpl *template.Template, store storage.Store, countsCache *dashboardCountsCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		page, limit, offset := parseNodeTablePageParams(r)

		// The main dashboard's Nodes table is restricted to nodes
		// reachable within dashboardReachableWindow (see its doc
		// comment) — a display-only cut, the whole-population counts
		// buildNodeTableData returns are deliberately built from an
		// unfiltered query and don't use this cutoff at all.
		cutoff := time.Now().Add(-dashboardReachableWindow)
		counts, rows, pagination, height, heightNodeCount, err := buildNodeTableData(ctx, store, countsCache, &cutoff, page, limit, offset, dashboardRowHistoryLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := dashboardData{
			TopPeeredWindowLabel: windowLabel(topPeeredWindow),
			Counts:               counts,
			Nodes:                rows,
			NodePage:             pagination.Page,
			NodeLimit:            pagination.Limit,
			NodeTotal:            pagination.Total,
			NodeRangeStart:       pagination.RangeStart,
			NodeRangeEnd:         pagination.RangeEnd,
			HasPrevPage:          pagination.HasPrevPage,
			HasNextPage:          pagination.HasNextPage,
			PrevPage:             pagination.PrevPage,
			NextPage:             pagination.NextPage,
		}

		data.NetworkHeight = height
		data.NetworkHeightNodeCount = heightNodeCount

		degrees, err := store.TopPeeredNodes(ctx, time.Now().Add(-topPeeredWindow), topPeeredLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, nd := range degrees {
			n, err := store.GetNode(ctx, nd.NodeID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Exclude role=collector-tagged nodes (see api.IsCollectorRole) -- a remote
			// collector satellite's own advertised identity must never be recommended as a
			// peer, on the dashboard's top-peered panel any more than on the API's own GET
			// /topology/top-peered (which already excludes it -- this was the gap: this
			// package read the same underlying storage.TopPeeredNodes data unfiltered).
			if api.IsCollectorRole(n.Tags) {
				continue
			}
			addrs, err := store.ListNodeAddresses(ctx, nd.NodeID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			view := scrubForDisplay(n, addrs)
			data.TopPeered = append(data.TopPeered, topPeeredRow{
				ID:                    nd.NodeID,
				Identity:              view.Identity,
				Capabilities:          view.Capabilities,
				PublicAddresses:       view.PublicAddresses,
				Degree:                nd.Degree,
				InDegree:              nd.InDegree,
				OutDegree:             nd.OutDegree,
				OnionPeerCount:        nd.OnionPeerCount,
				ClearnetPeerCount:     nd.ClearnetPeerCount,
				LiveDegree:            nd.LiveDegree,
				LiveInDegree:          nd.LiveInDegree,
				LiveOutDegree:         nd.LiveOutDegree,
				LiveOnionPeerCount:    nd.LiveOnionPeerCount,
				LiveClearnetPeerCount: nd.LiveClearnetPeerCount,
			})
		}

		if err := tmpl.ExecuteTemplate(w, "index.html.tmpl", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// handleFullNetwork serves GET /network: the complete, unfiltered node
// population (all nodes, paginated — no ReachableSince filter), as a
// companion to handleDashboard's "/" view, which only shows nodes
// reachable within dashboardReachableWindow. This is the "show me
// everything, including likely-dead/stale nodes" view, so its
// per-row history fetch uses networkRowHistoryLimit (3, not 1) to also
// compute each row's LikelyDead badge via computeLikelyDead. It
// deliberately has no "top peered" panel — that stays exclusively on
// the main dashboard (see networkData's doc comment) — but does reuse
// the exact same whole-population summary counts and NetworkHeight
// fetch shown there.
func handleFullNetwork(tmpl *template.Template, store storage.Store, countsCache *dashboardCountsCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		page, limit, offset := parseNodeTablePageParams(r)

		// reachableSince is nil here — /network's table has no
		// liveness filter at all, unlike handleDashboard's.
		counts, rows, pagination, height, heightNodeCount, err := buildNodeTableData(ctx, store, countsCache, nil, page, limit, offset, networkRowHistoryLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := networkData{
			Counts:         counts,
			Nodes:          rows,
			NodePage:       pagination.Page,
			NodeLimit:      pagination.Limit,
			NodeTotal:      pagination.Total,
			NodeRangeStart: pagination.RangeStart,
			NodeRangeEnd:   pagination.RangeEnd,
			HasPrevPage:    pagination.HasPrevPage,
			HasNextPage:    pagination.HasNextPage,
			PrevPage:       pagination.PrevPage,
			NextPage:       pagination.NextPage,
		}

		data.NetworkHeight = height
		data.NetworkHeightNodeCount = heightNodeCount

		if err := tmpl.ExecuteTemplate(w, "network.html.tmpl", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// handleTopologyGraph serves the visual topology graph page. It is a
// near-static handler: it renders the page shell only, with no node/edge
// data passed in as Go template values. All graph data is fetched
// client-side from the already-scrubbed GET /api/topology JSON endpoint
// (see topology.html.tmpl's inline <script>) — this guarantees the graph
// can never bypass the one place the privacy contract (no raw addresses
// for p2p_discovered nodes) is enforced, api.ScrubNode.
func handleTopologyGraph(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "topology.html.tmpl", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// handleMapPage serves the /map spike page (see BRIEF.md). Like
// handleTopologyGraph, this is a near-static handler: it renders the
// page shell only, with no node data passed in as Go template values.
// All marker data is fetched client-side from the already privacy-aware
// GET /api/nodes/map JSON endpoint (see map.html.tmpl's inline
// <script>) — this guarantees the page can never bypass the one place
// the /map population predicate is enforced, api.isMapEligible (and
// its handler, api.handleNodesMap).
func handleMapPage(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.ExecuteTemplate(w, "map.html.tmpl", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// walletHTTPUptimeWindow is the lookback window handleWalletNodes uses for its uptime%
// column (see Store.WalletHTTPUptime's doc comment on the Store interface for why this
// mirrors NetworkHeight's existing 24h window rather than a purpose-built one -- there is no
// pre-existing "uptime%" concept anywhere else in this codebase to instead reuse verbatim).
const walletHTTPUptimeWindow = 24 * time.Hour

// walletNodeRow is one row of the /wallet-nodes dashboard page (see handleWalletNodes): a
// node that BOTH has a non-nil WalletHTTPPort AND has opted into public address exposure
// (discovery_source registry_submitted or both) -- see ScrubNode's doc comment for why both
// conditions are required, not just the first.
type walletNodeRow struct {
	NodeID uuid.UUID

	Identity identity

	// Address is "host:wallet_http_port" -- the SAME host as the node's own
	// privacy-scrub-permitted public address (see storage.Node.WalletHTTPPort's doc
	// comment: this port always pairs with that node's own address, never a different
	// host), just with the wallet-sync HTTP service's port substituted in.
	Address string

	// Height/LastChecked/Reachable come from the most recent
	// storage.ProbeSourceWalletHTTP node_health row for this node (see
	// Store.GetLatestHealthCheck), NOT from GetNodeHistory -- the same node may also be
	// polled over gRPC/P2P, and this page must show THIS transport's own latest result,
	// not whichever transport happened to be probed most recently.
	Height      *int64
	LastChecked *time.Time
	Reachable   bool
	HasHistory  bool

	// UptimePercent is 0-100 (already multiplied for direct template display), nil if
	// this node has zero storage.ProbeSourceWalletHTTP rows within
	// walletHTTPUptimeWindow yet.
	UptimePercent *float64
	SampleCount   int
}

// walletNodesData is the template data for wallet_nodes.html.tmpl. Enabled mirrors
// handleWalletNodes' walletHTTPEnabled parameter -- when false, Nodes is always empty and
// the template renders the standard empty-state row (see handleWalletNodes' doc comment),
// distinct from WindowLabel simply being ""/zero.
type walletNodesData struct {
	Nodes       []walletNodeRow
	WindowLabel string
	Enabled     bool
}

// handleWalletNodes serves the /wallet-nodes dashboard page: a monero.fail-style public list
// of nodes known to ALSO offer the Tari wallet-sync HTTP service (see
// Netmap-Wallet-HTTP-Port-Design-2026-09-19.md for the full feature background), so
// third-party wallets can pick one to sync against. Columns: IP:port, current height,
// uptime% (see walletNodeRow's doc comment).
//
// walletHTTPEnabled mirrors the SAME mainnet-only -wallet-http-enabled flag
// internal/api.NewRouter's identically-named parameter is sourced from (see
// cmd/netmap/main.go) -- when false, this handler returns the empty/disabled state
// WITHOUT ever querying store.ListNodes at all (this feature must not be
// reachable/active on a testnet deployment, per this feature's dispatch brief's operator
// directive #1 -- that applies to this dashboard page too, not just the write endpoints).
//
// Visibility (when enabled) is gated identically to every other address-revealing view in
// this codebase: store.ListNodes(HasWalletHTTPPort: true) only narrows by "has a
// wallet_http_port set" -- it does NOT itself decide visibility. Each candidate node is
// still run through api.ScrubNode (the SAME single source of truth every other route/page
// in this codebase uses), and only included in the page at all if BOTH pn.Addresses and
// pn.WalletHTTPPort came back non-nil/non-empty (i.e. this node's discovery_source permits
// address exposure). There is no separate, ungated path to this data -- see api.ScrubNode's
// doc comment and this feature's hard safety rule #4.
func handleWalletNodes(tmpl *template.Template, store storage.Store, walletHTTPEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !walletHTTPEnabled {
			data := walletNodesData{Nodes: []walletNodeRow{}, WindowLabel: windowLabel(walletHTTPUptimeWindow), Enabled: false}
			if err := tmpl.ExecuteTemplate(w, "wallet_nodes.html.tmpl", data); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		ctx := r.Context()

		hasWalletHTTPPort := true
		nodes, err := store.ListNodes(ctx, storage.NodeFilter{HasWalletHTTPPort: &hasWalletHTTPPort})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rows := make([]walletNodeRow, 0, len(nodes))
		for _, n := range nodes {
			addrs, err := store.ListNodeAddresses(ctx, n.ID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// The scrub gate -- see this function's doc comment. A node whose
			// WalletHTTPPort is set but whose discovery_source doesn't (or no longer
			// does) permit address exposure is excluded entirely, not shown with a
			// blank address.
			pn := api.ScrubNode(n, addrs)
			if pn.WalletHTTPPort == nil || len(pn.Addresses) == 0 {
				continue
			}

			host, _, err := net.SplitHostPort(pn.Addresses[0])
			if err != nil || host == "" {
				continue
			}

			row := walletNodeRow{
				NodeID:   n.ID,
				Identity: buildIdentity(pn.PublicKey),
				Address:  net.JoinHostPort(host, strconv.Itoa(*pn.WalletHTTPPort)),
			}

			latest, err := store.GetLatestHealthCheck(ctx, n.ID, storage.ProbeSourceWalletHTTP)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if latest != nil {
				row.HasHistory = true
				row.Reachable = latest.Reachable
				row.Height = latest.Height
				t := latest.Timestamp
				row.LastChecked = &t
			}

			uptime, sampleCount, err := store.WalletHTTPUptime(ctx, n.ID, walletHTTPUptimeWindow)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if uptime != nil {
				pct := *uptime * 100
				row.UptimePercent = &pct
				row.SampleCount = sampleCount
			}

			rows = append(rows, row)
		}

		data := walletNodesData{Nodes: rows, WindowLabel: windowLabel(walletHTTPUptimeWindow), Enabled: true}
		if err := tmpl.ExecuteTemplate(w, "wallet_nodes.html.tmpl", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// submissionsData is the template data for submissions.html.tmpl.
type submissionsData struct {
	Submissions []storage.PendingSubmission
}

// handleSubmissions serves the human-facing submission review page: a
// server-rendered (Go html/template, not client-side JS) table of pending
// submissions, with Approve/Reject buttons that post directly to the JSON
// /api/admin/submissions/{id}/approve and /reject endpoints via htmx.
// This is a distinct route from the JSON GET /api/admin/submissions
// endpoint registered in internal/api — same path (under /admin),
// different mux, following this package's established web-vs-JSON-API
// split (see NewHandler's doc comment). Both this page and the JSON
// endpoints it posts to sit behind the same adminauth.Wrap gate.
func handleSubmissions(tmpl *template.Template, store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		submissions, err := store.ListPendingSubmissions(r.Context(), "pending")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := submissionsData{Submissions: submissions}
		if err := tmpl.ExecuteTemplate(w, "submissions.html.tmpl", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handleNodeDetail(tmpl *template.Template, store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid node id", http.StatusBadRequest)
			return
		}

		node, err := store.GetNode(ctx, id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		addrs, err := store.ListNodeAddresses(ctx, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		view := scrubForDisplay(node, addrs)

		history, err := store.GetNodeHistory(ctx, id, 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// See nodeDetailData.IdentityUpdatedAt's doc comment for why
		// this is its own GetRecentSuccessfulHealthChecks call rather
		// than derived from history above: history's newest row may be
		// a failed probe with no identity data at all. Limit is 3, per
		// Alex's explicit 2-3 request, so the "Recent history" table
		// has a few rows to show rather than just one.
		recentSuccessful, err := store.GetRecentSuccessfulHealthChecks(ctx, id, 3)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var identityUpdatedAt *time.Time
		var lastKnownVersion *string
		if len(recentSuccessful) > 0 {
			identityUpdatedAt = recentSuccessful[0].PeerIdentityUpdatedAt
			lastKnownVersion = recentSuccessful[0].Version
		}

		edges, err := store.ListNodeEdges(ctx, id, nodeEdgesLimit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := nodeDetailData{
			Node:                   node,
			History:                history,
			RecentSuccessfulChecks: recentSuccessful,
			Identity:               view.Identity,
			Capabilities:           view.Capabilities,
			PublicAddresses:        view.PublicAddresses,
			IdentityUpdatedAt:      identityUpdatedAt,
			LastKnownVersion:       lastKnownVersion,
		}

		// LikelyDead against the already-fetched 50-row history above —
		// no new aggregate query needed. See computeLikelyDead's doc
		// comment for the heuristic itself; also reused (with a much
		// shorter per-row history fetch) by buildNodeTableData for
		// /network's rows.
		data.LikelyDead = computeLikelyDead(history)

		for _, e := range edges {
			otherID := e.ToNodeID
			direction := "outbound"
			if e.FromNodeID != id {
				otherID = e.FromNodeID
				direction = "inbound"
			}

			otherNode, err := store.GetNode(ctx, otherID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			data.PeerEdges = append(data.PeerEdges, peerEdgeRow{
				OtherNodeID:   otherID,
				OtherIdentity: buildIdentity(otherNode.PublicKey),
				Direction:     direction,
				FirstSeen:     e.FirstSeen,
				LastSeen:      e.LastSeen,
			})
		}

		if err := tmpl.ExecuteTemplate(w, "node_detail.html.tmpl", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
