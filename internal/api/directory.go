package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// directoryClassAttributed/directoryClassAnonymous are the only two
// valid values of DirectoryNode.Class and the `?class=` query param
// (see handleDirectory below). The split is keyed OFF THE OWNER TAG
// (collector.HasOwnerTag) -- NEVER off storage.DiscoverySource -- per
// BRIEF.md: a node is very commonly discovery_source=p2p_discovered
// with an owner tag added on top later, so gating attribution on
// DiscoverySource would misclassify that real-world population as
// anonymous. DiscoverySource continues to control ONLY address-
// visibility (ScrubNode, unchanged).
const (
	directoryClassAttributed = "attributed"
	directoryClassAnonymous  = "anonymous"
)

// GeoPrecise is the full-precision geo projection included on an
// `attributed` DirectoryNode entry with a resolvable IPv4 address --
// the SAME already-consented lat/lon/city/country GET /nodes/map
// already exposes for exactly this population (see mapnodes.go's
// isMapEligible doc comment for the full "not a new privacy exposure"
// argument: the owner opted in via the public submission flow, and
// this address is already visible, unprojected, via GET /nodes).
type GeoPrecise struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	City      string  `json:"city"`
	Country   string  `json:"country"`
}

// GeoCoarse is the city/country-ONLY geo projection included on an
// `anonymous` DirectoryNode entry with a resolvable IPv4 address.
// Deliberately has NO Latitude/Longitude fields at all -- this is a
// genuinely new category of exposure beyond what GET /nodes/map does
// today (that endpoint never touches non-opted-in nodes), and the
// city/country-only cap is the explicit privacy boundary TariTalk
// Nodes' feed was scoped to accept (see BRIEF.md). Keeping this as its
// own Go type, with GeoPrecise's Latitude/Longitude fields structurally
// absent rather than present-but-zeroed, means a future refactor that
// tries to unify GeoPrecise/GeoCoarse into one shared field set fails
// to compile instead of silently leaking coordinates for an anonymous
// node -- a code reviewer can see the boundary at a glance instead of
// having to trust a runtime `if class == "anonymous" { ... }` branch
// that's one edit away from being deleted.
type GeoCoarse struct {
	City    string `json:"city"`
	Country string `json:"country"`
}

// DirectoryNode is one entry of the GET /v1/directory response body: a
// classification+coarse-geo feed for third-party consumers (see
// BRIEF.md's TariTalk Nodes background) -- NOT an address list. The
// real IPv4/IPv6/onion address string is NEVER included here, for ANY
// node, attributed or anonymous; GET /nodes remains the only route that
// returns real addresses, and only for opted-in nodes.
//
// GeoPrecise and GeoCoarse are never both set on the same entry --
// exactly one, or neither (no resolvable IPv4 / no geoip_cache entry
// yet / lookup failed), is ever populated, gated by Class (see
// classifyDirectoryNode below). See GeoCoarse's doc comment for why
// these are kept as two structurally distinct Go types rather than one
// shared field set.
type DirectoryNode struct {
	NodeID uuid.UUID `json:"node_id"`
	Label  string    `json:"label"`

	// Class is one of directoryClassAttributed/directoryClassAnonymous
	// -- see this file's const block doc comment for the owner-tag-not-
	// discovery-source classification rule.
	Class string `json:"class"`

	// Owner is the tags["owner"] value, included only for Class ==
	// "attributed" -- omitted (omitempty) for every anonymous entry,
	// matching this codebase's existing nullable-field JSON convention
	// (e.g. PublicSeedCandidate.Label's *string with omitempty in
	// api.go), just expressed as a plain string here since an
	// attributed node's owner is, by collector.HasOwnerTag's own
	// definition, always non-empty.
	Owner string `json:"owner,omitempty"`

	HasOnion  bool `json:"has_onion"`
	Confirmed bool `json:"confirmed"`

	GeoPrecise *GeoPrecise `json:"geo_precise,omitempty"`
	GeoCoarse  *GeoCoarse  `json:"geo_coarse,omitempty"`
}

// directoryResponse is the GET /v1/directory response body: a page of
// classified nodes plus the same pagination metadata shape as
// listNodesResponse (GET /nodes) -- Total/Limit/Offset/HasMore -- so a
// caller can walk every page without guessing page count from
// len(Nodes) alone.
type directoryResponse struct {
	Nodes   []DirectoryNode `json:"nodes"`
	Total   int             `json:"total"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
	HasMore bool            `json:"has_more"`
}

// DefaultDirectoryCacheTTL is the default TTL handleDirectory's
// in-process cache (see directoryCache below) is built with when the
// caller doesn't override it. Alex's explicit instruction was "let it
// get hammered" with a "5-10 second cache", picking 8s as the midpoint
// -- following the exact same "pick the midpoint of the operator's
// stated range" precedent DefaultStatsCacheTTL's own doc comment set
// (20s as the midpoint of a 15-30s range).
const DefaultDirectoryCacheTTL = 8 * time.Second

// directoryCacheEntry is one cached, already-computed directoryResponse
// plus the time it was computed at -- the per-key unit directoryCache
// stores below.
type directoryCacheEntry struct {
	response   directoryResponse
	computedAt time.Time
}

// directoryCache is handleDirectory's in-process TTL cache. Unlike
// stats.go's statsCache (a single cached value, since GET /v1/stats
// takes no query params), GET /v1/directory is parameterized
// (?owner=/?class=/?limit=/?offset=), so this caches the WHOLE computed
// directoryResponse per unique, normalized query-param combination --
// map[string]directoryCacheEntry keyed by that normalized query string
// (see directoryCacheKey below). One instance is created per
// handleDirectory call (i.e. once per process, at router-construction
// time -- see NewRouter), exactly mirroring statsCache's
// once-per-process, sync.RWMutex-guarded, get()/set() shape -- this is
// deliberately the SAME pattern, not a different caching approach,
// just keyed instead of single-valued.
type directoryCache struct {
	ttl time.Duration

	mu      sync.RWMutex
	entries map[string]directoryCacheEntry
}

// get returns the cached response for key and true if it exists and is
// still within ttl of when it was computed; otherwise it returns the
// zero value and false (cache miss/expiry/never-computed -- the caller
// must recompute), mirroring statsCache.get's exact semantics.
func (c *directoryCache) get(key string) (directoryResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || time.Since(entry.computedAt) >= c.ttl {
		return directoryResponse{}, false
	}
	return entry.response, true
}

// set stores resp as the new cached value for key, stamped with the
// current time -- the starting point for the next get's TTL check.
func (c *directoryCache) set(key string, resp directoryResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]directoryCacheEntry)
	}
	c.entries[key] = directoryCacheEntry{response: resp, computedAt: time.Now()}
}

// directoryCacheKey builds the normalized cache key for one
// (owner, class, limit, offset) query-param combination -- called with
// the ALREADY-defaulted/clamped limit/offset (not the raw query string
// values), so e.g. an omitted `?limit=` and an explicit
// `?limit=100` (the default) collide on the same cache entry rather
// than needlessly computing/storing it twice.
func directoryCacheKey(owner, class string, limit, offset int) string {
	return fmt.Sprintf("owner=%s&class=%s&limit=%d&offset=%d", owner, class, limit, offset)
}

// classifyDirectoryNode reports n's directory class and, if attributed,
// its owner tag value -- the single place implementing BRIEF.md's core
// classification rule: keyed OFF collector.HasOwnerTag, never off
// n.DiscoverySource. See this file's const block doc comment for the
// full "why" (a p2p_discovered node with an owner tag added later must
// still classify as attributed).
func classifyDirectoryNode(n storage.Node) (class string, owner string) {
	if collector.HasOwnerTag(n) {
		// HasOwnerTag already confirmed tags["owner"] is a non-empty
		// string, so this type assertion cannot fail.
		owner, _ = n.Tags["owner"].(string)
		return directoryClassAttributed, owner
	}
	return directoryClassAnonymous, ""
}

// buildDirectoryResponse computes the full GET /v1/directory response
// for one (owner, class, limit, offset) request. It fetches the WHOLE
// node population unfiltered (store.ListNodes(ctx, storage.NodeFilter{}),
// same "no filter, fetch everything" convention stats.go/mapnodes.go
// already use) and does every bit of filtering/classification/
// pagination in Go, rather than pushing `?owner=`/`?class=` down into
// SQL -- classification depends on collector.HasOwnerTag, a predicate
// with no direct SQL equivalent in this codebase (storage.NodeFilter's
// existing Owned field mixes in the separate pool_owned boolean flag
// too, which is NOT part of this endpoint's classification rule -- see
// classifyDirectoryNode's doc comment), so there is no single SQL
// WHERE clause that would compute the same population this function
// does.
//
// Geo resolution mirrors handleNodesMap's exact read-through pattern
// (see mapnodes.go): a server-side store.GetGeoIPCache lookup, never a
// live outbound geoip call from this HTTP handler, and a node with no
// cache entry yet (or a persistently-failed lookup) simply omits its
// geo fields entirely rather than blocking or plotting a meaningless
// (0, 0) coordinate.
func buildDirectoryResponse(ctx context.Context, store storage.Store, owner, class string, limit, offset int) (directoryResponse, error) {
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		return directoryResponse{}, err
	}

	nodeIDs := make([]uuid.UUID, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}
	addrsByNode, err := store.ListNodeAddressesForNodes(ctx, nodeIDs)
	if err != nil {
		return directoryResponse{}, err
	}

	// candidate carries everything buildDirectoryResponse's second pass
	// (geo attachment) needs about one node that survived the
	// owner/class filters below, computed once per node up front rather
	// than re-derived per page entry.
	type candidate struct {
		node    storage.Node
		class   string
		owner   string
		ipv4    string
		hasIPv4 bool
	}

	var candidates []candidate
	ipSet := make(map[string]struct{})
	for _, n := range nodes {
		nodeClass, nodeOwner := classifyDirectoryNode(n)

		// `?owner=` narrows the attributed set to this owner only --
		// nodes not matching are excluded from the response entirely,
		// not just re-labeled (see BRIEF.md's query-param section).
		// An anonymous node (nodeOwner == "") can never match a
		// non-empty owner filter, so this also naturally excludes the
		// whole anonymous population whenever `?owner=` is set.
		if owner != "" && nodeOwner != owner {
			continue
		}

		// `?class=` restricts the response to just that one
		// population; omitted (class == "") means both.
		if class != "" && nodeClass != class {
			continue
		}

		addrs := addrsByNode[n.ID]
		ip, hasIPv4 := firstIPv4Address(n, addrs)
		if hasIPv4 {
			ipSet[ip] = struct{}{}
		}

		candidates = append(candidates, candidate{
			node:    n,
			class:   nodeClass,
			owner:   nodeOwner,
			ipv4:    ip,
			hasIPv4: hasIPv4,
		})
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	geoCache, err := store.GetGeoIPCache(ctx, ips)
	if err != nil {
		return directoryResponse{}, err
	}

	total := len(candidates)

	// Pagination is applied AFTER filtering/classification, over the
	// final matching population -- same semantics as handleListNodes'
	// Total/HasMore (Total is the full matching count, independent of
	// this page's size).
	start := offset
	if start > len(candidates) {
		start = len(candidates)
	}
	end := len(candidates)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	page := candidates[start:end]

	out := make([]DirectoryNode, 0, len(page))
	for _, c := range page {
		addrs := addrsByNode[c.node.ID]
		pn := ScrubNode(c.node, addrs)

		var label string
		if c.node.Label != nil {
			label = *c.node.Label
		}

		dn := DirectoryNode{
			NodeID: c.node.ID,
			Label:  label,
			Class:  c.class,
			// Confirmed mirrors ComputeNodeCounts' exact predicate
			// (stats.go): a non-empty PublicKey via ScrubNode.
			Confirmed: len(pn.PublicKey) > 0,
			HasOnion:  pn.HasOnion,
		}
		if c.class == directoryClassAttributed {
			dn.Owner = c.owner
		}

		if c.hasIPv4 {
			if entry, ok := geoCache[c.ipv4]; ok && !entry.LookupFailed {
				switch c.class {
				case directoryClassAttributed:
					// Full precision -- mirrors GET /nodes/map exactly
					// for this exact already-consented population (see
					// GeoPrecise's doc comment).
					dn.GeoPrecise = &GeoPrecise{
						Latitude:  entry.Latitude,
						Longitude: entry.Longitude,
						City:      entry.City,
						Country:   entry.Country,
					}
				case directoryClassAnonymous:
					// City/country ONLY -- see GeoCoarse's doc comment
					// for why lat/lon must never appear here.
					dn.GeoCoarse = &GeoCoarse{
						City:    entry.City,
						Country: entry.Country,
					}
				}
			}
			// No cache entry yet, or a persistently-failed lookup:
			// both GeoPrecise/GeoCoarse stay nil -- omit rather than
			// plot a meaningless coordinate, same convention as
			// handleNodesMap.
		}

		out = append(out, dn)
	}

	return directoryResponse{
		Nodes:   out,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+len(out) < total,
	}, nil
}

// handleDirectory serves GET /v1/directory: a classification+coarse-geo
// feed for third-party consumers (see BRIEF.md's TariTalk Nodes
// background) that splits the whole node population into two named
// populations -- `attributed` (collector.HasOwnerTag true) and
// `anonymous` (false) -- keyed off the owner tag, never off
// storage.DiscoverySource (see this file's const block doc comment).
//
// Query params: `?owner=` (exact match, narrows the attributed set to
// one owner, excluding everything else), `?class=attributed|anonymous`
// (restricts to one population; omitted = both), `?limit=`/`?offset=`
// (same pagination convention -- and the same defaultNodeListLimit/
// maxNodeListLimit constants -- as GET /nodes' handleListNodes).
//
// The whole computed response is cached in-process for cacheTTL, keyed
// per unique (owner, class, limit, offset) combination (see
// directoryCache above and DefaultDirectoryCacheTTL) -- per Alex's
// explicit "let it get hammered" instruction, since this is a public,
// unauthenticated route a third party is expected to poll routinely. A
// cacheTTL <= 0 disables caching entirely (every request always misses
// and recomputes), falling out naturally from directoryCache.get's
// time.Since(...) >= ttl check without any special-casing, exactly
// mirroring handleStats' own cacheTTL <= 0 behavior.
//
// PRIVACY NOTE: see GeoCoarse's doc comment for the anonymous-population
// city/country-only cap this handler enforces via buildDirectoryResponse
// -- this is the one genuinely new exposure this endpoint introduces
// beyond what GET /nodes/map already does today, and it is a hard
// boundary, not a convenience default.
func handleDirectory(store storage.Store, cacheTTL time.Duration) http.HandlerFunc {
	cache := &directoryCache{ttl: cacheTTL}

	return func(w http.ResponseWriter, r *http.Request) {
		owner := r.URL.Query().Get("owner")

		class := r.URL.Query().Get("class")
		if class != "" && class != directoryClassAttributed && class != directoryClassAnonymous {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid class %q, must be %q or %q", class, directoryClassAttributed, directoryClassAnonymous))
			return
		}

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

		key := directoryCacheKey(owner, class, limit, offset)
		if resp, ok := cache.get(key); ok {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		resp, err := buildDirectoryResponse(r.Context(), store, owner, class, limit, offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		cache.set(key, resp)
		writeJSON(w, http.StatusOK, resp)
	}
}
