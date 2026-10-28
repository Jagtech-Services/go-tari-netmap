package api

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// ExtendedMapResponse is the GET /nodes/map/extended response body (see
// BRIEF.md): GET /nodes/map's exact existing attributed population
// (handleNodesMap/isMapEligible, unchanged) PLUS a second, deliberately
// differently-shaped array of aggregate, city-level markers for the
// anonymous (non-owner-tagged) population -- see AnonymousCluster's doc
// comment for exactly why these two arrays carry fundamentally different
// privacy guarantees and so cannot share one Go type.
type ExtendedMapResponse struct {
	Attributed []MapNode          `json:"attributed"`
	Anonymous  []AnonymousCluster `json:"anonymous"`
}

// AnonymousCluster is one aggregate, city-level marker for the
// non-owner-tagged (collector.HasOwnerTag false) node population with a
// resolvable IPv4 + geoip_cache entry (see buildExtendedMapResponse for
// the exact population/exclusion rules). Per BRIEF.md's TariTalk Nodes
// ask, this is a STRICTER privacy guarantee than directory.go's
// per-node anonymous DirectoryNode entries (which carry a node_id and
// confirmed/has_onion per node): an AnonymousCluster is aggregate-ONLY
// by design -- it never contains a node ID, a label, an address, or any
// other per-node identifying field, and never a wallet-availability
// signal (wallet_http_port) either, matching "would not be treated as
// ... available for wallet use." Do not add any per-node field to this
// type -- if a future caller needs a per-node anonymous view, that's
// exactly what GET /v1/directory's `class=anonymous` already is; this
// type must stay aggregate-only.
type AnonymousCluster struct {
	City            string    `json:"city"`
	Country         string    `json:"country"`
	Latitude        float64   `json:"latitude"`
	Longitude       float64   `json:"longitude"`
	ApproxNodeCount int       `json:"approx_node_count"`
	LastObservedAt  time.Time `json:"last_observed_at"`
}

// DefaultExtendedMapCacheTTL is the default TTL
// handleNodesMapExtended's in-process cache (see extendedMapCache
// below) is built with when the caller doesn't override it -- 20s,
// matching DefaultStatsCacheTTL's own precedent for a whole-population
// aggregate route with no query params to key a cache on.
const DefaultExtendedMapCacheTTL = 20 * time.Second

// extendedMapCache is handleNodesMapExtended's in-process TTL cache for
// the whole computed ExtendedMapResponse. Unlike directory.go's
// directoryCache (keyed per query-param combination), this endpoint has
// no query params at all, so a single cached value suffices -- this is
// exactly stats.go's statsCache shape, just caching a different response
// type. One instance is created per handleNodesMapExtended call (i.e.
// once per process, at router-construction time -- see NewRouter),
// guarded by a sync.RWMutex, matching this package's existing
// once-per-process cache convention.
type extendedMapCache struct {
	ttl time.Duration

	mu         sync.RWMutex
	response   ExtendedMapResponse
	computedAt time.Time
	valid      bool
}

// get returns the cached response and true if it exists and is still
// within ttl of when it was computed; otherwise it returns the zero
// value and false (cache miss/expiry -- the caller must recompute).
func (c *extendedMapCache) get() (ExtendedMapResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.valid || time.Since(c.computedAt) >= c.ttl {
		return ExtendedMapResponse{}, false
	}
	return c.response, true
}

// set stores resp as the new cached value, stamped with the current
// time -- the starting point for the next get's TTL check.
func (c *extendedMapCache) set(resp ExtendedMapResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.response = resp
	c.computedAt = time.Now()
	c.valid = true
}

// cityKey is the exact (city, country) string-match grouping key used
// both to bucket anonymous candidates into clusters and to build the
// attributed-population exclusion set below. Per BRIEF.md: exact string
// match on the geoip_cache entry's own City/Country fields -- no
// fuzzy/normalized matching. A pre-existing geoip-data-quality issue
// (the same real city resolving to two slightly different strings) is
// out of scope for this dispatch.
type cityKey struct {
	city    string
	country string
}

// buildExtendedMapResponse computes the full GET /nodes/map/extended
// response. It fetches the whole node population unfiltered (same
// "no filter, fetch everything" convention mapnodes.go/directory.go/
// stats.go already use) exactly once, and derives BOTH the attributed
// and anonymous halves from that single ListNodes/
// ListNodeAddressesForNodes/GetGeoIPCache round trip, rather than
// issuing it twice.
//
// role=collector exclusion (IsCollectorRole, see collectorrole.go) is
// applied FIRST, before either population's own predicate, and to BOTH
// populations: a remote collector satellite's own advertised identity
// must never show up on a public map, attributed or anonymous, same
// existing invariant elsewhere in this codebase
// (filterOutCollectorNodes/filterOutCollectorSeedCandidates). This
// matters concretely for a node that carries BOTH role=collector AND an
// owner tag: without checking role=collector first, such a node would
// satisfy isMapEligible below and leak into the attributed array.
//
// Attributed half (of the surviving, non-collector-role population):
// reuses isMapEligible's exact existing predicate -- same population,
// same shape, as GET /nodes/map (handleNodesMap) -- this dispatch does
// not change that endpoint's behavior at all.
//
// Anonymous half (of the surviving, non-collector-role population; see
// BRIEF.md's population + exclusion rule):
//  1. every node where collector.HasOwnerTag is false (mirrors
//     directory.go's classification -- keyed off the owner tag, never
//     storage.DiscoverySource) AND has a resolvable IPv4
//     (firstIPv4Address) AND a populated, non-LookupFailed geoip_cache
//     entry;
//  2. grouped by the exact (city, country) string pair from that
//     node's own geoip_cache entry;
//  3. any (city, country) cluster that also has at least one
//     already-computed attributed entry with that exact same
//     (city, country) is dropped entirely -- "if a city already has a
//     registered node, don't show an anonymous marker there";
//  4. for each surviving cluster: ApproxNodeCount is the number of
//     distinct nodes in it; LastObservedAt is MAX(nodes.last_seen)
//     across those nodes (computed here in Go from the already-fetched
//     nodes slice -- last_seen is already a plain column on nodes, no
//     new storage-layer query needed, following this repo's existing
//     "compute aggregates from an already-fetched node slice when
//     cheap enough" convention, see stats.go's ComputeNodeCounts);
//     Latitude/Longitude are the geoip_cache entry's own lat/lon from
//     one representative node in the cluster, chosen deterministically
//     by sorting the cluster's candidate node IDs and taking the first
//     (stable output ordering across requests, no averaging/centroid
//     math).
//
// A ?since=-style reachability/uptime gate is deliberately NOT applied
// anywhere in this function -- per BRIEF.md, the anonymous population's
// only gate is "has a resolvable IPv4 + geoip entry", nothing about
// health-check history ("not treated as verified, reliably online").
func buildExtendedMapResponse(ctx context.Context, store storage.Store) (ExtendedMapResponse, error) {
	nodes, err := store.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		return ExtendedMapResponse{}, err
	}

	nodeIDs := make([]uuid.UUID, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}
	addrsByNode, err := store.ListNodeAddressesForNodes(ctx, nodeIDs)
	if err != nil {
		return ExtendedMapResponse{}, err
	}

	// attributedCandidate/anonymousCandidate carry everything the
	// second pass (geo attachment/clustering) needs about one node
	// that survived the relevant population's filters, computed once
	// per node up front.
	type attributedCandidate struct {
		node storage.Node
		ipv4 string
	}
	type anonymousCandidate struct {
		node storage.Node
		ipv4 string
	}

	var attributedCandidates []attributedCandidate
	var anonymousCandidates []anonymousCandidate
	ipSet := make(map[string]struct{})

	for _, n := range nodes {
		// Exclude role=collector-tagged nodes (see collectorrole.go)
		// from BOTH populations up front -- a remote collector
		// satellite's own advertised identity must never show up on a
		// public map, attributed or anonymous, same existing
		// invariant elsewhere in this codebase (filterOutCollectorNodes/
		// filterOutCollectorSeedCandidates). This must be checked
		// before isMapEligible below: a collector-tagged node that
		// also happens to carry an owner tag would otherwise satisfy
		// isMapEligible and leak into the attributed array.
		if IsCollectorRole(n.Tags) {
			continue
		}

		addrs := addrsByNode[n.ID]

		if isMapEligible(n, addrs) {
			ip, _ := firstIPv4Address(n, addrs) // guaranteed ok, isMapEligible already checked
			attributedCandidates = append(attributedCandidates, attributedCandidate{node: n, ipv4: ip})
			ipSet[ip] = struct{}{}
			continue
		}

		// Anonymous candidates: no owner tag (mirrors
		// classifyDirectoryNode's rule, never DiscoverySource) AND a
		// resolvable IPv4.
		if collector.HasOwnerTag(n) {
			continue
		}
		ip, ok := firstIPv4Address(n, addrs)
		if !ok {
			continue
		}
		anonymousCandidates = append(anonymousCandidates, anonymousCandidate{node: n, ipv4: ip})
		ipSet[ip] = struct{}{}
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	geoCache, err := store.GetGeoIPCache(ctx, ips)
	if err != nil {
		return ExtendedMapResponse{}, err
	}

	// Build the attributed half first -- its (city, country) set drives
	// the anonymous exclusion rule below (BRIEF.md step 4).
	attributed := make([]MapNode, 0, len(attributedCandidates))
	excludedCities := make(map[cityKey]bool)
	for _, c := range attributedCandidates {
		entry, ok := geoCache[c.ipv4]
		if !ok || entry.LookupFailed {
			continue
		}

		var label string
		if c.node.Label != nil {
			label = *c.node.Label
		}
		pn := ScrubNode(c.node, addrsByNode[c.node.ID])
		attributed = append(attributed, MapNode{
			NodeID:    c.node.ID,
			Label:     label,
			Latitude:  entry.Latitude,
			Longitude: entry.Longitude,
			City:      entry.City,
			Country:   entry.Country,
			HasOnion:  pn.HasOnion,
		})
		excludedCities[cityKey{city: entry.City, country: entry.Country}] = true
	}

	// clusterMember is one anonymous node that resolved to a real
	// geoip_cache entry, carried through to the grouping pass below.
	type clusterMember struct {
		nodeID   uuid.UUID
		lastSeen time.Time
		entry    storage.GeoIPEntry
	}
	membersByCity := make(map[cityKey][]clusterMember)
	for _, c := range anonymousCandidates {
		entry, ok := geoCache[c.ipv4]
		if !ok || entry.LookupFailed {
			// Never looked up yet, or persistently unresolvable --
			// omit rather than group under a meaningless (0, 0)
			// location. Mirrors handleNodesMap's own convention.
			continue
		}
		key := cityKey{city: entry.City, country: entry.Country}
		membersByCity[key] = append(membersByCity[key], clusterMember{
			nodeID:   c.node.ID,
			lastSeen: c.node.LastSeen,
			entry:    entry,
		})
	}

	anonymous := make([]AnonymousCluster, 0, len(membersByCity))
	for key, members := range membersByCity {
		if excludedCities[key] {
			// A city already showing an attributed marker must not
			// also show an anonymous one -- BRIEF.md's core exclusion
			// rule.
			continue
		}

		// Deterministic representative point: sort by node UUID and
		// take the first, so repeated requests return byte-identical
		// output for an unchanged population.
		sort.Slice(members, func(i, j int) bool {
			return members[i].nodeID.String() < members[j].nodeID.String()
		})
		representative := members[0].entry

		lastObserved := members[0].lastSeen
		for _, m := range members[1:] {
			if m.lastSeen.After(lastObserved) {
				lastObserved = m.lastSeen
			}
		}

		anonymous = append(anonymous, AnonymousCluster{
			City:            key.city,
			Country:         key.country,
			Latitude:        representative.Latitude,
			Longitude:       representative.Longitude,
			ApproxNodeCount: len(members),
			LastObservedAt:  lastObserved,
		})
	}

	// Stable output ordering across requests, independent of Go's
	// randomized map iteration order -- sort by (city, country).
	sort.Slice(anonymous, func(i, j int) bool {
		if anonymous[i].City != anonymous[j].City {
			return anonymous[i].City < anonymous[j].City
		}
		return anonymous[i].Country < anonymous[j].Country
	})

	return ExtendedMapResponse{Attributed: attributed, Anonymous: anonymous}, nil
}

// handleNodesMapExtended serves GET /nodes/map/extended: an additive
// extension of GET /nodes/map (see BRIEF.md) that ALSO surfaces the
// non-attributed (anonymous) node population, aggregated to city-level
// clusters -- never a per-node list, never lat/lon beyond city
// precision, never a wallet-availability signal (see AnonymousCluster's
// doc comment for the full hard privacy invariant). Same public,
// unauthenticated trust level as GET /nodes/map and GET /v1/directory --
// deliberately NOT under /admin.
//
// This does not affect GET /nodes/map's own behavior/response shape at
// all (that handler is untouched), and does not affect GET /v1/stats or
// GET /v1/directory's counts either -- this is purely a new read path
// over already-stored data (ListNodes/ListNodeAddressesForNodes/
// GetGeoIPCache), not a new write, not a new classification stored
// anywhere.
//
// The full computed ExtendedMapResponse is cached in-process for
// cacheTTL (see extendedMapCache above and DefaultExtendedMapCacheTTL)
// -- this endpoint has no query params to key a cache on, so, like
// stats.go's handleStats, a single cached value is shared across every
// request. A cacheTTL <= 0 disables caching entirely, falling out
// naturally from extendedMapCache.get's time.Since(...) >= ttl check.
func handleNodesMapExtended(store storage.Store, cacheTTL time.Duration) http.HandlerFunc {
	cache := &extendedMapCache{ttl: cacheTTL}

	return func(w http.ResponseWriter, r *http.Request) {
		if resp, ok := cache.get(); ok {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		resp, err := buildExtendedMapResponse(r.Context(), store)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		cache.set(resp)
		writeJSON(w, http.StatusOK, resp)
	}
}
