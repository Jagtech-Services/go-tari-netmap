package collector

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/netaddr"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// RefreshGeoIP opportunistically tops up storage's geoip_cache table for
// TWO populations, unioned together:
//
//  1. The original /map feature's population — every node with a
//     non-empty tags["owner"] (HasOwnerTag) and at least one known IPv4
//     address (see BRIEF.md's original Scope section 1) — looked up
//     UNCONDITIONALLY, with no reachability requirement at all, exactly
//     as before.
//  2. The GET /nodes/map/extended "anonymous" cluster population — every
//     non-owner-tagged, non-role=collector node with a known IPv4 address
//     that has had at least one successful health check in the last 24h
//     (see anonymousReachableIPv4Addresses's doc comment). This second
//     population was added per a 2026-09-22 operator-approved expansion
//     (see BRIEF.md "expand geoip refresh to also cover the anonymous
//     population (bounded)"): GET /nodes/map/extended's `anonymous` array
//     was shipping permanently empty because nothing upstream ever
//     populated geoip_cache for non-owner-tagged nodes. The operator
//     signed off specifically because internal/api/mapextended.go's
//     anonymous output stays coarse-only/aggregate-only (city/country
//     clusters, never a per-node result — see its AnonymousCluster type),
//     which is what makes sending some previously-never-looked-up nodes'
//     IPs to the external ip-api.com service acceptable here. The 24h
//     reachability bound keeps the candidate population from blowing up
//     against ip-api.com's free-tier rate limit on the network's large
//     population of permanently-offline p2p_discovered gossip ghosts
//     (see storage.NodeFilter.ReachableSince's own doc comment and
//     PollIntervalLikelyDead's, which together explain why that
//     population dominates the raw node count by 100-500x and would
//     otherwise swamp the lookup budget for zero benefit).
//
// Both populations feed the SAME read-through/TTL/lookup/upsert pipeline
// below, over their deduped union — so GET /nodes/map's HTTP handler
// (internal/api's handleNodesMap) and GET /nodes/map/extended's handler
// never need to perform a live outbound geoip lookup themselves: an HTTP
// GET must never block on an outbound network call, so this loop does
// that work ahead of time on its own independent cadence (see
// runGeoIPRefreshLoop/GeoIPRefreshTickInterval), exactly like
// DiscoverOwned does for peer-walk data.
//
// It is a cheap no-op — not even a Storage query — when GeoIPClient is
// nil (the /map feature not opted into at all); it returns an error if
// Storage is unset but GeoIPClient isn't (a genuine misconfiguration,
// unlike the deliberate nil-disables convention for GeoIPClient itself).
//
// Read-through + TTL policy: only IPs staleGeoIPs reports as due (never
// cached at all, or past GeoIPSuccessTTL/GeoIPFailedTTL — see its doc
// comment) are ever sent to GeoIPClient.Lookup; a warm cache costs zero
// outbound requests on most ticks. Every IP passed to Lookup gets a
// geoip_cache row written back regardless of outcome — including one
// GeoIPClient.Lookup itself couldn't get a result for at all (a
// transport/decode error for that IP's batch, see Client.Lookup's doc
// comment) — cached as LookupFailed so a persistently-unresolvable IP
// gets GeoIPFailedTTL's shorter backoff instead of being retried on
// every single refresh tick forever.
func (c *Collector) RefreshGeoIP(ctx context.Context) error {
	if c.GeoIPClient == nil {
		return nil
	}
	if c.Storage == nil {
		return errors.New("collector: Storage is not configured")
	}

	ownerIPs, err := c.ownerIPv4Addresses(ctx)
	if err != nil {
		return fmt.Errorf("collector: refresh geoip: %w", err)
	}

	anonIPs, err := c.anonymousReachableIPv4Addresses(ctx)
	if err != nil {
		return fmt.Errorf("collector: refresh geoip: %w", err)
	}

	// Dedupe the combined set defensively — an IP could theoretically
	// appear in both slices, even though ownerIPv4Addresses' HasOwnerTag
	// predicate and anonymousReachableIPv4Addresses' !HasOwnerTag
	// predicate are mutually exclusive by construction, so this should
	// never actually happen in practice.
	seen := make(map[string]bool, len(ownerIPs)+len(anonIPs))
	ips := make([]string, 0, len(ownerIPs)+len(anonIPs))
	for _, ip := range ownerIPs {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	for _, ip := range anonIPs {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil
	}

	cached, err := c.Storage.GetGeoIPCache(ctx, ips)
	if err != nil {
		return fmt.Errorf("collector: refresh geoip: get cache: %w", err)
	}

	stale := staleGeoIPs(ips, cached, time.Now())
	if len(stale) == 0 {
		return nil
	}

	results, err := c.GeoIPClient.Lookup(ctx, stale)
	if err != nil {
		// Lookup already logs/returns per-batch errors internally and
		// still returns whatever it DID resolve — see its doc comment
		// — so this is logged, not fatal: entries below still get
		// written for whatever came back, and any IP with no result at
		// all is still cached as failed (see the missing-key handling
		// below), rather than this whole pass aborting.
		log.Printf("collector: geoip refresh: lookup error (continuing with partial results): %v", err)
	}

	now := time.Now()
	entries := make([]storage.GeoIPEntry, 0, len(stale))
	for _, ip := range stale {
		res, ok := results[ip]
		if !ok {
			entries = append(entries, storage.GeoIPEntry{IP: ip, LookedUpAt: now, LookupFailed: true})
			continue
		}
		entries = append(entries, storage.GeoIPEntry{
			IP:           ip,
			Latitude:     res.Latitude,
			Longitude:    res.Longitude,
			City:         res.City,
			Country:      res.Country,
			LookedUpAt:   now,
			LookupFailed: res.Failed,
		})
	}

	if err := c.Storage.UpsertGeoIPCache(ctx, entries); err != nil {
		return fmt.Errorf("collector: refresh geoip: upsert cache: %w", err)
	}
	log.Printf("collector: geoip refresh: looked up %d/%d candidate ip(s)", len(stale), len(ips))
	return nil
}

// ownerIPv4Addresses returns the deduped set of IPv4 addresses belonging
// to the /map population: every node with HasOwnerTag true, restricted
// to their known IPv4 addresses only (via netaddr.IPv4Host — the same
// classification internal/api's isMapEligible/firstIPv4 use for the
// identical predicate; deliberately re-implemented here rather than
// imported, since internal/api already imports internal/collector, so
// internal/collector cannot import internal/api back — see
// internal/netaddr's own doc comment for this established constraint).
func (c *Collector) ownerIPv4Addresses(ctx context.Context) ([]string, error) {
	nodes, err := c.Storage.ListNodes(ctx, storage.NodeFilter{})
	if err != nil {
		return nil, err
	}

	var owned []storage.Node
	for _, n := range nodes {
		if HasOwnerTag(n) {
			owned = append(owned, n)
		}
	}
	return c.ipv4AddressesForNodes(ctx, owned)
}

// anonymousReachableIPv4Addresses returns the deduped set of IPv4
// addresses belonging to the GET /nodes/map/extended "anonymous" cluster
// candidate population (see BRIEF.md "expand geoip refresh to also
// cover the anonymous population (bounded)" and RefreshGeoIP's doc
// comment for the full context/rationale): every node that is
//
//   - NOT owner-tagged (!HasOwnerTag) — owner-tagged nodes are the
//     separate, unconditional population ownerIPv4Addresses already
//     covers; and
//   - reachable at least once in the last 24h (storage.NodeFilter.
//     ReachableSince, same 24h window internal/api/stats.go's
//     FetchConfirmed24h already established as this codebase's
//     convention for "recently reachable" — see
//     `store.CountNodes(ctx, storage.NodeFilter{Confirmed: &confirmedTrue,
//     ReachableSince: &cutoff})` there) — deliberately WITHOUT also
//     requiring Confirmed: an anonymous cluster candidate is explicitly
//     allowed to be an unconfirmed placeholder node, since confirmation
//     status is unrelated to whether a node is worth plotting on a map;
//     and
//   - NOT tagged role=collector (the same tags["role"] == "collector"
//     check as internal/api's IsCollectorRole/collectorRoleTagValue —
//     re-implemented locally here rather than imported, since
//     internal/api already imports internal/collector, so
//     internal/collector cannot import internal/api back; this mirrors
//     the exact same existing constraint ownerIPv4Addresses' own doc
//     comment already notes for its netaddr.IPv4Host re-implementation).
//
// This bound exists specifically so this loop's outbound ip-api.com call
// volume never scales with the raw node count (which the network's huge
// population of permanently-offline p2p_discovered gossip ghosts — see
// PollIntervalLikelyDead's doc comment — dominates by 100-500x): a node
// that hasn't been reachable in the last 24h will never contribute a
// useful anonymous-cluster marker anyway, so it isn't worth spending
// lookup budget on.
//
// The ReachableSince filter is applied at the DB level via ListNodes'
// own NodeFilter (see storage.TestListNodesReachableSinceFilter for the
// established precedent that this is cheaper than an unfiltered
// full-population ListNodes scan followed by a per-node reachability
// check in Go), rather than fetching every node and filtering in Go.
func (c *Collector) anonymousReachableIPv4Addresses(ctx context.Context) ([]string, error) {
	cutoff := time.Now().Add(-24 * time.Hour)
	nodes, err := c.Storage.ListNodes(ctx, storage.NodeFilter{ReachableSince: &cutoff})
	if err != nil {
		return nil, err
	}

	var candidates []storage.Node
	for _, n := range nodes {
		if HasOwnerTag(n) {
			continue
		}
		if isCollectorRoleTag(n.Tags) {
			continue
		}
		candidates = append(candidates, n)
	}
	return c.ipv4AddressesForNodes(ctx, candidates)
}

// isCollectorRoleTag reports whether tags marks its node as a remote
// collector satellite's own advertised identity (tags["role"] ==
// "collector"). This is a local re-implementation of internal/api's
// IsCollectorRole/collectorRoleTagValue (see collectorrole.go there) —
// internal/collector cannot import internal/api (internal/api already
// imports internal/collector), the same constraint ownerIPv4Addresses'
// doc comment already notes for netaddr.IPv4Host vs. internal/api's
// isMapEligible/firstIPv4.
func isCollectorRoleTag(tags map[string]any) bool {
	v, ok := tags["role"]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s == "collector"
}

// ipv4AddressesForNodes returns the deduped set of IPv4 addresses for
// nodes, restricted to their known IPv4 addresses only (via
// netaddr.IPv4Host — the same classification internal/api's
// isMapEligible/firstIPv4 use for the identical predicate; deliberately
// re-implemented here rather than imported, since internal/api already
// imports internal/collector, so internal/collector cannot import
// internal/api back — see internal/netaddr's own doc comment for this
// established constraint). Shared by both ownerIPv4Addresses and
// anonymousReachableIPv4Addresses so the two candidate populations'
// IPv4-extraction logic can never drift apart.
func (c *Collector) ipv4AddressesForNodes(ctx context.Context, nodes []storage.Node) ([]string, error) {
	if len(nodes) == 0 {
		return nil, nil
	}

	nodeIDs := make([]uuid.UUID, 0, len(nodes))
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.ID)
	}

	addrsByNode, err := c.Storage.ListNodeAddressesForNodes(ctx, nodeIDs)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var ips []string
	addIfIPv4 := func(raw string) {
		ip, ok := netaddr.IPv4Host(raw)
		if !ok || seen[ip] {
			return
		}
		seen[ip] = true
		ips = append(ips, ip)
	}

	for _, n := range nodes {
		addrs := addrsByNode[n.ID]
		if len(addrs) == 0 {
			// Mirrors internal/api/privacy.go's addressStrings fallback
			// for legacy rows with no node_addresses rows recorded yet.
			if n.Address != "" {
				addIfIPv4(n.Address)
			}
			continue
		}
		for _, a := range addrs {
			addIfIPv4(a.Address)
		}
	}
	return ips, nil
}

// staleGeoIPs returns the subset of ips that need a fresh geoip lookup
// given already-cached entries (keyed by ip, e.g. from
// storage.Store.GetGeoIPCache) and now — BRIEF.md's exact TTL policy:
// an ip with no cache entry at all always needs a lookup; a successful
// (LookupFailed == false) entry is stale once GeoIPSuccessTTL has
// elapsed since LookedUpAt; a failed entry uses the much shorter
// GeoIPFailedTTL instead, so a transient rate-limit reject doesn't get
// treated as a month-long "known unresolvable" verdict.
//
// Pure function, no I/O of any kind — unit-testable without a real
// cache store, HTTP client, or network access.
func staleGeoIPs(ips []string, cached map[string]storage.GeoIPEntry, now time.Time) []string {
	var stale []string
	for _, ip := range ips {
		entry, ok := cached[ip]
		if !ok {
			stale = append(stale, ip)
			continue
		}
		ttl := GeoIPSuccessTTL
		if entry.LookupFailed {
			ttl = GeoIPFailedTTL
		}
		if now.Sub(entry.LookedUpAt) >= ttl {
			stale = append(stale, ip)
		}
	}
	return stale
}
