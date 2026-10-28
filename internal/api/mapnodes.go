package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/netaddr"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// MapNode is one entry of the GET /nodes/map response body: a
// privacy-scrubbed, geo-resolved projection of a node already returned
// (with its real address(es)) by GET /nodes -- see isMapEligible's doc
// comment for exactly why this is not a new privacy exposure.
type MapNode struct {
	NodeID    uuid.UUID `json:"node_id"`
	Label     string    `json:"label"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	City      string    `json:"city"`
	Country   string    `json:"country"`
	HasOnion  bool      `json:"has_onion"`
}

// isMapEligible reports whether n belongs to the /map feature's
// population (see BRIEF.md's Scope section 1): tags["owner"] set to a
// non-empty string (collector.HasOwnerTag -- the exact predicate
// factored out of collector.isPoolOwned specifically for this reuse,
// see its doc comment) AND at least one known IPv4 address
// (firstIPv4Address).
//
// Per BRIEF.md's "Why this population specifically": a node's real
// address is only ever exposed via GET /nodes when DiscoverySource is
// registry_submitted or both -- i.e. the owner opted in via the public
// submission form -- and tags["owner"] is likewise only ever set via
// that exact same opt-in path (see handleApproveSubmission in api.go:
// `tags["owner"] = *submission.OwnerTag`). So this predicate selects
// EXACTLY the already-consented, already-address-visible population:
// GET /nodes/map (see handleNodesMap below) returns the SAME addresses
// (projected as lat/lon instead of a raw IP string) that GET /nodes
// already exposes for every one of these nodes today. This is not a
// new privacy exposure -- do not "fix" this by running isMapEligible's
// candidates through ScrubNode's DiscoverySource gate expecting it to
// ever suppress anything additional; it can't, by construction.
func isMapEligible(n storage.Node, addrs []storage.NodeAddress) bool {
	if !collector.HasOwnerTag(n) {
		return false
	}
	_, ok := firstIPv4Address(n, addrs)
	return ok
}

// firstIPv4Address returns the first IPv4 address found among addrs (or
// n.Address, following addressStrings' same fallback convention for
// nodes with no node_addresses rows recorded), via netaddr.IPv4Host.
func firstIPv4Address(n storage.Node, addrs []storage.NodeAddress) (string, bool) {
	for _, a := range addressStrings(n, addrs) {
		if ip, ok := netaddr.IPv4Host(a); ok {
			return ip, true
		}
	}
	return "", false
}

// handleNodesMap serves GET /nodes/map: every node matching
// isMapEligible's owner-tagged+has_ipv4 predicate, with its known IPv4
// address resolved to an approximate lat/lon via storage's geoip_cache
// table (see internal/storage.Store.GetGeoIPCache and
// internal/collector.RefreshGeoIP, which populates that cache on its own
// independent background schedule -- see RefreshGeoIP's doc comment for
// why: an HTTP GET must never block on a live outbound geoip lookup).
//
// A node in the target population with no geoip_cache entry yet (never
// looked up, or the lookup itself failed -- see
// storage.GeoIPEntry.LookupFailed) is simply OMITTED from the response
// rather than blocking on a fresh lookup or returning a meaningless
// (0, 0) coordinate -- the next RefreshGeoIP tick will pick it up.
//
// PRIVACY NOTE (see isMapEligible's doc comment for the full argument):
// this endpoint returns the SAME already-consented addresses (as
// lat/lon, never a raw IP string) that GET /nodes already exposes for
// this exact population today -- this is not a new privacy exposure,
// merely a different projection of already-public data. A future reader
// must not mistake the addition of this endpoint for a new leak.
func handleNodesMap(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodes, err := store.ListNodes(r.Context(), storage.NodeFilter{})
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

		type candidate struct {
			node storage.Node
			ipv4 string
		}
		var candidates []candidate
		ipSet := make(map[string]struct{})
		for _, n := range nodes {
			addrs := addrsByNode[n.ID]
			if !isMapEligible(n, addrs) {
				continue
			}
			ip, _ := firstIPv4Address(n, addrs) // guaranteed ok, isMapEligible already checked
			candidates = append(candidates, candidate{node: n, ipv4: ip})
			ipSet[ip] = struct{}{}
		}

		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}

		cache, err := store.GetGeoIPCache(r.Context(), ips)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		out := make([]MapNode, 0, len(candidates))
		for _, c := range candidates {
			entry, ok := cache[c.ipv4]
			if !ok || entry.LookupFailed {
				// Never looked up yet, or persistently unresolvable --
				// omit rather than plot a meaningless (0, 0) marker.
				// See this handler's doc comment.
				continue
			}

			var label string
			if c.node.Label != nil {
				label = *c.node.Label
			}

			pn := ScrubNode(c.node, addrsByNode[c.node.ID])
			out = append(out, MapNode{
				NodeID:    c.node.ID,
				Label:     label,
				Latitude:  entry.Latitude,
				Longitude: entry.Longitude,
				City:      entry.City,
				Country:   entry.Country,
				HasOnion:  pn.HasOnion,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}
