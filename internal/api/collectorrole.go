package api

import "github.com/Jagtech-Services/go-tari-netmap/internal/storage"

// collectorRoleTagValue is the tags["role"] value POST /internal/collectors/report (see
// collector_report.go's handleCollectorReport) sets on a remote collector satellite's own
// advertised-identity node row(s) -- see that handler's doc comment for the exact tagging
// rule (self_identity-only, never inferred from confirmed_nodes/discovered_nodes/peer_edges).
// Every public-facing/recommendation route (see filterOutCollectorNodes/
// filterOutCollectorSeedCandidates's doc comments for the exact route list) excludes nodes
// tagged this way: a collector's own address is an ingestion-channel identity, never a real
// peer to recommend connecting to.
const collectorRoleTagValue = "collector"

// Reserved for a future tags["role"] == "relay" value (proxy-mode collectors that also forward
// real peer traffic on behalf of other nodes, not implemented yet). That case will need the
// OPPOSITE filtering treatment from collectorRoleTagValue above: a relay's address IS meant to
// be recommended as a real, dialable peer (that is the entire point of proxy mode), unlike a
// plain collector's own ingestion-channel identity. Do not fold "relay" into
// IsCollectorRole/filterOutCollectorNodes below when that ships -- it needs its own predicate
// and must NOT be excluded by the routes this file's filters gate. This comment is a
// deliberate placeholder only; per the governing brief, no code for "relay" filtering exists
// yet.

// IsCollectorRole reports whether tags marks its node as a remote collector satellite's own
// advertised identity (tags["role"] == "collector", see collectorRoleTagValue above). Exported
// so any package that reads node Tags directly and needs to apply the exact same
// "never recommend a collector's own identity as a peer" exclusion this package's own routes
// apply (see filterOutCollectorNodes/filterOutCollectorSeedCandidates's doc comments for the
// full route list) can share this one predicate rather than drifting a second copy of it --
// see internal/web's top-peered rendering for the motivating case (a role=collector node was
// visible there even though GET /topology/top-peered already excluded it via this same check).
func IsCollectorRole(tags map[string]any) bool {
	v, ok := tags["role"]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s == collectorRoleTagValue
}

// filterOutCollectorNodes returns a new slice containing every entry of nodes EXCEPT those
// tagged role=collector (see IsCollectorRole), preserving relative order otherwise. This must
// be applied by every route that recommends or exposes nodes as PEERS TO CONNECT TO: GET
// /topology, GET /topology/top-peered, and (via filterOutCollectorSeedCandidates below) GET
// /nodes/seeds, GET /config/peer-seeds, and their GET /nodes/seed_list(_tari) aliases.
//
// It must NOT be applied to plain listing/inspection routes (GET /nodes, GET /nodes/{id}): a
// collector's own node row must remain visible/inspectable there, it must simply never be
// recommended as a peer.
func filterOutCollectorNodes(nodes []storage.Node) []storage.Node {
	out := make([]storage.Node, 0, len(nodes))
	for _, n := range nodes {
		if IsCollectorRole(n.Tags) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// filterOutCollectorSeedCandidates mirrors filterOutCollectorNodes for
// storage.SeedCandidate (which carries its own Tags field directly, from
// Store.ListSeedCandidates) -- used by GET /nodes/seeds, GET /config/peer-seeds, and their GET
// /nodes/seed_list(_tari) aliases.
func filterOutCollectorSeedCandidates(candidates []storage.SeedCandidate) []storage.SeedCandidate {
	out := make([]storage.SeedCandidate, 0, len(candidates))
	for _, c := range candidates {
		if IsCollectorRole(c.Tags) {
			continue
		}
		out = append(out, c)
	}
	return out
}
