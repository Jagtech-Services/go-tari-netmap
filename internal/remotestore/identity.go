package remotestore

import (
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// addressNamespace is a fixed, arbitrary namespace UUID used only to derive stable,
// per-process synthetic node IDs for addresses this satellite has upserted locally but that
// no GET /nodes/seed_list refresh has (yet) revealed the real central-authoritative ID for --
// see deterministicNodeID and this package's doc comment on the "Node identity" section for
// the full rationale. It carries no other meaning and must never change (changing it would
// make every previously-generated synthetic ID for a given address inconsistent across a
// binary upgrade, though since these IDs are never persisted anywhere -- they live only in
// this process' memory for the lifetime of one run -- that would be a harmless, purely
// cosmetic churn, not a correctness bug).
var addressNamespace = uuid.MustParse("6f2b6c9e-6a97-4c1a-9e2c-2f6b6a2d9b31")

// deterministicNodeID derives a stable, version-5 (SHA-1-based) UUID from address. Calling
// this twice for the same address always returns the same UUID -- this is exactly the
// property resolveNodeIDLocked/ensureTrackedLocked need to keep a single node's identity
// self-consistent across repeated local UpsertDiscoveredNode/UpsertConfirmedNode calls within
// one process run, without any central round trip.
func deterministicNodeID(address string) uuid.UUID {
	return uuid.NewSHA1(addressNamespace, []byte(address))
}

// resolveNodeIDLocked returns the uuid.UUID this Store associates with address: the real,
// central-authoritative ID if a GET /nodes/seed_list refresh has already revealed one for
// this address (or any of its known aliases), otherwise a newly minted (and thereafter
// remembered) deterministicNodeID. Callers must hold s.mu.
func (s *Store) resolveNodeIDLocked(address string) uuid.UUID {
	if id, ok := s.idByAddress[address]; ok {
		return id
	}
	id := deterministicNodeID(address)
	s.idByAddress[address] = id
	return id
}

// ensureTrackedLocked returns the trackedNode for id, creating an empty one keyed by address
// if this is the first time id has been seen, and ensuring address is recorded among its
// known addresses and reverse-mapped back to id. Callers must hold s.mu.
func (s *Store) ensureTrackedLocked(id uuid.UUID, address string) *trackedNode {
	tn, ok := s.nodes[id]
	if !ok {
		tn = &trackedNode{node: storage.Node{ID: id, Address: address}}
		s.nodes[id] = tn
	}
	if tn.node.Address == "" {
		tn.node.Address = address
	}

	found := false
	for _, a := range tn.addresses {
		if a.Address == address {
			found = true
			break
		}
	}
	if !found {
		now := time.Now()
		tn.addresses = append(tn.addresses, storage.NodeAddress{NodeID: id, Address: address, FirstSeen: now, LastSeen: now})
	}

	s.idByAddress[address] = id
	if _, ok := s.addressByID[id]; !ok {
		s.addressByID[id] = address
	}
	return tn
}

// isOwnedTags mirrors internal/collector's isPoolOwned predicate exactly (tags["pool_owned"]
// == a genuine JSON boolean true, OR a non-empty tags["owner"] string) -- duplicated here
// (rather than importing internal/collector for it) to keep this package's dependency surface
// minimal; see this package's doc comment for why this predicate is, in practice, almost never
// true for a cache-derived node today (GET /nodes/seed_list's wire response carries no Tags
// field at all -- see refreshCache) and only ever meaningful for a node this satellite tracks
// purely locally via a caller-supplied non-empty tags argument to UpsertDiscoveredNode.
func isOwnedTags(tags map[string]any) bool {
	if v, ok := tags["pool_owned"]; ok {
		if b, ok := v.(bool); ok && b {
			return true
		}
	}
	if v, ok := tags["owner"]; ok {
		if s, ok := v.(string); ok && s != "" {
			return true
		}
	}
	return false
}
