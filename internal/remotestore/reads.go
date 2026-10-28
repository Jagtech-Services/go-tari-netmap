package remotestore

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// matchesFilterLocked reports whether tn satisfies every set field of filter, mirroring
// internal/storage's nodeFilterClauses predicate-by-predicate (DiscoverySource/Confirmed/
// HasHealthChecks/Owned/ReachableSince), just evaluated in memory over this store's own local
// trackedNode bookkeeping instead of via SQL. Callers must hold s.mu (or otherwise guarantee
// tn is not concurrently mutated).
//
// ReachableSince is approximated: a cacheDerived node (learned via GET /nodes/seed_list,
// which only ever returns nodes already gated on "reachable within
// storage.DefaultSeedHealthWindow" server-side) is treated as always satisfying any
// ReachableSince filter; a purely locally-tracked node (this satellite's own
// UpsertDiscoveredNode/UpsertConfirmedNode calls) never satisfies one, since this store keeps
// no actual health-check history timeline to check against. This is a one-sided
// approximation, not a precise recency check -- see this package's doc comment for why that's
// an accepted tradeoff for a store with this minimal a wire contract.
func matchesFilterLocked(tn *trackedNode, filter storage.NodeFilter) bool {
	n := tn.node

	if filter.DiscoverySource != "" && n.DiscoverySource != filter.DiscoverySource {
		return false
	}
	if filter.Confirmed != nil {
		confirmed := len(n.PublicKey) > 0
		if *filter.Confirmed != confirmed {
			return false
		}
	}
	if filter.HasHealthChecks != nil && *filter.HasHealthChecks != tn.hasHealthChecks {
		return false
	}
	if filter.Owned != nil && *filter.Owned != isOwnedTags(n.Tags) {
		return false
	}
	if filter.ReachableSince != nil && !tn.cacheDerived {
		return false
	}

	return true
}

// listNodesLocked applies filter over every tracked node, sorted by address (matching
// pgStore's own ORDER BY address) and Limit/Offset-paginated exactly like pgStore.ListNodes.
// Callers must hold s.mu.
func (s *Store) listNodesLocked(filter storage.NodeFilter) []storage.Node {
	matched := make([]storage.Node, 0, len(s.nodes))
	for _, tn := range s.nodes {
		if matchesFilterLocked(tn, filter) {
			matched = append(matched, tn.node)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].Address < matched[j].Address })

	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return []storage.Node{}
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}
	return matched
}

// ListNodes implements storage.Store, serving entirely from this store's local cache/tracked
// state -- see this package's doc comment for the full read model. A zero-value filter returns
// every locally known node, unpaginated, exactly like pgStore's own ListNodes -- this is
// relied upon by internal/collector's DiscoverOwned/RefreshGeoIP call sites that pass a bare
// storage.NodeFilter{}.
func (s *Store) ListNodes(ctx context.Context, filter storage.NodeFilter) ([]storage.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listNodesLocked(filter), nil
}

// CountNodes implements storage.Store, mirroring ListNodes but ignoring Limit/Offset, exactly
// like pgStore.CountNodes.
func (s *Store) CountNodes(ctx context.Context, filter storage.NodeFilter) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	filter.Limit = 0
	filter.Offset = 0
	return len(s.listNodesLocked(filter)), nil
}

// GetNode implements storage.Store, returning storage.ErrNotFound for any id this store has
// never resolved (neither via a cache refresh nor a local Upsert* call).
func (s *Store) GetNode(ctx context.Context, id uuid.UUID) (storage.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tn, ok := s.nodes[id]
	if !ok {
		return storage.Node{}, storage.ErrNotFound
	}
	return tn.node, nil
}

// ListNodeAddresses implements storage.Store, returning every address this store has ever
// recorded for nodeID (either from a cache refresh, which may report several addresses per
// node, or accumulated across repeated local UpsertDiscoveredNode/UpsertConfirmedNode calls
// for different addresses that resolved to the same ID). An unknown nodeID returns an empty,
// non-nil slice -- mirroring pgStore's own "no rows" behavior -- rather than an error, since
// this is a plain lookup, not an existence assertion.
func (s *Store) ListNodeAddresses(ctx context.Context, nodeID uuid.UUID) ([]storage.NodeAddress, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tn, ok := s.nodes[nodeID]
	if !ok {
		return []storage.NodeAddress{}, nil
	}
	out := make([]storage.NodeAddress, len(tn.addresses))
	copy(out, tn.addresses)
	return out, nil
}

// ListNodeAddressesForNodes implements storage.Store, the batch form of ListNodeAddresses --
// used directly by cmd/netmap-p2p-responder's peerListProvider. The returned map always has
// one entry per input nodeID, even for a node with zero known addresses (should not happen in
// practice, given a node only ever enters this store's tracking via an address in the first
// place, but guarded anyway for parity with pgStore's own contract).
func (s *Store) ListNodeAddressesForNodes(ctx context.Context, nodeIDs []uuid.UUID) (map[uuid.UUID][]storage.NodeAddress, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[uuid.UUID][]storage.NodeAddress, len(nodeIDs))
	for _, id := range nodeIDs {
		tn, ok := s.nodes[id]
		if !ok {
			out[id] = []storage.NodeAddress{}
			continue
		}
		addrs := make([]storage.NodeAddress, len(tn.addresses))
		copy(addrs, tn.addresses)
		out[id] = addrs
	}
	return out, nil
}
