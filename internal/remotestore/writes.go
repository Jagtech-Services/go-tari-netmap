package remotestore

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// pendingConfirmedNode is one buffered UpsertConfirmedNode call, awaiting flush as a
// confirmed_nodes entry in the next POST /internal/collectors/report (see
// internal/api/collector_report.go's collectorReportConfirmedNode for the matching wire
// shape).
type pendingConfirmedNode struct {
	Address         string
	PublicKey       []byte
	DiscoverySource storage.DiscoverySource
}

// pendingDiscoveredNode is one buffered UpsertDiscoveredNode call, awaiting flush as a
// discovered_nodes entry.
type pendingDiscoveredNode struct {
	Address string
}

// pendingHealthCheck is one buffered RecordHealthCheck call, awaiting flush as a
// health_checks entry. Address is resolved from in.NodeID at RecordHealthCheck time (via
// s.addressByID), since the wire contract is address-keyed, not ID-keyed.
type pendingHealthCheck struct {
	Address string
	Input   storage.HealthCheckInput
}

// pendingPeerEdge is one buffered RecordPeerEdgeObservation call, awaiting flush as a
// peer_edges entry. Both addresses are resolved from the given node IDs at
// RecordPeerEdgeObservation time, same reasoning as pendingHealthCheck.
type pendingPeerEdge struct {
	FromAddress string
	ToAddress   string
}

// maybeSignalFlushLocked non-blockingly signals s.flushTrigger once the combined
// pending-buffer size reaches flushBatchSize, so Run's select loop flushes immediately rather
// than waiting for the next FlushInterval tick. Callers must hold s.mu. The channel is
// buffered 1 and the send is non-blocking (select/default) specifically so that a burst of
// many upserts in a row -- each individually crossing the threshold check -- signals at most
// once per outstanding flush, never blocks the caller, and never panics on a full channel.
func (s *Store) maybeSignalFlushLocked() {
	total := len(s.pendingConfirmed) + len(s.pendingDiscovered) + len(s.pendingHealth) + len(s.pendingEdges)
	if total < s.flushBatchSize() {
		return
	}
	select {
	case s.flushTrigger <- struct{}{}:
	default:
	}
}

// UpsertDiscoveredNode implements storage.Store. It resolves/creates a local trackedNode for
// address (see ensureTrackedLocked), merges discoverySource/tags/label into it exactly like
// pgStore's own UpsertDiscoveredNode (discovery_source merges to storage.DiscoverySourceBoth
// on a differing value; tags are merged, never replaced; a non-nil label overwrites), and
// buffers address as a discovered_nodes entry for the next flush.
//
// tags is merged into the LOCAL copy only -- today's POST /internal/collectors/report wire
// contract has no field for propagating arbitrary tags centrally (the only tag this store's
// wire protocol can ever cause the central API to set is tags.role = "collector", via
// Config.SelfAddresses' self_identity mechanism, entirely independent of this method). Every
// real call site in internal/collector/internal/api that this store is actually exercised
// against always passes a nil tags argument; a non-nil, non-empty tags argument here is
// logged as a heads-up rather than silently, invisibly dropped.
func (s *Store) UpsertDiscoveredNode(ctx context.Context, address string, discoverySource storage.DiscoverySource, tags map[string]any, label *string) (storage.Node, error) {
	if address == "" {
		return storage.Node{}, errRemoteStore("address is required")
	}
	if discoverySource == "" {
		return storage.Node{}, errRemoteStore("discovery_source is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storage.Node{}, errClosed
	}

	id := s.resolveNodeIDLocked(address)
	tn := s.ensureTrackedLocked(id, address)

	if tn.node.DiscoverySource == "" {
		tn.node.DiscoverySource = discoverySource
	} else if tn.node.DiscoverySource != discoverySource {
		tn.node.DiscoverySource = storage.DiscoverySourceBoth
	}
	if len(tags) > 0 {
		if tn.node.Tags == nil {
			tn.node.Tags = map[string]any{}
		}
		for k, v := range tags {
			tn.node.Tags[k] = v
		}
		s.logf("remotestore: UpsertDiscoveredNode(%s) received non-empty tags %v -- merged into this store's local copy only, NOT propagated to the central API (today's report wire contract has no field for arbitrary tag propagation; only self_identity->role=collector is supported)", address, tags)
	}
	if label != nil {
		tn.node.Label = label
	}
	now := time.Now()
	if tn.node.FirstSeen.IsZero() {
		tn.node.FirstSeen = now
	}
	tn.node.LastSeen = now

	s.pendingDiscovered = append(s.pendingDiscovered, pendingDiscoveredNode{Address: address})
	s.maybeSignalFlushLocked()

	return tn.node, nil
}

// UpsertConfirmedNode implements storage.Store. It resolves/creates a local trackedNode for
// address, sets its PublicKey, merges discoverySource (same DiscoverySourceBoth-on-mismatch
// semantics as UpsertDiscoveredNode above), and buffers a confirmed_nodes entry for the next
// flush.
func (s *Store) UpsertConfirmedNode(ctx context.Context, address string, publicKey []byte, discoverySource storage.DiscoverySource) (storage.Node, error) {
	if address == "" {
		return storage.Node{}, errRemoteStore("address is required")
	}
	if len(publicKey) == 0 {
		return storage.Node{}, errRemoteStore("public_key is required")
	}
	if discoverySource == "" {
		return storage.Node{}, errRemoteStore("discovery_source is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storage.Node{}, errClosed
	}

	id := s.resolveNodeIDLocked(address)
	tn := s.ensureTrackedLocked(id, address)

	tn.node.PublicKey = append([]byte(nil), publicKey...)
	if tn.node.DiscoverySource == "" {
		tn.node.DiscoverySource = discoverySource
	} else if tn.node.DiscoverySource != discoverySource {
		tn.node.DiscoverySource = storage.DiscoverySourceBoth
	}
	now := time.Now()
	if tn.node.FirstSeen.IsZero() {
		tn.node.FirstSeen = now
	}
	tn.node.LastSeen = now

	s.pendingConfirmed = append(s.pendingConfirmed, pendingConfirmedNode{
		Address:         address,
		PublicKey:       append([]byte(nil), publicKey...),
		DiscoverySource: discoverySource,
	})
	s.maybeSignalFlushLocked()

	return tn.node, nil
}

// RecordHealthCheck implements storage.Store. in.NodeID must be an ID this Store has
// previously returned (from UpsertDiscoveredNode/UpsertConfirmedNode, or from a node in the
// cache populated by refreshCache) -- this store has no other way to resolve a NodeID back to
// an address, since its own local storage is entirely address-keyed underneath. A NodeID this
// store has never seen is an error, not a silently-dropped no-op: it almost certainly
// indicates a caller bug (recording a health check against a node this store never told it
// about).
func (s *Store) RecordHealthCheck(ctx context.Context, in storage.HealthCheckInput) error {
	if in.ProbeSource == "" {
		return errRemoteStore("probe_source is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	address, ok := s.addressByID[in.NodeID]
	if !ok {
		return errRemoteStore("record health check: unknown node id %s (never resolved by this store instance)", in.NodeID)
	}

	if tn, ok := s.nodes[in.NodeID]; ok {
		tn.hasHealthChecks = true
		tn.node.LastSeen = time.Now()
	}

	s.pendingHealth = append(s.pendingHealth, pendingHealthCheck{Address: address, Input: in})
	s.maybeSignalFlushLocked()
	return nil
}

// RecordPeerEdgeObservation implements storage.Store, resolving both fromNodeID/toNodeID back
// to addresses (see RecordHealthCheck's doc comment for why an unresolvable ID is an error,
// not a silent no-op) and buffering a peer_edges entry for the next flush.
//
// meta (see storage.Store's own doc comment on this parameter) is always ignored here: this
// Store's own local RecordPeerEdgeObservation calls are exactly the raw discovery-walk
// observations this satellite is buffering up TO report -- the central API is what stamps
// reported_by_collector/report_batch_id, once, when it actually applies the flushed batch (see
// internal/api/collector_report.go's applyCollectorReport), never this client-side buffering
// step. Accepting (and ignoring) the variadic parameter here purely satisfies the
// storage.Store interface.
func (s *Store) RecordPeerEdgeObservation(ctx context.Context, fromNodeID, toNodeID uuid.UUID, meta ...storage.PeerEdgeReportMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}

	fromAddr, ok := s.addressByID[fromNodeID]
	if !ok {
		return errRemoteStore("record peer edge: unknown from-node id %s (never resolved by this store instance)", fromNodeID)
	}
	toAddr, ok := s.addressByID[toNodeID]
	if !ok {
		return errRemoteStore("record peer edge: unknown to-node id %s (never resolved by this store instance)", toNodeID)
	}

	s.pendingEdges = append(s.pendingEdges, pendingPeerEdge{FromAddress: fromAddr, ToAddress: toAddr})
	s.maybeSignalFlushLocked()
	return nil
}
