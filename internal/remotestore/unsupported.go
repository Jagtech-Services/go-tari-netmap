package remotestore

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// The methods in this file exist ONLY to satisfy the storage.Store interface -- none of them
// are ever called by cmd/netmap-p2p-responder or by internal/collector's Poll/Discover
// functions (the only two callers this Store is built for; see this package's doc comment),
// since they are all central-API-only concerns (the public-submission review queue, the full
// unbounded topology graph, network-wide aggregates, etc.) that make no sense for a single
// remote collector satellite to serve out of its own small local cache. Every one of them
// returns errNotSupported (or, for the two GeoIP methods, a harmless empty no-op result --
// see below) rather than panicking, so a latent bug that DID call one of these fails loudly
// and safely instead of crashing the process.

// UpsertConfirmedNodeByPubKey is not supported: it has no address to report over this store's
// address-keyed wire contract at all (see this method's doc comment on the Store interface --
// it exists specifically for the "confirmed pubkey, zero advertised addresses" case, and
// cmd/netmap-p2p-responder's own responder.go already special-cases that by skipping the
// record entirely rather than calling this method, so it is never actually reached here).
func (s *Store) UpsertConfirmedNodeByPubKey(ctx context.Context, publicKey []byte, discoverySource storage.DiscoverySource) (storage.Node, error) {
	return storage.Node{}, errNotSupported
}

// ListTopology is not supported: the full topology graph is a central-API-only concern.
func (s *Store) ListTopology(ctx context.Context, filter storage.TopologyFilter) ([]storage.Node, []storage.PeerEdge, error) {
	return nil, nil, errNotSupported
}

// TopPeeredNodes is not supported: a network-wide top-peered ranking is a central-API-only
// concern.
func (s *Store) TopPeeredNodes(ctx context.Context, since time.Time, limit int) ([]storage.NodeDegree, error) {
	return nil, errNotSupported
}

// ListNodeEdges is not supported: this store keeps no peer_edges history of its own, only a
// pending-flush buffer of edges it has observed but not yet reported.
func (s *Store) ListNodeEdges(ctx context.Context, nodeID uuid.UUID, limit int) ([]storage.PeerEdge, error) {
	return nil, errNotSupported
}

// PruneOldPeerEdgeObservations is not supported: the peer_edge_observations retention loop
// (internal/collector.runPeerEdgeRetentionLoop) is only ever wired up against
// cmd/netmap/main.go's central Postgres-backed storage.Store, never against a satellite's own
// remotestore.Store (cmd/netmap-p2p-responder never runs that loop against this Store) -- this
// store keeps no peer_edge_observations table of its own to prune, only a pending-flush buffer
// of edges it has observed but not yet reported (same reasoning as ListNodeEdges above).
func (s *Store) PruneOldPeerEdgeObservations(ctx context.Context, olderThan time.Time, batchSize int) (int64, error) {
	return 0, errNotSupported
}

// NetworkHeight is not supported: a network-wide aggregate is a central-API-only concern.
func (s *Store) NetworkHeight(ctx context.Context) (*int64, int, error) {
	return nil, 0, errNotSupported
}

// ListSeedCandidates is not supported: this store IS a consumer of the central API's own
// GET /nodes/seed_list route (see cache.go's refreshCache), which is built on top of this
// exact method server-side -- there is no sense in which a satellite would call this on
// itself.
func (s *Store) ListSeedCandidates(ctx context.Context, since time.Duration) ([]storage.SeedCandidate, error) {
	return nil, errNotSupported
}

// IsAddressPubliclyOptedIn is not supported: the public-submission opt-in check is a
// central-API-only concern (backing POST /nodes, which no satellite ever serves).
func (s *Store) IsAddressPubliclyOptedIn(ctx context.Context, address string) (bool, error) {
	return false, errNotSupported
}

// FindNodeByHost is not supported: the wallet-node registration flow (POST /wallet-nodes)
// is a central-API-only concern, same reasoning as IsAddressPubliclyOptedIn.
func (s *Store) FindNodeByHost(ctx context.Context, host string) (storage.Node, bool, error) {
	return storage.Node{}, false, errNotSupported
}

// CreatePendingSubmission is not supported: the public-submission review queue is a
// central-API-only concern.
func (s *Store) CreatePendingSubmission(ctx context.Context, address string, label, ownerTag *string) (storage.PendingSubmission, error) {
	return storage.PendingSubmission{}, errNotSupported
}

// ListPendingSubmissions is not supported: see CreatePendingSubmission.
func (s *Store) ListPendingSubmissions(ctx context.Context, status string) ([]storage.PendingSubmission, error) {
	return nil, errNotSupported
}

// GetPendingSubmission is not supported: see CreatePendingSubmission.
func (s *Store) GetPendingSubmission(ctx context.Context, id uuid.UUID) (storage.PendingSubmission, error) {
	return storage.PendingSubmission{}, errNotSupported
}

// ApprovePendingSubmission is not supported: see CreatePendingSubmission.
func (s *Store) ApprovePendingSubmission(ctx context.Context, id uuid.UUID, promotedNodeID uuid.UUID) error {
	return errNotSupported
}

// RejectPendingSubmission is not supported: see CreatePendingSubmission.
func (s *Store) RejectPendingSubmission(ctx context.Context, id uuid.UUID, reason *string) error {
	return errNotSupported
}

// RecordSubmissionProbeResult is not supported: see CreatePendingSubmission.
func (s *Store) RecordSubmissionProbeResult(ctx context.Context, id uuid.UUID, reachable bool) error {
	return errNotSupported
}

// CountPendingSubmissions is not supported: see CreatePendingSubmission.
func (s *Store) CountPendingSubmissions(ctx context.Context) (int, error) {
	return 0, errNotSupported
}

// GetGeoIPCache is a harmless no-op (an always-empty result, never an error): the /map
// feature's geoip cache top-up loop (internal/collector.RefreshGeoIP) is a no-op itself
// whenever Collector.GeoIPClient is nil, which is how cmd/netmap-p2p-responder wires its own
// Collector (see that binary's main.go) -- this method is therefore never actually called in
// practice, but an empty map (rather than an error) is the more correct "no-op" response if it
// ever were, matching this interface method's "missing key means never looked up" contract.
func (s *Store) GetGeoIPCache(ctx context.Context, ips []string) (map[string]storage.GeoIPEntry, error) {
	return map[string]storage.GeoIPEntry{}, nil
}

// UpsertGeoIPCache is a harmless no-op, mirroring GetGeoIPCache -- never actually called in
// practice (see its doc comment), but a silent success rather than an error is the more
// correct "no-op" response if it ever were.
func (s *Store) UpsertGeoIPCache(ctx context.Context, entries []storage.GeoIPEntry) error {
	return nil
}

// GetNodeHistory is a trivial no-op, always returning an empty (never nil) history. This IS
// reachable in principle -- internal/collector's pollInterval calls it for an unconfirmed
// node past its checkpoint schedule -- but in practice never observes anything but an empty
// result here anyway: this store's cache only ever contains CONFIRMED nodes (see this
// package's doc comment), so ListNodes(Confirmed: false, ...) never returns anything for
// pollInterval to call this against in the first place, for a cache-derived node. A purely
// locally-tracked unconfirmed node (from this satellite's own peer walk) legitimately has no
// history to report either, since this store keeps no such timeline -- an empty result is the
// exact right answer, not a lie.
func (s *Store) GetNodeHistory(ctx context.Context, nodeID uuid.UUID, limit int) ([]storage.HealthCheck, error) {
	return []storage.HealthCheck{}, nil
}

// GetNodeHistoryForNodes is the batch form of GetNodeHistory, same trivial-empty reasoning.
func (s *Store) GetNodeHistoryForNodes(ctx context.Context, nodeIDs []uuid.UUID, limit int) (map[uuid.UUID][]storage.HealthCheck, error) {
	out := make(map[uuid.UUID][]storage.HealthCheck, len(nodeIDs))
	for _, id := range nodeIDs {
		out[id] = []storage.HealthCheck{}
	}
	return out, nil
}

// GetRecentSuccessfulHealthChecks is a trivial no-op, same reasoning as GetNodeHistory.
func (s *Store) GetRecentSuccessfulHealthChecks(ctx context.Context, nodeID uuid.UUID, limit int) ([]storage.HealthCheck, error) {
	return []storage.HealthCheck{}, nil
}

// GetLatestHealthCheck is a trivial no-op, same reasoning as GetNodeHistory -- this store
// keeps no node_health timeline of its own.
func (s *Store) GetLatestHealthCheck(ctx context.Context, nodeID uuid.UUID, probeSource storage.ProbeSource) (*storage.HealthCheck, error) {
	return nil, nil
}

// SetNodeWalletHTTPPort is not supported: a satellite never has occasion to set this --
// only the central API's own handleApproveSubmission does (see storage.Store's doc
// comment on this method for the hard safety rule around who may ever call it).
func (s *Store) SetNodeWalletHTTPPort(ctx context.Context, id uuid.UUID, port *int) error {
	return errNotSupported
}

// SetNodeWalletHTTPPortByAddress is not supported, same reasoning as
// SetNodeWalletHTTPPort -- internal/collector's syncOwnedWalletHTTPPorts is only ever wired
// up with a non-nil Collector.OwnedWalletHTTPPorts by cmd/netmap/main.go (the central
// process), never by cmd/netmap-p2p-responder (the satellite this Store backs), so this is
// never actually reached in practice.
func (s *Store) SetNodeWalletHTTPPortByAddress(ctx context.Context, address string, port int) (bool, error) {
	return false, errNotSupported
}

// WalletHTTPUptime is not supported: the /wallet-nodes dashboard page is a central-API-only
// concern, same as every other dashboard aggregate in this file.
func (s *Store) WalletHTTPUptime(ctx context.Context, nodeID uuid.UUID, since time.Duration) (*float64, int, error) {
	return nil, 0, errNotSupported
}

// CreatePendingWalletSubmission is not supported: the wallet-node registration review
// queue is a central-API-only concern, same reasoning as CreatePendingSubmission.
func (s *Store) CreatePendingWalletSubmission(ctx context.Context, host string, walletHTTPPort int) (storage.PendingWalletSubmission, error) {
	return storage.PendingWalletSubmission{}, errNotSupported
}

// ListPendingWalletSubmissions is not supported: see CreatePendingWalletSubmission.
func (s *Store) ListPendingWalletSubmissions(ctx context.Context, status string) ([]storage.PendingWalletSubmission, error) {
	return nil, errNotSupported
}

// GetPendingWalletSubmission is not supported: see CreatePendingWalletSubmission.
func (s *Store) GetPendingWalletSubmission(ctx context.Context, id uuid.UUID) (storage.PendingWalletSubmission, error) {
	return storage.PendingWalletSubmission{}, errNotSupported
}

// RecordWalletSubmissionProbeResult is not supported: see CreatePendingWalletSubmission.
func (s *Store) RecordWalletSubmissionProbeResult(ctx context.Context, id uuid.UUID, reachable bool) error {
	return errNotSupported
}

// ApprovePendingWalletSubmission is not supported: see CreatePendingWalletSubmission.
func (s *Store) ApprovePendingWalletSubmission(ctx context.Context, id uuid.UUID, promotedNodeID uuid.UUID, outcome storage.WalletProbeOutcome) error {
	return errNotSupported
}

// RejectPendingWalletSubmission is not supported: see CreatePendingWalletSubmission.
func (s *Store) RejectPendingWalletSubmission(ctx context.Context, id uuid.UUID, reason *string) error {
	return errNotSupported
}
