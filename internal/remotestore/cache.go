package remotestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// seedListWireCandidate mirrors internal/api's exported PublicSeedCandidate JSON shape
// exactly (node_id, public_key as hex, label, addresses) -- see this package's doc comment
// for why this is independently defined rather than importing internal/api, and for the
// accounting of exactly what's NOT carried over the wire (notably: no Tags field at all, and
// no discovery_source).
type seedListWireCandidate struct {
	NodeID    uuid.UUID `json:"node_id"`
	PublicKey string    `json:"public_key"`
	Label     *string   `json:"label,omitempty"`
	Addresses []string  `json:"addresses"`
}

type seedListWireResponse struct {
	Candidates []seedListWireCandidate `json:"candidates"`
	Since      string                  `json:"since"`
}

// refreshCache fetches GET /nodes/seed_list and merges its candidates into this store's local
// node cache. Every candidate becomes (or updates) a cacheDerived trackedNode keyed by its
// real, central-authoritative NodeID -- this is the ONE path by which a real (non-synthetic)
// uuid.UUID ever enters this store's bookkeeping (see identity.go's doc comment).
//
// What is faithfully carried over: NodeID, PublicKey, Label, and every known Address (all of
// which become idByAddress entries pointing at NodeID, so a later local
// UpsertDiscoveredNode/UpsertConfirmedNode call for any of them resolves to the real ID
// instead of minting a synthetic one -- see resolveNodeIDLocked's "soft transition" doc
// comment).
//
// What is NOT faithfully carried, and why: api.PublicSeedCandidate (the wire type GET
// /nodes/seeds and GET /nodes/seed_list both actually serve) carries no Tags field at all, so
// a cached node's Owned status (isOwnedTags) is always false regardless of the real central
// tags -- and no discovery_source field, so DiscoverySource is synthesized as
// storage.DiscoverySourceBoth for every cached entry (a reasonable stand-in: every
// GET /nodes/seed_list candidate is, by construction, already gated on discovery_source IN
// ('registry_submitted', 'both') server-side -- see storage.Store.ListSeedCandidates). See
// this package's doc comment for the accepted-tradeoff framing.
//
// hasHealthChecks is set true for every cached entry: GET /nodes/seed_list only ever returns
// nodes already gated on "at least one reachable=true health check within
// storage.DefaultSeedHealthWindow" server-side, so this is a safe, meaningful inference, not
// a guess.
func (s *Store) refreshCache(ctx context.Context) error {
	url := strings.TrimRight(s.cfg.BaseURL, "/") + "/nodes/seed_list"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errRemoteStore("build seed_list request: %w", err)
	}

	resp, err := s.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return errRemoteStore("fetch seed_list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errRemoteStore("fetch seed_list: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}

	var parsed seedListWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return errRemoteStore("decode seed_list response: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}

	now := time.Now()
	for _, c := range parsed.Candidates {
		if len(c.Addresses) == 0 {
			s.logf("remotestore: seed_list candidate %s has zero addresses, skipping", c.NodeID)
			continue
		}
		pubkey, err := hex.DecodeString(c.PublicKey)
		if err != nil {
			s.logf("remotestore: seed_list candidate %s has invalid hex public_key %q, skipping: %v", c.NodeID, c.PublicKey, err)
			continue
		}

		firstSeen := now
		if existing, ok := s.nodes[c.NodeID]; ok {
			firstSeen = existing.node.FirstSeen
		}

		primary := c.Addresses[0]
		tn := &trackedNode{
			node: storage.Node{
				ID:              c.NodeID,
				Address:         primary,
				PublicKey:       pubkey,
				DiscoverySource: storage.DiscoverySourceBoth,
				Tags:            map[string]any{},
				Label:           c.Label,
				FirstSeen:       firstSeen,
				LastSeen:        now,
			},
			hasHealthChecks: true,
			cacheDerived:    true,
		}

		addrs := make([]storage.NodeAddress, 0, len(c.Addresses))
		for _, a := range c.Addresses {
			addrs = append(addrs, storage.NodeAddress{NodeID: c.NodeID, Address: a, FirstSeen: firstSeen, LastSeen: now})
			s.idByAddress[a] = c.NodeID
		}
		tn.addresses = addrs
		s.addressByID[c.NodeID] = primary

		s.nodes[c.NodeID] = tn
	}

	return nil
}
