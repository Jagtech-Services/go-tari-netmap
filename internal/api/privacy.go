package api

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// PublicNode is the privacy-scrubbed view of a storage.Node exposed via the
// JSON API. It is the single source of truth for what a node looks like to
// an API caller: real address strings (IPv4/IPv6/onion) are NEVER included
// for a node discovered purely by walking the peer graph
// (storage.DiscoverySourceP2P) — Addresses is nil in that case. Only nodes
// whose owner opted in via the public registry-submission endpoint
// (storage.DiscoverySourceRegistry or storage.DiscoverySourceBoth) have
// Addresses populated, with every known address string for that node (not
// just one). The HasIPv4/HasIPv6/HasOnion capability booleans are always
// populated regardless of opt-in status, since knowing a node has (say) an
// onion address doesn't reveal what that address actually is.
//
// Node identity is PublicKey, not Addresses — Addresses (when present) is
// informational, not an identifier. A nil/empty PublicKey means the node is
// an unconfirmed placeholder (discovered by address alone, not yet
// successfully probed to confirm its real pubkey), not an error.
type PublicNode struct {
	ID              uuid.UUID               `json:"id"`
	PublicKey       []byte                  `json:"public_key,omitempty"`
	DiscoverySource storage.DiscoverySource `json:"discovery_source"`
	Tags            map[string]any          `json:"tags"`
	Label           *string                 `json:"label,omitempty"`
	FirstSeen       time.Time               `json:"first_seen"`
	LastSeen        time.Time               `json:"last_seen"`
	HasIPv4         bool                    `json:"has_ipv4"`
	HasIPv6         bool                    `json:"has_ipv6"`
	HasOnion        bool                    `json:"has_onion"`
	Addresses       []string                `json:"addresses,omitempty"`

	// WalletHTTPPort mirrors Addresses' exact opt-in gating: it is only ever populated
	// (from storage.Node.WalletHTTPPort) when DiscoverySource already permits address
	// exposure (registry_submitted or both) -- see ScrubNode. There is deliberately no
	// separate, ungated way to learn a node's wallet-sync HTTP port; a node that hasn't
	// opted into public address listing at all must not leak this port either, even if it
	// were somehow known.
	WalletHTTPPort *int `json:"wallet_http_port,omitempty"`
}

// PublicNodeDegree is the privacy-scrubbed view of a storage.NodeDegree
// exposed via GET /topology/top-peered. storage.NodeDegree carries a raw
// Address field, so it needs the same treatment as PublicNode rather than
// being returned as-is.
type PublicNodeDegree struct {
	NodeID                uuid.UUID `json:"node_id"`
	PublicKey             []byte    `json:"public_key,omitempty"`
	HasIPv4               bool      `json:"has_ipv4"`
	HasIPv6               bool      `json:"has_ipv6"`
	HasOnion              bool      `json:"has_onion"`
	Addresses             []string  `json:"addresses,omitempty"`
	Degree                int       `json:"degree"`
	InDegree              int       `json:"in_degree"`
	OutDegree             int       `json:"out_degree"`
	OnionPeerCount        int       `json:"onion_peer_count"`
	ClearnetPeerCount     int       `json:"clearnet_peer_count"`
	LiveDegree            int       `json:"live_degree"`
	LiveInDegree          int       `json:"live_in_degree"`
	LiveOutDegree         int       `json:"live_out_degree"`
	LiveOnionPeerCount    int       `json:"live_onion_peer_count"`
	LiveClearnetPeerCount int       `json:"live_clearnet_peer_count"`
}

// addrKind classifies the host portion of an address string for the
// purposes of the HasIPv4/HasIPv6/HasOnion capability booleans.
type addrKind int

const (
	addrKindUnknown addrKind = iota
	addrKindIPv4
	addrKindIPv6
	addrKindOnion
)

// classifyAddress splits address into host:port (via net.SplitHostPort)
// and classifies the host: a ".onion" suffix (case-insensitive) is onion;
// otherwise the host is parsed as an IP and classified IPv4 vs IPv6 by
// whether net.IP.To4 succeeds. Malformed addresses (SplitHostPort failure,
// or a host that's neither a valid IP nor ends in .onion) classify as
// addrKindUnknown rather than erroring — a single bad address entry must
// not fail the whole request.
func classifyAddress(address string) addrKind {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return addrKindUnknown
	}

	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		return addrKindOnion
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return addrKindUnknown
	}
	if ip.To4() != nil {
		return addrKindIPv4
	}
	return addrKindIPv6
}

// addressStrings returns the set of raw address strings to classify for
// n: every entry in addrs if non-empty, otherwise falling back to n's own
// Address field (covers rows/callers that haven't loaded node_addresses).
func addressStrings(n storage.Node, addrs []storage.NodeAddress) []string {
	if len(addrs) == 0 {
		if n.Address == "" {
			return nil
		}
		return []string{n.Address}
	}

	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.Address
	}
	return out
}

// ScrubNode builds the PublicNode view of n given its known addresses
// addrs (pass the result of Store.ListNodeAddresses; an empty/nil slice is
// fine and falls back to n.Address for capability classification). This is
// the single place responsible for deciding whether a real address string
// reaches an API response — see the hard privacy requirement in this
// package's doc comment on PublicNode.
func ScrubNode(n storage.Node, addrs []storage.NodeAddress) PublicNode {
	pn := PublicNode{
		ID:              n.ID,
		PublicKey:       n.PublicKey,
		DiscoverySource: n.DiscoverySource,
		Tags:            n.Tags,
		Label:           n.Label,
		FirstSeen:       n.FirstSeen,
		LastSeen:        n.LastSeen,
	}

	for _, a := range addressStrings(n, addrs) {
		switch classifyAddress(a) {
		case addrKindIPv4:
			pn.HasIPv4 = true
		case addrKindIPv6:
			pn.HasIPv6 = true
		case addrKindOnion:
			pn.HasOnion = true
		}
	}

	if n.DiscoverySource == storage.DiscoverySourceRegistry || n.DiscoverySource == storage.DiscoverySourceBoth {
		pn.Addresses = addressStrings(n, addrs)
		// WalletHTTPPort goes through the EXACT SAME gate as Addresses above -- see this
		// hard requirement on PublicNode.WalletHTTPPort's doc comment and
		// storage.Node.WalletHTTPPort's. There is no separate condition or ungated
		// route for this field; it is only ever set here, inside this same if-block.
		pn.WalletHTTPPort = n.WalletHTTPPort
	}

	return pn
}

// ScrubNodeDegree builds the PublicNodeDegree view of nd. Unlike ScrubNode,
// it needs to look up the full node (for DiscoverySource) and its
// addresses, since storage.NodeDegree only carries a raw Address string
// and a NodeID — hence the extra store.GetNode/store.ListNodeAddresses
// round trip per result. Acceptable N+1 given TopPeeredNodes results are
// capped at limit.
func ScrubNodeDegree(ctx context.Context, store storage.Store, nd storage.NodeDegree) (PublicNodeDegree, error) {
	n, err := store.GetNode(ctx, nd.NodeID)
	if err != nil {
		return PublicNodeDegree{}, err
	}
	addrs, err := store.ListNodeAddresses(ctx, nd.NodeID)
	if err != nil {
		return PublicNodeDegree{}, err
	}

	pn := ScrubNode(n, addrs)
	return PublicNodeDegree{
		NodeID:                nd.NodeID,
		PublicKey:             pn.PublicKey,
		HasIPv4:               pn.HasIPv4,
		HasIPv6:               pn.HasIPv6,
		HasOnion:              pn.HasOnion,
		Addresses:             pn.Addresses,
		Degree:                nd.Degree,
		InDegree:              nd.InDegree,
		OutDegree:             nd.OutDegree,
		OnionPeerCount:        nd.OnionPeerCount,
		ClearnetPeerCount:     nd.ClearnetPeerCount,
		LiveDegree:            nd.LiveDegree,
		LiveInDegree:          nd.LiveInDegree,
		LiveOutDegree:         nd.LiveOutDegree,
		LiveOnionPeerCount:    nd.LiveOnionPeerCount,
		LiveClearnetPeerCount: nd.LiveClearnetPeerCount,
	}, nil
}
