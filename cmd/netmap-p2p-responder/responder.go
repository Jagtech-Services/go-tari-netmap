package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"
	pb "github.com/Jagtech-Services/go-tari-lib/v3/p2p/proto"

	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// dbCallTimeout bounds every individual storage.Store call this binary makes from
// ResponderConfig's callbacks. Both callbacks are invoked from goroutines managed entirely by
// go-tari-lib/p2p's Serve (see its doc comment) — a hung Postgres query must never hang or leak
// those goroutines indefinitely.
const dbCallTimeout = 10 * time.Second

// knownGoodWindow is the "known good peers" recency window BRIEF3.md's governing requirement
// ("we want to let the communication happen long enough that we can give them a list of known
// good peers") specifies: only nodes with at least one reachable=true health check within the
// last hour are ever served, mirroring storage.NodeFilter.ReachableSince's exact intended use
// for this scenario.
const knownGoodWindow = time.Hour

// maxServedPeers caps the number of peers ever returned from a single get_peers response,
// applied on top of (not instead of) go-tari-lib/rpc.ServeGetPeers' own server-side N/MaxClaims/
// MaxAddressesPerClaim bound enforcement against the REQUESTING peer's own ask — this is this
// binary's own independent ceiling on the SOURCE list peerListProvider hands to Serve, so a
// get_peers request with N=0 ("give me everything") still can't make this responder hand out an
// unbounded list from the DB. Matches the throwaway spike binary's prior cap of the same value.
const maxServedPeers = 200

// dbBackedResponder holds the real storage.Store dependency behind ResponderConfig's two
// callbacks (OnPeerIdentity/PeerListProvider), replacing go-tari-lib's throwaway in-memory
// peerStore (cmd/p2p-responder-spike/main.go) with real Postgres persistence — see this
// package's main.go doc comment and BRIEF3.md for the full rationale.
type dbBackedResponder struct {
	store storage.Store

	// logf is normally log.Printf; overridable in tests so failures are visible via t.Logf
	// instead of stdout.
	logf func(format string, args ...interface{})

	// metrics holds this process' own dedicated *responderMetrics (see metrics.go) --
	// threaded in explicitly rather than referenced as a package-level var, since metric
	// names are network-scoped and only built once -network is parsed (see main.go's run()
	// and newResponderMetrics).
	metrics *responderMetrics
}

// onPeerIdentity implements ResponderConfig.OnPeerIdentity: on every successful Noise_XX
// handshake + identity exchange, it records the peer as a confirmed node (we have a real
// confirmed pubkey recovered directly from the handshake, per UpsertConfirmedNode's contract —
// this is NOT a third-party claim) and records one health-check row for it.
//
// remoteAddr — the raw TCP connection's remote address (the client's OS-assigned ephemeral
// source port, e.g. "104.161.20.146:49456") — is NEVER recorded as a claimed, dialable address.
// It is only evidence that some connection from this peer happened, which the health-check row
// below already captures via node.ID linkage; treating it as an advertised address would let a
// probe/monitoring client that claims zero real addresses pollute node_addresses with garbage
// that peerListProvider could later serve back out to real peers as if it were dialable (see
// BRIEF6.md for the full incident writeup and the confirmed-live garbage this produced).
//
// The only addresses ever recorded are genuinely self-claimed ones: every entry in
// identity.Addresses, decoded from its raw rust-multiaddr binary encoding via
// collector.ParsePeerAddress (the exact same decoder already proven against gRPC/P2P GetPeers
// claims elsewhere in this repo — see grpc_client.go's parsePeerAddress), and then validated by
// isClaimedAddressAllowed to reject private/loopback/link-local/multicast/unspecified clearnet
// IPs — a peer's own self-claimed address is no more trustworthy than a public HTTP submission
// (internal/api/validate.go's validateSubmittedHost applies the exact same rejection to that
// path, for the exact same reason: this service's own async health-check/probe machinery dials
// every recorded address, so accepting a private/loopback claim is an SSRF vector). See
// OPENCODE_BRIEF.md ("reject invalid P2P self-claimed addresses") for the full incident
// writeup and the confirmed-live garbage (127.0.0.1:*, 192.168.0.120:18189, etc.) this produced.
//
//   - If the peer claims at least one address that survives validation, the first such address
//     is used in the UpsertConfirmedNode call that ensures the node row exists (case (a)/(b)/
//     (c)/(d) in its doc comment in internal/storage/storage.go, depending on prior state), and
//     every subsequent valid claimed address gets its own UpsertConfirmedNode call (case (b):
//     "known pubkey, new address" is a no-op-beyond-ensuring-the-row, so looping it once per
//     address is exactly BRIEF3.md's "address-add call once per claimed address", not a
//     reinvention of its multi-address handling).
//   - If the peer claims ZERO addresses, or every claimed address is rejected by validation
//     (e.g. a bare probe/monitoring client, or a peer claiming only 127.0.0.1), NO node row,
//     node_addresses row, or health-check row is created for this identity exchange at all — a
//     blank/address-less node row is itself an invalid record (per direct instruction from the
//     project owner), not a lesser evil worth recording anyway.
//
// ResponderConfig.OnPeerIdentity's own signature has no context.Context or error return (it's a
// plain synchronous reporting callback — see its doc comment in go-tari-lib/p2p/responder.go),
// so this method derives its own bounded context per call; a failed/slow DB write here is logged
// (never panics) and simply means this one identity exchange's data doesn't make it into
// storage — it must never take down the calling connection goroutine.
func (r *dbBackedResponder) onPeerIdentity(remoteAddr net.Addr, peerStaticKey []byte, identity *p2p.PeerInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), dbCallTimeout)
	defer cancel()

	// Decode every genuinely self-claimed address up front, deduplicating so a peer that
	// (redundantly) repeats the same claim twice doesn't issue two identical DB calls, and
	// rejecting any that fail isClaimedAddressAllowed's private/loopback/reserved-IP check.
	var claimed []string
	seen := make(map[string]bool, len(identity.Addresses))
	for _, raw := range identity.Addresses {
		addr, ok := collector.ParsePeerAddress(raw)
		if !ok || seen[addr] {
			// Skip unparseable claims, best-effort, matching parsePeerAddress's existing
			// "skip rather than emit garbage" convention elsewhere in this repo.
			continue
		}
		if !isClaimedAddressAllowed(addr) {
			// Skip private/loopback/link-local/multicast/unspecified clearnet claims,
			// best-effort, same convention as the unparseable-claim skip above — this
			// must never abort processing of the peer's other claimed addresses.
			r.logf("netmap-p2p-responder: rejecting private/reserved self-claimed address %q from pubkey=%x", addr, peerStaticKey)
			continue
		}
		seen[addr] = true
		claimed = append(claimed, addr)
	}

	if len(claimed) == 0 {
		// No usable/valid claimed addresses (either the peer claimed none at all, or every
		// claim was rejected above) — a blank-address node row is itself an invalid record
		// (see this method's doc comment), so skip recording this identity exchange as a
		// node/health-check row entirely, rather than calling UpsertConfirmedNodeByPubKey.
		r.logf("netmap-p2p-responder: pubkey=%x claimed no usable addresses, skipping node record", peerStaticKey)
		return
	}

	node, err := r.store.UpsertConfirmedNode(ctx, claimed[0], peerStaticKey, storage.DiscoverySourceP2P)
	if err != nil {
		r.metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, resultLabel(false)).Inc()
		r.logf("netmap-p2p-responder: UpsertConfirmedNode(pubkey=%x) failed: %v", peerStaticKey, err)
		return
	}
	r.metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, resultLabel(true)).Inc()

	// claimed is guaranteed non-empty here (the len(claimed) == 0 early-return above), so
	// claimed[1:] is always safe: every entry after the first (already consumed by the
	// UpsertConfirmedNode call above that ensures the node row exists) gets its own
	// UpsertConfirmedNode call.
	for _, addr := range claimed[1:] {
		if _, err := r.store.UpsertConfirmedNode(ctx, addr, peerStaticKey, storage.DiscoverySourceP2P); err != nil {
			r.metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, resultLabel(false)).Inc()
			r.logf("netmap-p2p-responder: UpsertConfirmedNode(%s, self-claimed address) failed: %v", addr, err)
			continue
		}
		r.metrics.bufferAppendResult.WithLabelValues(bufferOperationUpsertNode, resultLabel(true)).Inc()
	}

	var version *string
	if identity.UserAgent != "" {
		v := identity.UserAgent
		version = &v
	}

	// PeerIdentityUpdatedAt: the peer's own self-reported identity-signature timestamp,
	// converted from Unix seconds to a *time.Time — mirroring the exact conversion idiom
	// internal/collector/p2p_client.go's GetInfo already uses for the same field.
	var peerIdentityUpdatedAt *time.Time
	if identity.IdentitySignature != nil && identity.IdentitySignature.UpdatedAt != 0 {
		t := time.Unix(identity.IdentitySignature.UpdatedAt, 0)
		peerIdentityUpdatedAt = &t
	}

	if err := r.store.RecordHealthCheck(ctx, storage.HealthCheckInput{
		NodeID:                node.ID,
		Reachable:             true,
		ProbeSource:           storage.ProbeSourceP2P,
		Version:               version,
		PeerIdentityUpdatedAt: peerIdentityUpdatedAt,
	}); err != nil {
		r.metrics.bufferAppendResult.WithLabelValues(bufferOperationRecordHealth, resultLabel(false)).Inc()
		r.logf("netmap-p2p-responder: RecordHealthCheck(%s) failed: %v", node.ID, err)
		return
	}
	r.metrics.bufferAppendResult.WithLabelValues(bufferOperationRecordHealth, resultLabel(true)).Inc()
}

// isClaimedAddressAllowed reports whether a peer-self-claimed "host:port" address (as decoded
// by collector.ParsePeerAddress) is safe to record and later dial by this service's own async
// health-check/probe machinery. It mirrors internal/api/validate.go's validateSubmittedHost
// exactly, via the shared api.IsPrivateOrReservedIP predicate: a self-claimed P2P identity
// address is no more trustworthy than a publicly submitted one, and both are dialed by the same
// probe machinery, so both get the same SSRF-hardening rejection of private/loopback/
// link-local/multicast/unspecified IPs.
//
// Onion (.onion) addresses are never IPs — net.SplitHostPort followed by net.ParseIP simply
// fails to produce an IP for them, so they fall through this check unchanged, exactly as
// validateSubmittedHost's own onion handling does (see validateHostSyntax's onion branch).
func isClaimedAddressAllowed(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// Should not happen — collector.ParsePeerAddress always returns "host:port" — but
		// fail closed (reject) rather than dial something this function couldn't even
		// parse into a host.
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP at all (e.g. a .onion host) — nothing for the private/reserved-IP
		// check to apply to, so it passes unchanged.
		return true
	}

	return !api.IsPrivateOrReservedIP(ip)
}

// peerListProvider implements ResponderConfig.PeerListProvider: it serves REAL confirmed-good
// peers from storage — the same underlying "known good peers" goal BRIEF3.md's original
// governing requirement described ("we want to let the communication happen long enough that
// we can give them a list of known good peers") — rather than a static/in-memory list.
//
// IMPORTANT (documentation-drift fix, see this repo's readiness-review follow-up): the DB
// query below is storage.NodeFilter{Confirmed: true, ReachableSince: now-1h}, unchanged from
// BRIEF3's original "all confirmed nodes reachable within the last hour" wording — but against
// a remote-collector satellite's ACTUAL storage.Store (internal/remotestore), ReachableSince
// does NOT mean what it means against the central Postgres-backed store. See
// internal/remotestore/reads.go's matchesFilterLocked: a cache-derived tracked node (learned
// via this satellite's periodic GET /nodes/seed_list refresh) is treated as satisfying ANY
// ReachableSince filter unconditionally, while a purely locally-tracked node (confirmed by
// this satellite's own peer walk/handshake, never yet reflected in a seed_list refresh) never
// satisfies one at all (this store keeps no local health-check timeline to check against). So
// in practice, on a remote-collector satellite, the population actually served here is:
//
//   - every node the central system already serves via GET /nodes/seed_list — i.e. opted-in
//     (discovery_source IN ('registry_submitted', 'both')) AND recently reachable per the
//     CENTRAL system's own storage.DefaultSeedHealthWindow (3h, not 1h), refreshed on this
//     satellite's own CacheRefreshInterval cadence (default 60s, so up to that much
//     additionally stale on top of the central window) — NOT "reachable within the last hour"
//     against this satellite's own local view; and
//   - a purely locally-confirmed node this satellite itself has handshaked with is NEVER
//     included here, no matter how recently, until a later seed_list refresh reflects it back
//     (if it ever does — this satellite's own on-the-wire confirmed_nodes reports are, per the
//     Fix 6(a) trust-boundary fix, always applied centrally as discovery_source =
//     p2p_discovered, which never qualifies for GET /nodes/seed_list's opted-in gate on its
//     own).
//
// This is a REAL, intentional behavior change from BRIEF3's original 1h/"every confirmed node"
// requirement (confirmed as intentional, given the Alex-approved satellite design — every
// satellite geographically shares the exact same central "known-good" population rather than
// each independently observing a locally-different subset), not merely a doc-drift bug — this
// comment exists so a future reader isn't misled by the 1h constant/Confirmed-only filter
// below into thinking that's still an accurate description of what gets served.
//
// The DB query (storage.NodeFilter{Confirmed: true, ReachableSince: now-1h}) is the SOURCE list;
// go-tari-lib/rpc.ServeGetPeers still independently enforces the requesting peer's own N/
// MaxClaims/MaxAddressesPerClaim bounds server-side on top of this (see its doc comment) — this
// function's own maxServedPeers cap (applied via NodeFilter.Limit) is a further, independent
// ceiling on the source list itself, so a request with N=0 ("give me everything") still can't
// walk away with an unbounded response.
//
// IMPORTANT — go-tari-lib/v3 (v3.1.0, the tagged release this repo now pins) API gap: the
// original (ctx context.Context) ([]*pb.PeerInfo, error) signature this method used to have
// matched ResponderConfig.PeerListProvider as it existed on go-tari-lib's feat/db-backed-peer-
// list branch (commit 36f40b9, "make PeerListProvider context-aware and error-tolerant") — but
// that branch was NEVER merged into go-tari-lib's main and v3.1.0 does NOT include it (confirmed
// via `git log --all` / `git branch --contains`: 36f40b9 and 5339107 only exist on
// feat/db-backed-peer-list, not on main or any tag). go-tari-lib/v3's actually-tagged
// p2p.ResponderConfig.PeerListProvider is the original, simpler `func() []*pb.PeerInfo` — no
// ctx, no error return at all (see p2p/responder.go's knownPeers(), which just calls
// `c.PeerListProvider()` with no error handling whatsoever). This method's signature below has
// been adapted to match that real, tagged API: ctx is derived internally from
// context.Background() instead of being threaded in from Serve (so a cancelled Serve ctx no
// longer promptly cancels an in-flight DB call — it is still bounded by dbCallTimeout below,
// just not cancelled early), and any error is logged via r.logf and converted to an empty
// result instead of being returned (preserving this method's previously-documented "no peers
// available right now -> empty list" external behavior, just enforced here instead of by
// go-tari-lib, since the real API gives it nowhere to put an error at all).
//
// This is a genuine upstream capability loss, not a stylistic choice — flag it back if DB-call
// cancellation-on-shutdown or structured error propagation for this path matters before
// go-tari-lib's feat/db-backed-peer-list branch is merged and a new tag is cut upstream.
func (r *dbBackedResponder) peerListProvider() []*pb.PeerInfo {
	ctx, cancel := context.WithTimeout(context.Background(), dbCallTimeout)
	defer cancel()

	confirmed := true
	since := time.Now().Add(-knownGoodWindow)
	nodes, err := r.store.ListNodes(ctx, storage.NodeFilter{
		Confirmed:      &confirmed,
		ReachableSince: &since,
		Limit:          maxServedPeers,
	})
	if err != nil {
		r.logf("p2p-responder: peerListProvider: listing known-good confirmed nodes: %v", err)
		return nil
	}
	if len(nodes) == 0 {
		return nil
	}

	nodeIDs := make([]uuid.UUID, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}
	addrsByNode, err := r.store.ListNodeAddressesForNodes(ctx, nodeIDs)
	if err != nil {
		r.logf("p2p-responder: peerListProvider: batch-listing node addresses: %v", err)
		return nil
	}

	peers := make([]*pb.PeerInfo, 0, len(nodes))
	for _, n := range nodes {
		if len(n.PublicKey) == 0 {
			// Should not happen given Confirmed: true (public_key IS NOT NULL), but guard
			// against it anyway rather than serving a peer entry with no identity at all.
			continue
		}

		var addrs [][]byte
		for _, a := range addrsByNode[n.ID] {
			encoded, ok := encodeStoredAddress(a.Address)
			if !ok {
				// Best-effort: skip an address this binary can't re-encode into the wire
				// multiaddr format (e.g. IPv6 -- go-tari-lib's EncodeMultiaddrString only
				// implements /ip4/.../tcp/... and /onion3/...:... today) rather than emit
				// garbage on the wire.
				continue
			}
			addrs = append(addrs, encoded)
		}
		if len(addrs) == 0 {
			// A peer entry with zero addresses is useless to whoever we serve it to (they
			// have nothing to dial) -- skip it, same reasoning as
			// PeerHasNoAddresses/PeerHasNoUsableAddresses rejecting it on the other end.
			continue
		}

		peers = append(peers, &pb.PeerInfo{
			PublicKey: n.PublicKey,
			Claims: []*pb.PeerIdentityClaim{
				{
					Addresses:    addrs,
					PeerFeatures: p2p.FeaturesCommunicationNode,
				},
			},
		})
	}
	return peers
}

// encodeStoredAddress converts a storage-shaped "host:port" address (see
// internal/storage.NodeAddress.Address -- e.g. "1.2.3.4:18189" or
// "abc...xyz.onion:18189", the same convention internal/collector's parsePeerAddress/
// classifyAddress already use throughout this repo) back into the raw rust-multiaddr binary
// wire encoding go-tari-lib/p2p.EncodeMultiaddrString produces, for use in an outgoing
// pb.PeerIdentityClaim.Addresses entry.
//
// Only what EncodeMultiaddrString itself supports can be re-encoded: /ip4/.../tcp/... and
// /onion3/...:... (see go-tari-lib/p2p/multiaddr.go's doc comment -- IPv6 is not implemented
// there today). Anything else, including a stored IPv6 address, returns (nil, false) rather
// than silently dropping/garbling it -- callers skip such addresses (see peerListProvider).
func encodeStoredAddress(address string) ([]byte, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, false
	}

	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		onionAddr := strings.TrimSuffix(strings.ToLower(host), ".onion")
		encoded, err := p2p.EncodeMultiaddrString(fmt.Sprintf("/onion3/%s:%s", onionAddr, port))
		if err != nil {
			return nil, false
		}
		return encoded, true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6 -- not supported by go-tari-lib's EncodeMultiaddrString today.
		return nil, false
	}
	encoded, err := p2p.EncodeMultiaddrString(fmt.Sprintf("/ip4/%s/tcp/%s", ip4.String(), port))
	if err != nil {
		return nil, false
	}
	return encoded, true
}
