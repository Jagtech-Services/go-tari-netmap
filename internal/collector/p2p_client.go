package collector

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"time"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"
	pb "github.com/Jagtech-Services/go-tari-lib/v3/p2p/proto"
	rpcpkg "github.com/Jagtech-Services/go-tari-lib/v3/p2p/rpc"
)

// P2PShardIndex returns which shard (in [0, shardCount)) addr routes to, via a stable FNV-1a
// hash of addr — deterministic across calls/processes/restarts (unlike Go's native map
// iteration order or a pointer-identity hash), so a given address always lands on the same
// shard. shardCount <= 0 is treated as 1 (no sharding, everything routes to shard 0).
//
// This is exported so it's independently unit-testable and so collector.go's poll() P2P
// concurrency dispatch (see Sharded/p2pShardCount) can use the EXACT same shard assignment
// p2pNodeClient itself uses to pick its SOCKS proxy for a given address (see
// p2pNodeClient.proxyForAddr) — these two must agree, or the whole point of bounding
// concurrency PER real Tor instance breaks.
func P2PShardIndex(addr string, shardCount int) int {
	if shardCount <= 0 {
		return 0
	}
	h := fnv.New32a()
	h.Write([]byte(addr))
	return int(h.Sum32() % uint32(shardCount))
}

// p2pDialTimeout bounds how long p2pNodeClient waits for a single probe
// (handshake + identity exchange + the actual RPC call) to complete before
// giving up on an addr. This is deliberately an alias to grpc_client.go's
// dialTimeout, not an independent value: the dial timeout is meant to be
// shared across both transports (real-world network/Tor-circuit latency
// applies equally to either), so bumping one without the other would just
// reintroduce the same too-short-for-onion-peers problem on this path.
// See dialTimeout's doc comment in grpc_client.go for the full reasoning
// (including the live-tested 60s-manual-vs-5s-production finding) behind
// its current 180s value.
const p2pDialTimeout = dialTimeout

// p2pProbeFuncs is the seam between p2pNodeClient and go-tari-lib/p2p's
// free functions (ProbeChainMetadata/ProbeGetPeers/Probe). go-tari-lib/p2p
// exposes no interface of its own to mock, so this package-private
// interface exists purely so tests can inject a fake implementation
// instead of making real P2P network calls — mirroring how grpcNodeClient
// injects dial/dialOpts for the same purpose.
type p2pProbeFuncs interface {
	probeChainMetadata(ctx context.Context, addr string, opts p2p.ProbeOptions) (*p2p.ChainMetadataInfo, error)
	probeGetPeers(ctx context.Context, addr string, req rpcpkg.GetPeersRequest, opts p2p.ProbeOptions) ([]*pb.PeerInfo, error)

	// probeIdentity performs a Noise_XX handshake against addr and
	// returns the peer's confirmed pubkey (PeerInfo.RemoteStaticPubKey),
	// recovered directly from the handshake rather than claimed by a
	// third party. See GetInfo's doc comment for why this is a second,
	// independent probe/dial from probeChainMetadata rather than
	// something bolted onto ChainMetadataInfo. It also takes
	// ProbeOptions for SOCKS support, same reasoning as the other two
	// probes.
	probeIdentity(ctx context.Context, addr string, opts p2p.ProbeOptions) (*p2p.PeerInfo, error)
}

// realP2PProbeFuncs is the default p2pProbeFuncs implementation, backed by
// the real go-tari-lib/p2p package.
type realP2PProbeFuncs struct{}

func (realP2PProbeFuncs) probeChainMetadata(ctx context.Context, addr string, opts p2p.ProbeOptions) (*p2p.ChainMetadataInfo, error) {
	return p2p.ProbeChainMetadataWithOptions(ctx, addr, opts)
}

func (realP2PProbeFuncs) probeGetPeers(ctx context.Context, addr string, req rpcpkg.GetPeersRequest, opts p2p.ProbeOptions) ([]*pb.PeerInfo, error) {
	return p2p.ProbeGetPeersWithOptions(ctx, addr, req, opts)
}

func (realP2PProbeFuncs) probeIdentity(ctx context.Context, addr string, opts p2p.ProbeOptions) (*p2p.PeerInfo, error) {
	return p2p.ProbeWithOptions(ctx, addr, opts)
}

// p2pNodeClient is the real go-tari-lib/p2p-backed NodeClient
// implementation. It talks to a Tari node's comms/RPC-over-P2P interface
// directly (Noise_XX handshake + identity exchange + a single RPC call per
// probe), rather than via gRPC — see grpcNodeClient in grpc_client.go for
// the gRPC-based counterpart.
type p2pNodeClient struct {
	// probes is normally realP2PProbeFuncs{}; overridable in tests to
	// inject a fake implementation so tests exercise GetInfo/GetPeers'
	// mapping logic without any real P2P network calls.
	probes p2pProbeFuncs

	// socksProxyAddrs holds the "host:port" address(es) of one or more SOCKS5 proxies (e.g.
	// local Tor daemon SocksPort instances) passed through to
	// probeChainMetadata/probeGetPeers/probeIdentity via p2p.ProbeOptions, letting this client
	// reach `.onion` Tari peers. This is the field actually consulted by proxyForAddr for every
	// real dial — see NewP2PClientWithShardedProxies' doc comment.
	//
	// A nil/empty slice (the zero value) means no SOCKS proxy at all (dial directly) —
	// proxyForAddr returns "" in that case, preserving the exact pre-existing zero-config
	// behavior. A single-element slice behaves exactly like the pre-sharding single
	// socksProxyAddr field always did: every address routes to that one proxy. More than one
	// element shards each dial's proxy selection across all of them via P2PShardIndex, keyed on
	// the addr being dialed — see proxyForAddr/ShardCount.
	socksProxyAddrs []string

	// socksProxyAddr mirrors socksProxyAddrs[0] (or "" if socksProxyAddrs is empty). It is kept
	// purely for backward compatibility with existing test assertions/call sites that read this
	// exact field name/semantics for the single/zero-proxy case (see NewP2PClient/
	// NewP2PClientWithSocksProxy/NewP2PClientWithOptions, all of which still populate it) — it
	// plays NO role in dial-target resolution; proxyForAddr/GetInfo/GetPeers only ever consult
	// socksProxyAddrs (plural). Do not read this field for anything other than the single/
	// zero-proxy case; with 2+ proxies configured it is simply the first one, not "the" proxy.
	socksProxyAddr string

	// networkByte is passed through to probeChainMetadata/probeGetPeers/
	// probeIdentity via p2p.ProbeOptions.NetworkByte, selecting which
	// Tari network's wire protocol byte this client's P2P handshakes
	// advertise (e.g. MainNet vs a testnet like Esmeralda). The zero
	// value is p2p.NetworkByteMainNet (0x00), preserving the exact
	// pre-existing zero-config behavior for any caller (existing or
	// future) that doesn't set it explicitly — see
	// NewP2PClient/NewP2PClientWithOptions.
	networkByte byte
}

// NewP2PClient returns a NodeClient backed by real go-tari-lib/p2p calls
// against Tari nodes over the comms/RPC-over-P2P transport. It takes no
// required args: each method probes the addr passed to it, per-call. The
// returned client dials directly (no SOCKS proxy) and targets MainNet
// (p2p.NetworkByteMainNet) — see NewP2PClientWithSocksProxy for `.onion`
// peer support, or NewP2PClientWithOptions to target a different Tari
// network (e.g. a testnet).
func NewP2PClient() NodeClient {
	return NewP2PClientWithOptions("", p2p.NetworkByteMainNet)
}

// NewP2PClientWithSocksProxy returns a NodeClient identical to
// NewP2PClient's, except probeChainMetadata/probeGetPeers/probeIdentity
// calls are given proxyAddr (a SOCKS5 proxy "host:port", e.g. a local Tor
// daemon's SocksPort) via p2p.ProbeOptions.SocksProxyAddr, letting this
// client reach `.onion` Tari peers. proxyAddr has no effect on
// non-`.onion` addresses — see p2p.ProbeOptions's doc comment in
// go-tari-lib.
func NewP2PClientWithSocksProxy(proxyAddr string) NodeClient {
	return NewP2PClientWithOptions(proxyAddr, p2p.NetworkByteMainNet)
}

// NewP2PClientWithOptions returns a NodeClient identical to
// NewP2PClient's/NewP2PClientWithSocksProxy's, additionally letting the
// caller pick which Tari network's peers this client will successfully
// probe, via networkByte — a p2p.ProbeOptions.NetworkByte value (e.g.
// p2p.NetworkByteMainNet, p2p.NetworkByteEsmeralda, etc. — the named
// constants live in go-tari-lib's p2p package). socksProxyAddr behaves
// exactly as in NewP2PClientWithSocksProxy (pass "" to dial directly).
//
// This is a thin wrapper around NewP2PClientWithShardedProxies with a
// 0- or 1-element proxy slice — see that constructor's doc comment.
func NewP2PClientWithOptions(socksProxyAddr string, networkByte byte) NodeClient {
	var addrs []string
	if socksProxyAddr != "" {
		addrs = []string{socksProxyAddr}
	}
	return NewP2PClientWithShardedProxies(addrs, networkByte)
}

// NewP2PClientWithShardedProxies returns a NodeClient identical to NewP2PClientWithOptions',
// except it accepts MULTIPLE SOCKS5 proxy addresses (e.g. N independent local Tor daemon
// instances' SocksPorts) rather than just one. Every GetInfo/GetPeers dial resolves which of
// socksProxyAddrs to actually use for its target addr via P2PShardIndex(addr,
// len(socksProxyAddrs)) — see proxyForAddr — so a given address always routes to the same one
// of the N proxies, deterministically, letting a caller (see collector.go's poll() P2P
// dispatch, via the Sharded interface/ShardCount) bound concurrency PER real Tor instance
// rather than across all of them combined.
//
// socksProxyAddrs may be nil/empty (dial directly, no SOCKS proxy at all) or have exactly one
// element (every address routes to that single proxy, byte-for-byte the pre-sharding
// behavior) — both are handled correctly by proxyForAddr/P2PShardIndex without any special-
// casing here. NewP2PClient/NewP2PClientWithSocksProxy/NewP2PClientWithOptions are all thin
// wrappers around this constructor with a 0- or 1-element slice, so every existing caller/test
// that passes a single proxy or none keeps working EXACTLY as before.
func NewP2PClientWithShardedProxies(socksProxyAddrs []string, networkByte byte) NodeClient {
	var single string
	if len(socksProxyAddrs) > 0 {
		single = socksProxyAddrs[0]
	}
	return &p2pNodeClient{
		probes:          realP2PProbeFuncs{},
		socksProxyAddrs: socksProxyAddrs,
		socksProxyAddr:  single,
		networkByte:     networkByte,
	}
}

// proxyForAddr resolves the actual SOCKS5 proxy address to use for a dial to addr, via
// P2PShardIndex(addr, len(c.socksProxyAddrs)) — see NewP2PClientWithShardedProxies' doc
// comment. Returns "" (dial directly) if c.socksProxyAddrs is empty.
func (c *p2pNodeClient) proxyForAddr(addr string) string {
	if len(c.socksProxyAddrs) == 0 {
		return ""
	}
	return c.socksProxyAddrs[P2PShardIndex(addr, len(c.socksProxyAddrs))]
}

// ShardCount implements the Sharded interface (see collector.go), returning the number of
// independent SOCKS proxy shards this client dials across — max(1, len(c.socksProxyAddrs)), so
// a caller bounding concurrency per shard always gets at least 1 (the degenerate "no sharding"
// case for zero or one configured proxy).
func (c *p2pNodeClient) ShardCount() int {
	return max(1, len(c.socksProxyAddrs))
}

// GetInfo implements NodeClient.
//
// Version comes from PeerInfo.UserAgent, returned by the same
// probeIdentity call already made below to recover PublicKey — so it
// costs nothing extra: ChainMetadataInfo (the result of
// go-tari-lib/p2p.ProbeChainMetadata) has no version/user-agent field, but
// probeIdentity's PeerInfo does, and that second dial is already being
// paid for PublicKey's sake (see below), so Version rides along for free.
// Like PublicKey, Version simply stays nil if probeIdentity fails.
//
// PeerIdentityUpdatedAt rides along the exact same way, from
// PeerInfo.IdentitySignature.UpdatedAt (converted from Unix seconds to a
// *time.Time) — the peer's own claim of when it last (re-)signed its P2P
// identity. IdentitySignature is nil if the peer sent no signature (per
// its own doc comment in go-tari-lib), in which case, like Version and
// PublicKey, PeerIdentityUpdatedAt is simply left nil.
//
// PublicKey IS worth that second dial: ChainMetadataInfo
// has no pubkey field at all (out of scope to add — that's inside
// go-tari-lib), so the only way to get addr's confirmed pubkey over this
// transport is a second, independent p2p.ProbeWithOptions call (a full
// Noise_XX handshake in its own right, recovering
// PeerInfo.RemoteStaticPubKey).
// This means GetInfo now makes two separate P2P dials/handshakes to the
// same addr on every call — an accepted, real limitation given
// go-tari-lib is out of scope to modify further to merge them into one
// round trip. The two probes are independent: if probeChainMetadata
// succeeds but probeIdentity fails (or vice versa), that does not fail
// the whole call — Reachable reflects whether probeChainMetadata
// succeeded (the existing behavior/contract other code depends on);
// PublicKey simply stays nil if probeIdentity failed, logged but
// non-fatal.
func (c *p2pNodeClient) GetInfo(ctx context.Context, addr string) (NodeInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, p2pDialTimeout)
	defer cancel()

	proxyAddr := c.proxyForAddr(addr)

	meta, err := c.probes.probeChainMetadata(ctx, addr, p2p.ProbeOptions{SocksProxyAddr: proxyAddr, NetworkByte: c.networkByte})
	if err != nil {
		return NodeInfo{}, fmt.Errorf("p2p ProbeChainMetadata %s: %w", addr, err)
	}

	info := NodeInfo{
		Reachable: true,
	}

	if peerInfo, err := c.probes.probeIdentity(ctx, addr, p2p.ProbeOptions{SocksProxyAddr: proxyAddr, NetworkByte: c.networkByte}); err != nil {
		log.Printf("p2p GetInfo %s: probeIdentity failed (non-fatal, PublicKey left nil): %v", addr, err)
	} else {
		info.PublicKey = peerInfo.RemoteStaticPubKey
		if peerInfo.UserAgent != "" {
			v := peerInfo.UserAgent
			info.Version = &v
		}
		if peerInfo.IdentitySignature != nil && peerInfo.IdentitySignature.UpdatedAt != 0 {
			t := time.Unix(peerInfo.IdentitySignature.UpdatedAt, 0)
			info.PeerIdentityUpdatedAt = &t
		}
	}

	height := int64(meta.BestBlockHeight)
	info.Height = &height
	// Same reasoning as grpc_client.go's GetInfo: Tari's own
	// best-block-height IS its view of the chain tip once synced, and
	// get_chain_metadata doesn't expose a separate "network tip vs our
	// tip" split, so ChainTipHeight mirrors Height here rather than
	// being left nil.
	chainTip := height
	info.ChainTipHeight = &chainTip

	latencyMS := int(meta.Latency.Milliseconds())
	info.LatencyMS = &latencyMS

	// RxtHashrate/C29Hashrate/Sha3xHashrate are not derivable from
	// get_chain_metadata — left nil, same as the GRPC path.

	return info, nil
}

// GetPeers implements NodeClient.
func (c *p2pNodeClient) GetPeers(ctx context.Context, addr string) ([]DiscoveredPeer, error) {
	ctx, cancel := context.WithTimeout(ctx, p2pDialTimeout)
	defer cancel()

	peers, err := c.probes.probeGetPeers(ctx, addr, p2p.DefaultGetPeersRequest(), p2p.ProbeOptions{SocksProxyAddr: c.proxyForAddr(addr), NetworkByte: c.networkByte})
	if err != nil {
		return nil, fmt.Errorf("p2p ProbeGetPeers %s: %w", addr, err)
	}

	seen := make(map[string]bool)
	var discovered []DiscoveredPeer
	for _, peer := range peers {
		var pubKey []byte
		if len(peer.PublicKey) > 0 {
			pubKey = peer.PublicKey
		}
		for _, claim := range peer.Claims {
			for _, a := range claim.Addresses {
				hostPort, ok := parsePeerAddress(a)
				if !ok {
					// Best-effort: skip unparseable addresses rather than
					// emitting garbage, same as grpc_client.go's GetPeers.
					continue
				}
				if seen[hostPort] {
					// A peer can advertise the same address across
					// multiple claims; dedupe before returning.
					continue
				}
				seen[hostPort] = true
				discovered = append(discovered, DiscoveredPeer{Address: hostPort, PublicKey: pubKey})
			}
		}
	}

	return discovered, nil
}
