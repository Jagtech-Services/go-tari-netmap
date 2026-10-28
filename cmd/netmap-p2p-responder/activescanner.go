package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// newActiveScanner builds the internal/collector.Collector this binary runs for its
// active-scanner role, wired against store (a remote-collector satellite's
// internal/remotestore.Store, but any storage.Store works) -- this is the exact same
// peer-graph-walking/health-checking logic cmd/netmap's own binary runs (see that binary's
// main.go), mirrored here minus anything Postgres-specific (there is none left to remove:
// store is passed in fully constructed, and this function never touches migrations).
//
// metrics' OnPollResult (see this repo's readiness-review follow-up, Fix 2 / findings
// I17/I28) is wired here, mirroring cmd/netmap/main.go's identical `c.OnPollResult =
// metrics.onPollResult` -- before this fix, this binary's active-scanner role emitted zero
// metrics of its own, unlike cmd/netmap's Collector.
//
// Every env var below is named identically to cmd/netmap/main.go's own equivalent, so a single
// shared deployment config convention applies across both binaries -- see each var's own
// comment in cmd/netmap/main.go for the full rationale behind each; this function only
// reproduces the wiring, not the reasoning already documented there.
func newActiveScanner(store storage.Store, metrics *responderMetrics) *collector.Collector {
	ownedGRPCAddresses := parseOwnedGRPCAddresses(os.Getenv("NETMAP_OWNED_GRPC_ADDRESSES"))
	grpcClient := collector.NewGRPCClientWithAddressMap(ownedGRPCAddresses)

	socksProxyAddrs := parseSocksProxyAddrs(os.Getenv("NETMAP_SOCKS_PROXY_ADDRS"), os.Getenv("NETMAP_SOCKS_PROXY_ADDR"))

	var networkByte byte
	if v := os.Getenv("NETMAP_NETWORK_BYTE"); v != "" {
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			log.Printf("netmap-p2p-responder: invalid NETMAP_NETWORK_BYTE %q, ignoring (defaulting to MainNet): %v", v, err)
		} else {
			networkByte = byte(n)
		}
	}
	p2pClient := collector.NewP2PClientWithShardedProxies(socksProxyAddrs, networkByte)

	c := collector.New(collector.Config{
		SeedNodes:  parseSeedNodes(os.Getenv("NETMAP_SEED_NODES")),
		DialJitter: 500 * time.Millisecond,
	})
	c.Storage = store
	c.GRPCClient = grpcClient
	c.P2PClient = p2pClient
	c.OnPollResult = metrics.onPollResult
	return c
}

// parseSeedNodes parses a comma-separated list of seed node addresses, trimming whitespace and
// dropping empty entries -- identical to cmd/netmap/main.go's own helper of the same name
// (duplicated here rather than shared, since Go main packages aren't importable).
func parseSeedNodes(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	seeds := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			seeds = append(seeds, p)
		}
	}
	return seeds
}

// parseOwnedGRPCAddresses parses NETMAP_OWNED_GRPC_ADDRESSES's raw value, identical to
// cmd/netmap/main.go's own helper of the same name -- see that function's doc comment for the
// full "p2pAddress=grpcAddress" format rationale.
func parseOwnedGRPCAddresses(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		p2pAddr, grpcAddr, ok := strings.Cut(pair, "=")
		p2pAddr = strings.TrimSpace(p2pAddr)
		grpcAddr = strings.TrimSpace(grpcAddr)
		if !ok || p2pAddr == "" || grpcAddr == "" {
			log.Printf("netmap-p2p-responder: skipping malformed NETMAP_OWNED_GRPC_ADDRESSES entry %q (want \"p2pAddress=grpcAddress\")", pair)
			continue
		}
		out[p2pAddr] = grpcAddr
	}
	return out
}

// parseSocksProxyAddrs implements NETMAP_SOCKS_PROXY_ADDRS' plural-preferred/
// NETMAP_SOCKS_PROXY_ADDR-singular-fallback precedence, identical to cmd/netmap/main.go's own
// helper of the same name.
func parseSocksProxyAddrs(pluralRaw, singularRaw string) []string {
	if pluralRaw != "" {
		return parseSeedNodes(pluralRaw)
	}
	if singularRaw != "" {
		return []string{singularRaw}
	}
	return nil
}

// selfAdvertisedAddresses converts this binary's -public-tcp-addr/-onion3-addr flag values
// (multiaddr string form, e.g. "/ip4/1.2.3.4/tcp/18189" or "/onion3/<addr>:18189") into the
// plain "host:port" storage convention used throughout storage.Node.Address/node_addresses
// (see internal/collector's parsePeerAddress/classifyAddress for the same convention
// elsewhere in this repo) -- this is exactly what remotestore.Config.SelfAddresses needs for
// the self_identity field of every POST /internal/collectors/report (see this repo's
// governing brief's tagging section): the central API tags whichever node address matches
// self_identity with tags.role = "collector", and it compares against plain "host:port"
// strings, not raw multiaddrs.
//
// At least one of the two arguments is already guaranteed non-empty by
// parseAdvertisedAddresses' own fail-fast check, called before this function in run() -- but
// this function does not itself assume that, and simply returns an empty slice if both are
// empty.
func selfAdvertisedAddresses(publicTCPAddr, onion3Addr string) ([]string, error) {
	var out []string
	if publicTCPAddr != "" {
		addr, err := parseIP4TCPMultiaddr(publicTCPAddr)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	if onion3Addr != "" {
		addr, err := parseOnion3Multiaddr(onion3Addr)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}

// parseIP4TCPMultiaddr converts a "/ip4/<ip>/tcp/<port>" multiaddr string into "<ip>:<port>".
func parseIP4TCPMultiaddr(s string) (string, error) {
	const prefix = "/ip4/"
	if !strings.HasPrefix(s, prefix) {
		return "", errAdvertisedAddr(s, "expected /ip4/.../tcp/... form")
	}
	rest := strings.TrimPrefix(s, prefix)
	ip, port, ok := strings.Cut(rest, "/tcp/")
	if !ok || ip == "" || port == "" {
		return "", errAdvertisedAddr(s, "expected /ip4/.../tcp/... form")
	}
	if net.ParseIP(ip) == nil {
		return "", errAdvertisedAddr(s, "invalid ipv4 address")
	}
	return net.JoinHostPort(ip, port), nil
}

// parseOnion3Multiaddr converts a "/onion3/<addr>:<port>" multiaddr string into
// "<addr>.onion:<port>".
func parseOnion3Multiaddr(s string) (string, error) {
	const prefix = "/onion3/"
	if !strings.HasPrefix(s, prefix) {
		return "", errAdvertisedAddr(s, "expected /onion3/<addr>:<port> form")
	}
	rest := strings.TrimPrefix(s, prefix)
	host, port, err := net.SplitHostPort(rest)
	if err != nil || host == "" || port == "" {
		return "", errAdvertisedAddr(s, "expected /onion3/<addr>:<port> form")
	}
	return net.JoinHostPort(host+".onion", port), nil
}

func errAdvertisedAddr(addr, reason string) error {
	return &advertisedAddrError{addr: addr, reason: reason}
}

type advertisedAddrError struct {
	addr, reason string
}

func (e *advertisedAddrError) Error() string {
	return "invalid advertised address " + strconv.Quote(e.addr) + ": " + e.reason
}
