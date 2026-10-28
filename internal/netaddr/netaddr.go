// Package netaddr holds shared IP-classification logic with no dependency on
// any other github.com/Jagtech-Services/go-tari-netmap package. It exists purely to
// avoid an import cycle: internal/api already imports internal/collector
// (for collector.NodeClient/collector.ParsePeerAddress/collector.PollOnce),
// so internal/collector cannot import internal/api back. Both packages need
// the exact same SSRF-hardening private/loopback/link-local/multicast/
// unspecified IP check — internal/api applies it to publicly submitted
// addresses (POST /nodes) and self-claimed P2P-responder addresses, while
// internal/collector applies it to peer-graph-walk peer-reported addresses
// (a remote node's GetPeers response) — so the classification predicate
// itself lives here, in a leaf package both can import directly.
package netaddr

import "net"

// IsPrivateOrReservedIP reports whether ip is a private/loopback/
// link-local/multicast/unspecified address. This is the canonical
// SSRF-hardening classification shared by internal/api's
// IsPrivateOrReservedIP (which delegates here) and internal/collector's
// peerAddressAllowed: any address this service might end up dialing on its
// own (via its async health-check/probe machinery, or by walking a peer
// graph) must not be allowed to point back into private/reserved network
// space.
func IsPrivateOrReservedIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// IPv4Host extracts the IPv4 host portion of a "host:port"-shaped
// address string, mirroring internal/api/privacy.go's classifyAddress
// convention (net.SplitHostPort + net.ParseIP, IPv4 vs IPv6 decided by
// whether net.IP.To4 succeeds) without depending on internal/api --
// this lives here, in the leaf netaddr package, for the same reason
// IsPrivateOrReservedIP does (see this file's doc comment): both
// internal/api (the /map feature's owner+ipv4 population filter, see
// BRIEF.md) and internal/collector (the geoip-cache refresh loop's
// candidate-IP extraction) need the identical classification, and
// internal/api already imports internal/collector, so internal/collector
// cannot import internal/api back.
//
// Returns ("", false) for a malformed address (SplitHostPort failure),
// a host that isn't a valid IP at all (e.g. a `.onion` address), or a
// host that parses as IPv6 rather than IPv4. The returned IP string is
// ip.String()'s canonical form, not necessarily byte-identical to the
// input host substring (e.g. no leading zeros), which matters for using
// it as a stable geoip_cache lookup/cache key.
func IPv4Host(address string) (string, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	return ip4.String(), true
}
