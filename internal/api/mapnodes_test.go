package api

import (
	"testing"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// TestIsMapEligible covers BRIEF.md's exact /map population predicate:
// tags["owner"] non-empty string AND at least one known IPv4 address.
func TestIsMapEligible(t *testing.T) {
	cases := []struct {
		name  string
		node  storage.Node
		addrs []storage.NodeAddress
		want  bool
	}{
		{
			name:  "owner tag + ipv4 address -> eligible",
			node:  storage.Node{Tags: map[string]any{"owner": "Alice"}},
			addrs: []storage.NodeAddress{{Address: "203.0.113.5:18189"}},
			want:  true,
		},
		{
			name:  "owner tag, no addresses at all -> not eligible",
			node:  storage.Node{Tags: map[string]any{"owner": "Alice"}},
			addrs: nil,
			want:  false,
		},
		{
			name:  "owner tag + onion-only address -> not eligible (no ipv4)",
			node:  storage.Node{Tags: map[string]any{"owner": "Alice"}},
			addrs: []storage.NodeAddress{{Address: "abcdefghijklmnop.onion:18189"}},
			want:  false,
		},
		{
			name:  "owner tag + ipv6-only address -> not eligible (no ipv4)",
			node:  storage.Node{Tags: map[string]any{"owner": "Alice"}},
			addrs: []storage.NodeAddress{{Address: "[2001:db8::1]:18189"}},
			want:  false,
		},
		{
			name:  "empty owner tag string -> not eligible even with ipv4",
			node:  storage.Node{Tags: map[string]any{"owner": ""}},
			addrs: []storage.NodeAddress{{Address: "203.0.113.5:18189"}},
			want:  false,
		},
		{
			name:  "no owner tag at all -> not eligible even with ipv4",
			node:  storage.Node{Tags: map[string]any{}},
			addrs: []storage.NodeAddress{{Address: "203.0.113.5:18189"}},
			want:  false,
		},
		{
			name:  "pool_owned bool true but no owner string -> not eligible",
			node:  storage.Node{Tags: map[string]any{"pool_owned": true}},
			addrs: []storage.NodeAddress{{Address: "203.0.113.5:18189"}},
			want:  false,
		},
		{
			name:  "owner tag + mixed onion and ipv4 addresses -> eligible",
			node:  storage.Node{Tags: map[string]any{"owner": "Alice"}},
			addrs: []storage.NodeAddress{{Address: "abcdefghijklmnop.onion:18189"}, {Address: "203.0.113.5:18189"}},
			want:  true,
		},
		{
			name:  "owner tag, no node_addresses rows, falls back to n.Address (ipv4)",
			node:  storage.Node{Tags: map[string]any{"owner": "Alice"}, Address: "203.0.113.5:18189"},
			addrs: nil,
			want:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isMapEligible(tc.node, tc.addrs)
			if got != tc.want {
				t.Errorf("isMapEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFirstIPv4Address covers the address-selection helper directly,
// including its non-IPv4-first ordering behavior (it returns the FIRST
// IPv4 match, not necessarily addrs[0]).
func TestFirstIPv4Address(t *testing.T) {
	n := storage.Node{Address: "fallback-should-not-be-used:1"}
	addrs := []storage.NodeAddress{
		{Address: "abcdefghijklmnop.onion:18189"},
		{Address: "203.0.113.5:18189"},
		{Address: "203.0.113.6:18189"},
	}

	ip, ok := firstIPv4Address(n, addrs)
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if ip != "203.0.113.5" {
		t.Errorf("ip = %q, want %q (first IPv4 match, port stripped)", ip, "203.0.113.5")
	}
}

// TestFirstIPv4AddressNoMatch confirms ok=false when nothing classifies
// as IPv4, rather than e.g. returning the onion address's host string.
func TestFirstIPv4AddressNoMatch(t *testing.T) {
	n := storage.Node{}
	addrs := []storage.NodeAddress{{Address: "abcdefghijklmnop.onion:18189"}}

	if _, ok := firstIPv4Address(n, addrs); ok {
		t.Errorf("expected ok=false for an onion-only address set")
	}
}
