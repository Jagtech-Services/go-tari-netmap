package collector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"
)

// TestP2PShardIndexDeterministic verifies that P2PShardIndex is stable/deterministic: the same
// address and shardCount always route to the same shard, across many repeated calls -- this is
// the property collector.go's poll() P2P dispatch and p2pNodeClient.proxyForAddr both rely on
// to agree on shard assignment (see P2PShardIndex's doc comment).
func TestP2PShardIndexDeterministic(t *testing.T) {
	const shardCount = 24
	addrs := []string{
		"1.2.3.4:18189",
		"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.onion:18189",
		"[::1]:18189",
		"",
	}
	for _, addr := range addrs {
		want := P2PShardIndex(addr, shardCount)
		for i := 0; i < 1000; i++ {
			if got := P2PShardIndex(addr, shardCount); got != want {
				t.Fatalf("P2PShardIndex(%q, %d) is non-deterministic: call %d = %d, want %d", addr, shardCount, i, got, want)
			}
		}
	}
}

// TestP2PShardIndexZeroOrNegativeShardCountReturnsZero verifies the documented shardCount <= 0
// => 0 (no sharding) behavior.
func TestP2PShardIndexZeroOrNegativeShardCountReturnsZero(t *testing.T) {
	for _, shardCount := range []int{0, -1, -100} {
		if got := P2PShardIndex("some-addr:18189", shardCount); got != 0 {
			t.Errorf("P2PShardIndex(_, %d) = %d, want 0", shardCount, got)
		}
	}
}

// TestP2PShardIndexRange verifies P2PShardIndex never returns an out-of-range shard index for a
// positive shardCount.
func TestP2PShardIndexRange(t *testing.T) {
	const shardCount = 24
	for i := 0; i < 5000; i++ {
		addr := fmt.Sprintf("%064x.onion:18189", i)
		idx := P2PShardIndex(addr, shardCount)
		if idx < 0 || idx >= shardCount {
			t.Fatalf("P2PShardIndex(%q, %d) = %d, want in [0, %d)", addr, shardCount, idx, shardCount)
		}
	}
}

// TestP2PShardIndexEvenishDistribution hashes several thousand distinct synthetic onion-looking
// address strings across a realistic shard count (24) and asserts no single shard receives
// wildly more than its fair share (within a generous 50%-150%-of-mean tolerance band) -- this
// proves "even-ish", not perfectly uniform; the point is to catch a badly broken/degenerate hash
// usage (e.g. everything landing on shard 0), not to over-assert precision on a general-purpose
// hash function.
func TestP2PShardIndexEvenishDistribution(t *testing.T) {
	const shardCount = 24
	const numAddrs = 24000 // 1000 per shard on average

	counts := make([]int, shardCount)
	for i := 0; i < numAddrs; i++ {
		addr := fmt.Sprintf("%064x.onion:18189", i)
		counts[P2PShardIndex(addr, shardCount)]++
	}

	mean := float64(numAddrs) / float64(shardCount)
	lowerBound := mean * 0.5
	upperBound := mean * 1.5
	for shard, count := range counts {
		if float64(count) < lowerBound || float64(count) > upperBound {
			t.Errorf("shard %d received %d addresses, want within [%.0f, %.0f] (mean %.0f) -- distribution: %v",
				shard, count, lowerBound, upperBound, mean, counts)
		}
	}
}

// TestP2PClientShardedProxiesRoutesByShard verifies that a p2pNodeClient configured with N
// SOCKS proxies actually passes the SHARD-SELECTED proxy address (not just proxy index 0) to
// the underlying probe funcs for a given address, for at least two addresses that P2PShardIndex
// assigns to different shards.
func TestP2PClientShardedProxiesRoutesByShard(t *testing.T) {
	proxies := []string{"127.0.0.1:9100", "127.0.0.1:9101", "127.0.0.1:9102"}

	// Find two addresses that hash to two different shards among the 3 configured proxies, so
	// this test genuinely exercises shard-based routing rather than coincidentally always
	// landing on shard 0.
	var addrA, addrB string
	var shardA int
	found := false
	for i := 0; i < 10000 && !found; i++ {
		addr := fmt.Sprintf("candidate-%d.onion:18189", i)
		shard := P2PShardIndex(addr, len(proxies))
		if addrA == "" {
			addrA, shardA = addr, shard
			continue
		}
		if shard != shardA {
			addrB = addr
			found = true
		}
	}
	if !found {
		t.Fatal("could not find two candidate addresses hashing to different shards -- test setup problem")
	}

	client, ok := NewP2PClientWithShardedProxies(proxies, p2p.NetworkByteMainNet).(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClientWithShardedProxies(...) = %T, want *p2pNodeClient", NewP2PClientWithShardedProxies(proxies, p2p.NetworkByteMainNet))
	}
	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{},
		identity:      &p2p.PeerInfo{},
	}
	client.probes = fake

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wantProxyA := proxies[P2PShardIndex(addrA, len(proxies))]
	if _, err := client.GetInfo(ctx, addrA); err != nil {
		t.Fatalf("GetInfo(%q): %v", addrA, err)
	}
	if fake.lastChainMetadataOpts.SocksProxyAddr != wantProxyA {
		t.Errorf("GetInfo(%q) SocksProxyAddr = %q, want %q (shard %d)", addrA, fake.lastChainMetadataOpts.SocksProxyAddr, wantProxyA, shardA)
	}

	wantProxyB := proxies[P2PShardIndex(addrB, len(proxies))]
	if _, err := client.GetInfo(ctx, addrB); err != nil {
		t.Fatalf("GetInfo(%q): %v", addrB, err)
	}
	if fake.lastChainMetadataOpts.SocksProxyAddr != wantProxyB {
		t.Errorf("GetInfo(%q) SocksProxyAddr = %q, want %q", addrB, fake.lastChainMetadataOpts.SocksProxyAddr, wantProxyB)
	}
	if wantProxyA == wantProxyB {
		t.Fatalf("test setup problem: addrA and addrB resolved to the same proxy %q -- expected different shards", wantProxyA)
	}

	// GetPeers should route through the same shard-selected proxy too.
	if _, err := client.GetPeers(ctx, addrA); err != nil {
		t.Fatalf("GetPeers(%q): %v", addrA, err)
	}
	if fake.lastGetPeersOpts.SocksProxyAddr != wantProxyA {
		t.Errorf("GetPeers(%q) SocksProxyAddr = %q, want %q", addrA, fake.lastGetPeersOpts.SocksProxyAddr, wantProxyA)
	}
}

// TestP2PClientShardCount verifies p2pNodeClient.ShardCount's max(1, len(socksProxyAddrs))
// contract for the zero/one/many-proxy cases.
func TestP2PClientShardCount(t *testing.T) {
	cases := []struct {
		name    string
		proxies []string
		want    int
	}{
		{name: "no proxies", proxies: nil, want: 1},
		{name: "single proxy", proxies: []string{"127.0.0.1:9050"}, want: 1},
		{name: "24 proxies", proxies: make([]string, 24), want: 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, ok := NewP2PClientWithShardedProxies(tc.proxies, p2p.NetworkByteMainNet).(*p2pNodeClient)
			if !ok {
				t.Fatalf("NewP2PClientWithShardedProxies(...) = %T, want *p2pNodeClient", NewP2PClientWithShardedProxies(tc.proxies, p2p.NetworkByteMainNet))
			}
			if got := client.ShardCount(); got != tc.want {
				t.Errorf("ShardCount() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestP2PClientImplementsSharded is a compile-time-ish smoke test proving *p2pNodeClient
// satisfies the Sharded interface collector.go's poll() dispatch type-asserts against.
func TestP2PClientImplementsSharded(t *testing.T) {
	var _ Sharded = NewP2PClient().(*p2pNodeClient)
}
