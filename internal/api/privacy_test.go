package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

func TestScrubNodeP2PHidesAddress(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "1.2.3.4:18142",
		DiscoverySource: storage.DiscoverySourceP2P,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	pn := ScrubNode(n, nil)

	if len(pn.Addresses) != 0 {
		t.Errorf("Addresses = %v, want empty for p2p_discovered node", pn.Addresses)
	}
	if !pn.HasIPv4 {
		t.Error("HasIPv4 = false, want true")
	}
	if pn.HasIPv6 || pn.HasOnion {
		t.Errorf("HasIPv6 = %v, HasOnion = %v, want both false", pn.HasIPv6, pn.HasOnion)
	}
}

// TestScrubNodeP2PHidesWalletHTTPPort is the single most safety-critical test in this
// feature's brief: a p2p_discovered node's wallet_http_port must NEVER be exposed via
// ScrubNode (the single choke point every address-revealing API/dashboard route in this
// codebase goes through), even if that field somehow ended up set on the underlying
// storage.Node -- see storage.Node.WalletHTTPPort's doc comment for the hard safety rule
// this test proves is actually enforced, not just documented. A p2p_discovered node's
// address is already hidden (see TestScrubNodeP2PHidesAddress above); this proves
// WalletHTTPPort is hidden identically, through the exact same gate, not a separate,
// possibly-forgotten condition.
func TestScrubNodeP2PHidesWalletHTTPPort(t *testing.T) {
	port := 9000
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "1.2.3.4:18142",
		DiscoverySource: storage.DiscoverySourceP2P,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		WalletHTTPPort:  &port,
	}

	pn := ScrubNode(n, nil)

	if pn.WalletHTTPPort != nil {
		t.Errorf("WalletHTTPPort = %v, want nil for p2p_discovered node -- this must never be exposed for a node whose discovery_source doesn't permit address exposure", *pn.WalletHTTPPort)
	}
	if len(pn.Addresses) != 0 {
		t.Errorf("Addresses = %v, want empty for p2p_discovered node", pn.Addresses)
	}
}

// TestScrubNodeBothDiscoverySourceExposesWalletHTTPPort verifies the positive case: a node
// whose discovery_source is "both" (seen via both P2P discovery AND public registry
// submission) DOES expose WalletHTTPPort, exactly like it exposes Addresses -- both are
// gated by the identical condition in ScrubNode.
func TestScrubNodeBothDiscoverySourceExposesWalletHTTPPort(t *testing.T) {
	port := 9000
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "9.9.9.9:18142",
		DiscoverySource: storage.DiscoverySourceBoth,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		WalletHTTPPort:  &port,
	}

	pn := ScrubNode(n, nil)

	if pn.WalletHTTPPort == nil || *pn.WalletHTTPPort != port {
		t.Errorf("WalletHTTPPort = %v, want %d", pn.WalletHTTPPort, port)
	}
	if len(pn.Addresses) != 1 || pn.Addresses[0] != "9.9.9.9:18142" {
		t.Errorf("Addresses = %v, want [9.9.9.9:18142]", pn.Addresses)
	}
}

// TestScrubNodeRegistrySubmittedNilWalletHTTPPort verifies that an opted-in
// (registry_submitted) node with NO wallet_http_port set (the overwhelming common case --
// see storage.Node.WalletHTTPPort's doc comment: this is opt-in, not every registered node
// has one) simply omits it, rather than exposing some fabricated/zero value.
func TestScrubNodeRegistrySubmittedNilWalletHTTPPort(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "5.6.7.8:18142",
		DiscoverySource: storage.DiscoverySourceRegistry,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	pn := ScrubNode(n, nil)

	if pn.WalletHTTPPort != nil {
		t.Errorf("WalletHTTPPort = %v, want nil (no port was ever set on this node)", *pn.WalletHTTPPort)
	}
}

func TestScrubNodeRegistrySubmittedShowsAddress(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "5.6.7.8:18142",
		DiscoverySource: storage.DiscoverySourceRegistry,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	pn := ScrubNode(n, nil)

	if len(pn.Addresses) != 1 || pn.Addresses[0] != "5.6.7.8:18142" {
		t.Errorf("Addresses = %v, want [5.6.7.8:18142]", pn.Addresses)
	}
}

func TestScrubNodeBothShowsAddress(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "9.9.9.9:18142",
		DiscoverySource: storage.DiscoverySourceBoth,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	pn := ScrubNode(n, nil)

	if len(pn.Addresses) != 1 || pn.Addresses[0] != "9.9.9.9:18142" {
		t.Errorf("Addresses = %v, want [9.9.9.9:18142]", pn.Addresses)
	}
}

func TestScrubNodeOnionOnly(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		Address:         "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:18142",
		DiscoverySource: storage.DiscoverySourceP2P,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	pn := ScrubNode(n, nil)

	if !pn.HasOnion {
		t.Error("HasOnion = false, want true")
	}
	if pn.HasIPv4 || pn.HasIPv6 {
		t.Errorf("HasIPv4 = %v, HasIPv6 = %v, want both false", pn.HasIPv4, pn.HasIPv6)
	}
	if len(pn.Addresses) != 0 {
		t.Errorf("Addresses = %v, want empty", pn.Addresses)
	}
}

func TestScrubNodeIPv6(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		DiscoverySource: storage.DiscoverySourceP2P,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}
	addrs := []storage.NodeAddress{
		{Address: "[2001:db8::1]:18142"},
	}

	pn := ScrubNode(n, addrs)

	if !pn.HasIPv6 {
		t.Error("HasIPv6 = false, want true")
	}
	if pn.HasIPv4 || pn.HasOnion {
		t.Errorf("HasIPv4 = %v, HasOnion = %v, want both false", pn.HasIPv4, pn.HasOnion)
	}
}

func TestScrubNodeMultipleAddresses(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		DiscoverySource: storage.DiscoverySourceRegistry,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}
	addrs := []storage.NodeAddress{
		{Address: "1.2.3.4:18142"},
		{Address: "[2001:db8::1]:18142"},
		{Address: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:18142"},
	}

	pn := ScrubNode(n, addrs)

	if !pn.HasIPv4 || !pn.HasIPv6 || !pn.HasOnion {
		t.Errorf("HasIPv4 = %v, HasIPv6 = %v, HasOnion = %v, want all true", pn.HasIPv4, pn.HasIPv6, pn.HasOnion)
	}
	// n.Address is empty here (only addrs is populated), so Addresses
	// should contain every entry of addrs, in order, per addressStrings.
	want := []string{
		"1.2.3.4:18142",
		"[2001:db8::1]:18142",
		"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:18142",
	}
	if len(pn.Addresses) != len(want) {
		t.Fatalf("Addresses = %v, want %v", pn.Addresses, want)
	}
	for i, addr := range want {
		if pn.Addresses[i] != addr {
			t.Errorf("Addresses[%d] = %q, want %q", i, pn.Addresses[i], addr)
		}
	}
}

func TestScrubNodeMalformedAddressDoesNotPanic(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		DiscoverySource: storage.DiscoverySourceP2P,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}
	addrs := []storage.NodeAddress{
		{Address: "not-a-valid-address"},   // no port, SplitHostPort fails
		{Address: "1.2.3.4:18142"},         // still classified correctly
		{Address: "totally:bogus:address"}, // malformed, skipped gracefully
	}

	pn := ScrubNode(n, addrs)

	if !pn.HasIPv4 {
		t.Error("HasIPv4 = false, want true (valid entry should still be classified despite malformed siblings)")
	}
	if pn.HasIPv6 || pn.HasOnion {
		t.Errorf("HasIPv6 = %v, HasOnion = %v, want both false", pn.HasIPv6, pn.HasOnion)
	}
}

func TestScrubNodePlaceholderPubKey(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		DiscoverySource: storage.DiscoverySourceP2P,
		PublicKey:       nil,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	pn := ScrubNode(n, nil)

	if len(pn.PublicKey) != 0 {
		t.Errorf("PublicKey = %x, want empty for placeholder node", pn.PublicKey)
	}
}

// TestScrubNodeDualStackOptedInShowsAllAddresses proves the real
// dual-stack-opted-in gap: an opted-in node (registry or both) with both a
// clearnet and an onion address known must have both HasIPv4/HasIPv6 AND
// HasOnion set true, and pn.Addresses must contain every one of those
// known addresses.
func TestScrubNodeDualStackOptedInShowsAllAddresses(t *testing.T) {
	n := storage.Node{
		ID:              uuid.New(),
		DiscoverySource: storage.DiscoverySourceBoth,
		Tags:            map[string]any{},
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}
	const clearnetAddr = "1.2.3.4:18142"
	const onionAddr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:18142"
	addrs := []storage.NodeAddress{
		{Address: clearnetAddr},
		{Address: onionAddr},
	}

	pn := ScrubNode(n, addrs)

	if !pn.HasIPv4 {
		t.Error("HasIPv4 = false, want true")
	}
	if !pn.HasOnion {
		t.Error("HasOnion = false, want true")
	}
	if len(pn.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want both %q and %q", pn.Addresses, clearnetAddr, onionAddr)
	}
	found := map[string]bool{}
	for _, a := range pn.Addresses {
		found[a] = true
	}
	if !found[clearnetAddr] {
		t.Errorf("Addresses = %v, missing clearnet address %q", pn.Addresses, clearnetAddr)
	}
	if !found[onionAddr] {
		t.Errorf("Addresses = %v, missing onion address %q", pn.Addresses, onionAddr)
	}
}

func TestClassifyAddress(t *testing.T) {
	cases := []struct {
		address string
		want    addrKind
	}{
		{"1.2.3.4:18142", addrKindIPv4},
		{"[2001:db8::1]:18142", addrKindIPv6},
		{"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd.onion:18142", addrKindOnion},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCD.ONION:18142", addrKindOnion},
		{"not-a-valid-address", addrKindUnknown},
		{"", addrKindUnknown},
	}
	for _, tc := range cases {
		if got := classifyAddress(tc.address); got != tc.want {
			t.Errorf("classifyAddress(%q) = %v, want %v", tc.address, got, tc.want)
		}
	}
}
