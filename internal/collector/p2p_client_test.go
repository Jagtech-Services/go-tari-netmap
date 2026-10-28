package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"
	pb "github.com/Jagtech-Services/go-tari-lib/v3/p2p/proto"
	rpcpkg "github.com/Jagtech-Services/go-tari-lib/v3/p2p/rpc"
)

// fakeP2PProbeFuncs is a fixture p2pProbeFuncs implementation used to
// exercise p2pNodeClient's GetInfo/GetPeers mapping logic without any real
// P2P network calls.
type fakeP2PProbeFuncs struct {
	chainMetadata    *p2p.ChainMetadataInfo
	chainMetadataErr error

	identity    *p2p.PeerInfo
	identityErr error

	peers    []*pb.PeerInfo
	peersErr error

	// lastChainMetadataOpts/lastGetPeersOpts/lastIdentityOpts record the
	// p2p.ProbeOptions each fake probe method was last called with, so
	// tests can assert on what p2pNodeClient passed through (e.g.
	// socksProxyAddr wiring).
	lastChainMetadataOpts p2p.ProbeOptions
	lastGetPeersOpts      p2p.ProbeOptions
	lastIdentityOpts      p2p.ProbeOptions
}

func (f *fakeP2PProbeFuncs) probeChainMetadata(ctx context.Context, addr string, opts p2p.ProbeOptions) (*p2p.ChainMetadataInfo, error) {
	f.lastChainMetadataOpts = opts
	if f.chainMetadataErr != nil {
		return nil, f.chainMetadataErr
	}
	return f.chainMetadata, nil
}

func (f *fakeP2PProbeFuncs) probeIdentity(ctx context.Context, addr string, opts p2p.ProbeOptions) (*p2p.PeerInfo, error) {
	f.lastIdentityOpts = opts
	if f.identityErr != nil {
		return nil, f.identityErr
	}
	return f.identity, nil
}

func (f *fakeP2PProbeFuncs) probeGetPeers(ctx context.Context, addr string, req rpcpkg.GetPeersRequest, opts p2p.ProbeOptions) ([]*pb.PeerInfo, error) {
	f.lastGetPeersOpts = opts
	if f.peersErr != nil {
		return nil, f.peersErr
	}
	return f.peers, nil
}

func TestP2PClientGetInfo(t *testing.T) {
	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{
			BestBlockHeight: 54321,
			Latency:         42 * time.Millisecond,
		},
		identity: &p2p.PeerInfo{
			RemoteStaticPubKey: []byte("node-own-pubkey"),
			UserAgent:          "minotari_node/5.5.0",
			IdentitySignature:  &p2p.IdentitySignature{UpdatedAt: 1700000000},
		},
	}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.GetInfo(ctx, "127.0.0.1:18189")
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !info.Reachable {
		t.Errorf("Reachable = false, want true")
	}
	if info.Height == nil || *info.Height != 54321 {
		t.Errorf("Height = %v, want 54321", info.Height)
	}
	if info.ChainTipHeight == nil || *info.ChainTipHeight != 54321 {
		t.Errorf("ChainTipHeight = %v, want 54321", info.ChainTipHeight)
	}
	if info.LatencyMS == nil || *info.LatencyMS != 42 {
		t.Errorf("LatencyMS = %v, want 42", info.LatencyMS)
	}
	if string(info.PublicKey) != "node-own-pubkey" {
		t.Errorf("PublicKey = %q, want %q", info.PublicKey, "node-own-pubkey")
	}
	if info.Version == nil || *info.Version != "minotari_node/5.5.0" {
		t.Errorf("Version = %v, want %q", info.Version, "minotari_node/5.5.0")
	}
	if info.PeerIdentityUpdatedAt == nil || !info.PeerIdentityUpdatedAt.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("PeerIdentityUpdatedAt = %v, want %v", info.PeerIdentityUpdatedAt, time.Unix(1700000000, 0))
	}
	if info.RxtHashrate != nil || info.C29Hashrate != nil || info.Sha3xHashrate != nil {
		t.Errorf("expected all hashrate fields nil, got Rxt=%v C29=%v Sha3x=%v",
			info.RxtHashrate, info.C29Hashrate, info.Sha3xHashrate)
	}
}

// TestP2PClientGetInfoNoIdentitySignatureLeavesPeerIdentityUpdatedAtNil
// verifies that a peer sending no IdentitySignature at all (a nil
// pointer, per PeerInfo.IdentitySignature's doc comment in go-tari-lib)
// leaves PeerIdentityUpdatedAt nil rather than panicking or defaulting to
// some zero-time value.
func TestP2PClientGetInfoNoIdentitySignatureLeavesPeerIdentityUpdatedAtNil(t *testing.T) {
	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{BestBlockHeight: 1},
		identity: &p2p.PeerInfo{
			RemoteStaticPubKey: []byte("node-own-pubkey"),
			IdentitySignature:  nil,
		},
	}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.GetInfo(ctx, "127.0.0.1:18189")
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.PeerIdentityUpdatedAt != nil {
		t.Errorf("PeerIdentityUpdatedAt = %v, want nil", *info.PeerIdentityUpdatedAt)
	}
}

// TestP2PClientGetInfoIdentityProbeFailureIsNonFatal verifies that a
// failing probeIdentity call does not fail GetInfo overall: Reachable/
// Height must still reflect the successful probeChainMetadata call, only
// PublicKey is left nil.
func TestP2PClientGetInfoIdentityProbeFailureIsNonFatal(t *testing.T) {
	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{
			BestBlockHeight: 111,
		},
		identityErr: errors.New("boom: identity handshake failed"),
	}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.GetInfo(ctx, "127.0.0.1:18189")
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !info.Reachable {
		t.Errorf("Reachable = false, want true (identity probe failure must not affect Reachable)")
	}
	if info.Height == nil || *info.Height != 111 {
		t.Errorf("Height = %v, want 111", info.Height)
	}
	if info.PublicKey != nil {
		t.Errorf("PublicKey = %x, want nil", info.PublicKey)
	}
	if info.Version != nil {
		t.Errorf("Version = %v, want nil", *info.Version)
	}
	if info.PeerIdentityUpdatedAt != nil {
		t.Errorf("PeerIdentityUpdatedAt = %v, want nil", *info.PeerIdentityUpdatedAt)
	}
}

func TestP2PClientGetInfoPropagatesProbeError(t *testing.T) {
	fake := &fakeP2PProbeFuncs{chainMetadataErr: errors.New("boom: handshake failed")}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetInfo(ctx, "127.0.0.1:18189"); err == nil {
		t.Fatal("GetInfo: expected error from failing ProbeChainMetadata, got nil")
	}
}

func TestP2PClientGetPeers(t *testing.T) {
	// One peer with a single text-multiaddr claim, one peer with two
	// claims that both advertise the SAME address (dedup across claims),
	// one peer with a mix of a parseable and an unparseable address
	// (unparseable skipped, parseable kept), and one peer whose only
	// address is unparseable (contributes nothing).
	binaryIP4TCP := encodeTestBinaryMultiaddrIP4TCP([4]byte{10, 0, 0, 1}, 18189)

	fake := &fakeP2PProbeFuncs{
		peers: []*pb.PeerInfo{
			{
				PublicKey: []byte("peer1"),
				Claims: []*pb.PeerIdentityClaim{
					{Addresses: [][]byte{[]byte("/ip4/1.2.3.4/tcp/18189")}},
				},
			},
			{
				PublicKey: []byte("peer2-dup-across-claims"),
				Claims: []*pb.PeerIdentityClaim{
					{Addresses: [][]byte{binaryIP4TCP}},
					{Addresses: [][]byte{binaryIP4TCP}}, // same address, second claim
				},
			},
			{
				PublicKey: []byte("peer3-mixed"),
				Claims: []*pb.PeerIdentityClaim{
					{Addresses: [][]byte{
						{0xff, 0xff, 0xff}, // garbage, unparseable
						[]byte("/ip4/9.9.9.9/tcp/1234"),
					}},
				},
			},
			{
				PublicKey: []byte("peer4-unparseable-only"),
				Claims: []*pb.PeerIdentityClaim{
					{Addresses: [][]byte{{0x00, 0x01, 0x02}}},
				},
			},
		},
	}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	peers, err := client.GetPeers(ctx, "127.0.0.1:18189")
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}

	want := map[string]string{
		"1.2.3.4:18189":  "peer1",
		"10.0.0.1:18189": "peer2-dup-across-claims",
		"9.9.9.9:1234":   "peer3-mixed",
	}
	if len(peers) != len(want) {
		t.Fatalf("GetPeers returned %d peers, want %d: %v", len(peers), len(want), peers)
	}
	seen := map[string]bool{}
	for _, p := range peers {
		wantPubKey, ok := want[p.Address]
		if !ok {
			t.Errorf("unexpected peer address %q", p.Address)
			continue
		}
		if seen[p.Address] {
			t.Errorf("peer address %q returned more than once (dedup failed)", p.Address)
		}
		if string(p.PublicKey) != wantPubKey {
			t.Errorf("peer %q PublicKey = %q, want %q", p.Address, p.PublicKey, wantPubKey)
		}
		seen[p.Address] = true
	}
	for addr := range want {
		if !seen[addr] {
			t.Errorf("expected peer address %q not found in result %v", addr, peers)
		}
	}
}

func TestP2PClientGetPeersPropagatesProbeError(t *testing.T) {
	fake := &fakeP2PProbeFuncs{peersErr: errors.New("boom: rpc negotiation failed")}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetPeers(ctx, "127.0.0.1:18189"); err == nil {
		t.Fatal("GetPeers: expected error from failing ProbeGetPeers, got nil")
	}
}

func TestNewP2PClientReturnsRealProbes(t *testing.T) {
	client, ok := NewP2PClient().(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClient() = %T, want *p2pNodeClient", NewP2PClient())
	}
	if _, ok := client.probes.(realP2PProbeFuncs); !ok {
		t.Errorf("NewP2PClient().probes = %T, want realP2PProbeFuncs", client.probes)
	}
	if client.socksProxyAddr != "" {
		t.Errorf("NewP2PClient().socksProxyAddr = %q, want \"\"", client.socksProxyAddr)
	}
	if client.networkByte != p2p.NetworkByteMainNet {
		t.Errorf("NewP2PClient().networkByte = %v, want p2p.NetworkByteMainNet (%v)", client.networkByte, p2p.NetworkByteMainNet)
	}
}

// TestNewP2PClientWithSocksProxyReturnsRealProbes mirrors
// TestNewP2PClientReturnsRealProbes, additionally asserting that the
// given proxy address is stored on the returned client.
func TestNewP2PClientWithSocksProxyReturnsRealProbes(t *testing.T) {
	client, ok := NewP2PClientWithSocksProxy("127.0.0.1:9050").(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClientWithSocksProxy(...) = %T, want *p2pNodeClient", NewP2PClientWithSocksProxy("127.0.0.1:9050"))
	}
	if _, ok := client.probes.(realP2PProbeFuncs); !ok {
		t.Errorf("NewP2PClientWithSocksProxy(...).probes = %T, want realP2PProbeFuncs", client.probes)
	}
	if client.socksProxyAddr != "127.0.0.1:9050" {
		t.Errorf("NewP2PClientWithSocksProxy(...).socksProxyAddr = %q, want %q", client.socksProxyAddr, "127.0.0.1:9050")
	}
}

// TestP2PClientZeroSocksProxyAddrIsZeroConfigProbeOptions verifies that a
// p2pNodeClient with socksProxyAddr left as its zero value ("") passes a
// zero-value p2p.ProbeOptions through to probeChainMetadata/probeGetPeers
// — i.e. existing callers that never set socksProxyAddr get byte-for-byte
// identical zero-config behavior after this change.
func TestP2PClientZeroSocksProxyAddrIsZeroConfigProbeOptions(t *testing.T) {
	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{},
		identity:      &p2p.PeerInfo{},
	}
	client := &p2pNodeClient{probes: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetInfo(ctx, "127.0.0.1:18189"); err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if _, err := client.GetPeers(ctx, "127.0.0.1:18189"); err != nil {
		t.Fatalf("GetPeers: %v", err)
	}

	if fake.lastChainMetadataOpts != (p2p.ProbeOptions{}) {
		t.Errorf("lastChainMetadataOpts = %+v, want zero value", fake.lastChainMetadataOpts)
	}
	if fake.lastGetPeersOpts != (p2p.ProbeOptions{}) {
		t.Errorf("lastGetPeersOpts = %+v, want zero value", fake.lastGetPeersOpts)
	}
	if fake.lastIdentityOpts != (p2p.ProbeOptions{}) {
		t.Errorf("lastIdentityOpts = %+v, want zero value", fake.lastIdentityOpts)
	}
}

// TestP2PClientPassesThroughSocksProxyAddr verifies that a p2pNodeClient
// with socksProxyAddr set passes a p2p.ProbeOptions carrying that same
// address through to both probeChainMetadata and probeGetPeers.
func TestP2PClientPassesThroughSocksProxyAddr(t *testing.T) {
	const proxyAddr = "127.0.0.1:9050"

	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{},
		identity:      &p2p.PeerInfo{},
	}
	client, ok := NewP2PClientWithSocksProxy(proxyAddr).(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClientWithSocksProxy(...) = %T, want *p2pNodeClient", NewP2PClientWithSocksProxy(proxyAddr))
	}
	client.probes = fake

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetInfo(ctx, "127.0.0.1:18189"); err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if _, err := client.GetPeers(ctx, "127.0.0.1:18189"); err != nil {
		t.Fatalf("GetPeers: %v", err)
	}

	if fake.lastChainMetadataOpts.SocksProxyAddr != proxyAddr {
		t.Errorf("lastChainMetadataOpts.SocksProxyAddr = %q, want %q", fake.lastChainMetadataOpts.SocksProxyAddr, proxyAddr)
	}
	if fake.lastGetPeersOpts.SocksProxyAddr != proxyAddr {
		t.Errorf("lastGetPeersOpts.SocksProxyAddr = %q, want %q", fake.lastGetPeersOpts.SocksProxyAddr, proxyAddr)
	}
	if fake.lastIdentityOpts.SocksProxyAddr != proxyAddr {
		t.Errorf("lastIdentityOpts.SocksProxyAddr = %q, want %q", fake.lastIdentityOpts.SocksProxyAddr, proxyAddr)
	}
}

// TestNewP2PClientWithOptionsReturnsRealProbes verifies that
// NewP2PClientWithOptions stores both the given socksProxyAddr and
// networkByte on the returned client, mirroring
// TestNewP2PClientWithSocksProxyReturnsRealProbes.
func TestNewP2PClientWithOptionsReturnsRealProbes(t *testing.T) {
	client, ok := NewP2PClientWithOptions("127.0.0.1:9050", p2p.NetworkByteEsmeralda).(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClientWithOptions(...) = %T, want *p2pNodeClient", NewP2PClientWithOptions("127.0.0.1:9050", p2p.NetworkByteEsmeralda))
	}
	if _, ok := client.probes.(realP2PProbeFuncs); !ok {
		t.Errorf("NewP2PClientWithOptions(...).probes = %T, want realP2PProbeFuncs", client.probes)
	}
	if client.socksProxyAddr != "127.0.0.1:9050" {
		t.Errorf("NewP2PClientWithOptions(...).socksProxyAddr = %q, want %q", client.socksProxyAddr, "127.0.0.1:9050")
	}
	if client.networkByte != p2p.NetworkByteEsmeralda {
		t.Errorf("NewP2PClientWithOptions(...).networkByte = %v, want %v", client.networkByte, p2p.NetworkByteEsmeralda)
	}
}

// TestP2PClientGetInfoPassesThroughNetworkByte verifies that a
// p2pNodeClient constructed with a non-default networkByte passes that
// same byte through in the p2p.ProbeOptions given to both
// probeChainMetadata and probeIdentity during GetInfo.
func TestP2PClientGetInfoPassesThroughNetworkByte(t *testing.T) {
	fake := &fakeP2PProbeFuncs{
		chainMetadata: &p2p.ChainMetadataInfo{},
		identity:      &p2p.PeerInfo{},
	}
	client, ok := NewP2PClientWithOptions("", p2p.NetworkByteEsmeralda).(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClientWithOptions(...) = %T, want *p2pNodeClient", NewP2PClientWithOptions("", p2p.NetworkByteEsmeralda))
	}
	client.probes = fake

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetInfo(ctx, "127.0.0.1:18189"); err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	if fake.lastChainMetadataOpts.NetworkByte != p2p.NetworkByteEsmeralda {
		t.Errorf("lastChainMetadataOpts.NetworkByte = %v, want %v", fake.lastChainMetadataOpts.NetworkByte, p2p.NetworkByteEsmeralda)
	}
	if fake.lastIdentityOpts.NetworkByte != p2p.NetworkByteEsmeralda {
		t.Errorf("lastIdentityOpts.NetworkByte = %v, want %v", fake.lastIdentityOpts.NetworkByte, p2p.NetworkByteEsmeralda)
	}
}

// TestP2PClientGetPeersPassesThroughNetworkByte mirrors
// TestP2PClientGetInfoPassesThroughNetworkByte for GetPeers/
// probeGetPeers.
func TestP2PClientGetPeersPassesThroughNetworkByte(t *testing.T) {
	fake := &fakeP2PProbeFuncs{}
	client, ok := NewP2PClientWithOptions("", p2p.NetworkByteEsmeralda).(*p2pNodeClient)
	if !ok {
		t.Fatalf("NewP2PClientWithOptions(...) = %T, want *p2pNodeClient", NewP2PClientWithOptions("", p2p.NetworkByteEsmeralda))
	}
	client.probes = fake

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.GetPeers(ctx, "127.0.0.1:18189"); err != nil {
		t.Fatalf("GetPeers: %v", err)
	}

	if fake.lastGetPeersOpts.NetworkByte != p2p.NetworkByteEsmeralda {
		t.Errorf("lastGetPeersOpts.NetworkByte = %v, want %v", fake.lastGetPeersOpts.NetworkByte, p2p.NetworkByteEsmeralda)
	}
}
