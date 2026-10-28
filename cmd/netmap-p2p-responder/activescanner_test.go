package main

import (
	"testing"

	"github.com/Jagtech-Services/go-tari-netmap/internal/remotestore"
)

func TestSelfAdvertisedAddressesIP4TCP(t *testing.T) {
	got, err := selfAdvertisedAddresses("/ip4/203.0.113.7/tcp/18189", "")
	if err != nil {
		t.Fatalf("selfAdvertisedAddresses: %v", err)
	}
	if len(got) != 1 || got[0] != "203.0.113.7:18189" {
		t.Fatalf("got %v, want [203.0.113.7:18189]", got)
	}
}

func TestSelfAdvertisedAddressesOnion3(t *testing.T) {
	const onion = "wyow2dp6w2ff4u2kebklkmbzwlixyhjtza5bf3pt3oxnps5hcjn76iyd"
	got, err := selfAdvertisedAddresses("", "/onion3/"+onion+":18141")
	if err != nil {
		t.Fatalf("selfAdvertisedAddresses: %v", err)
	}
	if len(got) != 1 || got[0] != onion+".onion:18141" {
		t.Fatalf("got %v, want [%s.onion:18141]", got, onion)
	}
}

func TestSelfAdvertisedAddressesBoth(t *testing.T) {
	const onion = "wyow2dp6w2ff4u2kebklkmbzwlixyhjtza5bf3pt3oxnps5hcjn76iyd"
	got, err := selfAdvertisedAddresses("/ip4/203.0.113.7/tcp/18189", "/onion3/"+onion+":18141")
	if err != nil {
		t.Fatalf("selfAdvertisedAddresses: %v", err)
	}
	want := []string{"203.0.113.7:18189", onion + ".onion:18141"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSelfAdvertisedAddressesNeitherSet(t *testing.T) {
	got, err := selfAdvertisedAddresses("", "")
	if err != nil {
		t.Fatalf("selfAdvertisedAddresses: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestSelfAdvertisedAddressesMalformed(t *testing.T) {
	cases := []struct {
		name          string
		publicTCPAddr string
		onion3Addr    string
	}{
		{"bad ip4 prefix", "/ip6/::1/tcp/1", ""},
		{"missing tcp segment", "/ip4/1.2.3.4/udp/1", ""},
		{"invalid ip", "/ip4/not-an-ip/tcp/1", ""},
		{"bad onion prefix", "", "/onion2/abc:1"},
		{"onion missing port", "", "/onion3/abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := selfAdvertisedAddresses(tc.publicTCPAddr, tc.onion3Addr); err == nil {
				t.Errorf("expected an error for %+v", tc)
			}
		})
	}
}

func TestParseSeedNodes(t *testing.T) {
	got := parseSeedNodes(" 1.2.3.4:1 , , 5.6.7.8:2,")
	want := []string{"1.2.3.4:1", "5.6.7.8:2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if parseSeedNodes("") != nil {
		t.Error("expected nil for empty input")
	}
}

func TestParseOwnedGRPCAddresses(t *testing.T) {
	got := parseOwnedGRPCAddresses("1.2.3.4:18189=1.2.3.4:18102, malformed , 5.6.7.8:18189=5.6.7.8:18102")
	want := map[string]string{"1.2.3.4:18189": "1.2.3.4:18102", "5.6.7.8:18189": "5.6.7.8:18102"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseSocksProxyAddrsPluralPreferred(t *testing.T) {
	got := parseSocksProxyAddrs("127.0.0.1:9100,127.0.0.1:9101", "127.0.0.1:9200")
	want := []string{"127.0.0.1:9100", "127.0.0.1:9101"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseSocksProxyAddrsSingularFallback(t *testing.T) {
	got := parseSocksProxyAddrs("", "127.0.0.1:9200")
	if len(got) != 1 || got[0] != "127.0.0.1:9200" {
		t.Fatalf("got %v, want [127.0.0.1:9200]", got)
	}
}

func TestParseSocksProxyAddrsBothEmpty(t *testing.T) {
	if got := parseSocksProxyAddrs("", ""); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// TestNewActiveScannerWiresStorage is a smoke test asserting newActiveScanner returns a
// Collector with Storage/GRPCClient/P2PClient all non-nil and wired against the given store --
// full behavioral coverage of the collector loops themselves lives in internal/collector's own
// test suite; this only proves the wiring in this binary is present.
func TestNewActiveScannerWiresStorage(t *testing.T) {
	store, err := remotestore.New(remotestore.Config{BaseURL: "http://127.0.0.1:1", APIKey: "k"})
	if err != nil {
		t.Fatalf("remotestore.New: %v", err)
	}
	c := newActiveScanner(store, mustTestResponderMetrics(t))
	if c.Storage == nil {
		t.Error("expected Storage to be wired")
	}
	if c.GRPCClient == nil {
		t.Error("expected GRPCClient to be wired")
	}
	if c.P2PClient == nil {
		t.Error("expected P2PClient to be wired")
	}
	if c.OnPollResult == nil {
		t.Error("expected OnPollResult to be wired (see this repo's readiness-review follow-up, Fix 2 / findings I17/I28 -- the active-scanner role must not go unmetriced)")
	}
}
