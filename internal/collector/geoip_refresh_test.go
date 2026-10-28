package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/Jagtech-Services/go-tari-netmap/internal/geoip"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// TestStaleGeoIPsPolicy exercises staleGeoIPs' pure TTL logic directly —
// no I/O, no Storage, no HTTP client — covering every case from
// BRIEF.md's cache policy: never-cached, fresh success, stale success,
// fresh failure, and stale failure.
func TestStaleGeoIPsPolicy(t *testing.T) {
	now := time.Now()

	cached := map[string]storage.GeoIPEntry{
		"1.1.1.1": {IP: "1.1.1.1", LookedUpAt: now.Add(-1 * time.Hour), LookupFailed: false},                 // fresh success
		"2.2.2.2": {IP: "2.2.2.2", LookedUpAt: now.Add(-(GeoIPSuccessTTL + time.Hour)), LookupFailed: false}, // stale success
		"3.3.3.3": {IP: "3.3.3.3", LookedUpAt: now.Add(-1 * time.Hour), LookupFailed: true},                  // fresh failure
		"4.4.4.4": {IP: "4.4.4.4", LookedUpAt: now.Add(-(GeoIPFailedTTL + time.Hour)), LookupFailed: true},   // stale failure
	}

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"} // 5.5.5.5: never cached

	got := staleGeoIPs(ips, cached, now)

	want := map[string]bool{"2.2.2.2": true, "4.4.4.4": true, "5.5.5.5": true}
	gotSet := make(map[string]bool, len(got))
	for _, ip := range got {
		gotSet[ip] = true
	}

	for ip := range want {
		if !gotSet[ip] {
			t.Errorf("staleGeoIPs: expected %s to be reported stale, wasn't", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "3.3.3.3"} {
		if gotSet[ip] {
			t.Errorf("staleGeoIPs: expected %s to still be fresh, was reported stale", ip)
		}
	}
	if len(got) != len(want) {
		t.Errorf("staleGeoIPs: got %v, want exactly %v", got, want)
	}
}

// TestStaleGeoIPsBoundary checks the >= boundary explicitly: an entry
// exactly at its TTL is due (not "one instant away from due").
func TestStaleGeoIPsBoundary(t *testing.T) {
	now := time.Now()
	cached := map[string]storage.GeoIPEntry{
		"1.1.1.1": {IP: "1.1.1.1", LookedUpAt: now.Add(-GeoIPSuccessTTL), LookupFailed: false},
	}
	got := staleGeoIPs([]string{"1.1.1.1"}, cached, now)
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("staleGeoIPs at exact TTL boundary = %v, want [1.1.1.1]", got)
	}
}

// fakeGeoIPDoer is an in-memory geoip.HTTPDoer fixture: no real network
// access. It answers ip-api.com's batch request/response JSON shape
// generically (it doesn't import internal/geoip's unexported types), so
// it stays decoupled from that package's internals.
type fakeGeoIPDoer struct {
	mu       sync.Mutex
	requests int
	byIP     map[string]struct {
		lat, lon      float64
		city, country string
		fail          bool
	}
}

type geoIPBatchRequestItem struct {
	Query  string `json:"query"`
	Fields string `json:"fields"`
}

type geoIPBatchResponseItem struct {
	Query   string  `json:"query"`
	Status  string  `json:"status"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city"`
	Country string  `json:"country"`
}

// fieldsRequested reports whether field is present in a comma-separated
// "fields" request string, matching how ip-api.com itself parses that
// parameter -- used by fakeGeoIPDoer to only echo back what the real
// API would for a given request, instead of unconditionally.
func fieldsRequested(fields, field string) bool {
	for _, f := range strings.Split(fields, ",") {
		if f == field {
			return true
		}
	}
	return false
}

func (f *fakeGeoIPDoer) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var items []geoIPBatchRequestItem
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}

	resp := make([]geoIPBatchResponseItem, 0, len(items))
	for _, it := range items {
		fixture, ok := f.byIP[it.Query]
		status := "success"
		if !ok || fixture.fail {
			status = "fail"
		}
		item := geoIPBatchResponseItem{
			Query: it.Query, Status: status,
			Lat: fixture.lat, Lon: fixture.lon,
			City: fixture.city, Country: fixture.country,
		}
		// Mirror ip-api.com's real batch behavior: a response item
		// only carries a "query" value if "query" was present in that
		// request item's "fields" string -- it is NOT echoed back by
		// default. A fixture that always echoes Query regardless of
		// the requested fields would hide a regression like
		// internal/geoip's requestFields dropping "query", since
		// lookupBatch there keys its result map by Query.
		if !fieldsRequested(it.Fields, "query") {
			item.Query = ""
		}
		resp = append(resp, item)
	}

	respBody, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
		Header:     make(http.Header),
	}, nil
}

// TestRefreshGeoIPReadThroughAndTTL exercises RefreshGeoIP end to end
// against the real test Postgres store (same convention as every other
// test in this file) but a completely fake HTTP client standing in for
// ip-api.com — no real network access anywhere in this test. It covers
// the full read-through contract: an owner-tagged+IPv4 node's address
// gets looked up and cached on the first pass, and a second pass within
// GeoIPSuccessTTL makes zero further HTTP calls (the cache is still
// fresh) — the core "an HTTP GET should never block on an outbound
// geoip call" guarantee this loop exists to provide.
func TestRefreshGeoIPReadThroughAndTTL(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.UpsertDiscoveredNode(ctx, "203.0.113.5:18189", storage.DiscoverySourceRegistry,
		map[string]any{"owner": "Alice"}, nil)
	if err != nil {
		t.Fatalf("seed owner-tagged node: %v", err)
	}

	fake := &fakeGeoIPDoer{byIP: map[string]struct {
		lat, lon      float64
		city, country string
		fail          bool
	}{
		"203.0.113.5": {lat: 51.5, lon: -0.12, city: "London", country: "United Kingdom"},
	}}

	client := &geoip.Client{HTTPClient: fake, Limiter: rate.NewLimiter(rate.Inf, 10)}

	c := New(Config{})
	c.Storage = store
	c.GeoIPClient = client

	if err := c.RefreshGeoIP(ctx); err != nil {
		t.Fatalf("RefreshGeoIP (first pass): %v", err)
	}
	if fake.requests != 1 {
		t.Fatalf("expected exactly 1 HTTP batch call after first RefreshGeoIP, got %d", fake.requests)
	}

	cache, err := store.GetGeoIPCache(ctx, []string{"203.0.113.5"})
	if err != nil {
		t.Fatalf("GetGeoIPCache: %v", err)
	}
	entry, ok := cache["203.0.113.5"]
	if !ok {
		t.Fatalf("expected a cached geoip entry for 203.0.113.5")
	}
	if entry.LookupFailed {
		t.Errorf("entry.LookupFailed = true, want false")
	}
	if entry.Latitude != 51.5 || entry.Longitude != -0.12 || entry.City != "London" || entry.Country != "United Kingdom" {
		t.Errorf("unexpected cached entry: %+v", entry)
	}
	if entry.LookedUpAt.IsZero() {
		t.Errorf("expected LookedUpAt to be set")
	}

	// Second pass: the cache entry is still fresh (well within
	// GeoIPSuccessTTL), so RefreshGeoIP must not issue any further HTTP
	// call at all — this is the read-through behavior the /map handler
	// depends on never blocking on a live lookup.
	if err := c.RefreshGeoIP(ctx); err != nil {
		t.Fatalf("RefreshGeoIP (second pass): %v", err)
	}
	if fake.requests != 1 {
		t.Errorf("expected no additional HTTP call for an already-fresh cache entry, total calls = %d", fake.requests)
	}
}

// TestRefreshGeoIPCachesFailedLookup verifies a node whose IP ip-api.com
// itself reports "fail" for still gets a geoip_cache row written
// (LookupFailed: true), per BRIEF.md's "lookup_failed lets a failed
// lookup be cached too" requirement — so a persistently-unresolvable IP
// gets GeoIPFailedTTL's shorter backoff instead of being retried on
// every single refresh tick forever.
func TestRefreshGeoIPCachesFailedLookup(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.UpsertDiscoveredNode(ctx, "198.51.100.9:18189", storage.DiscoverySourceRegistry,
		map[string]any{"owner": "Bob"}, nil)
	if err != nil {
		t.Fatalf("seed owner-tagged node: %v", err)
	}

	// No fixture entry for 198.51.100.9 at all -- fakeGeoIPDoer reports
	// every un-fixtured query as ip-api.com status "fail".
	fake := &fakeGeoIPDoer{byIP: map[string]struct {
		lat, lon      float64
		city, country string
		fail          bool
	}{}}
	client := &geoip.Client{HTTPClient: fake, Limiter: rate.NewLimiter(rate.Inf, 10)}

	c := New(Config{})
	c.Storage = store
	c.GeoIPClient = client

	if err := c.RefreshGeoIP(ctx); err != nil {
		t.Fatalf("RefreshGeoIP: %v", err)
	}

	cache, err := store.GetGeoIPCache(ctx, []string{"198.51.100.9"})
	if err != nil {
		t.Fatalf("GetGeoIPCache: %v", err)
	}
	entry, ok := cache["198.51.100.9"]
	if !ok {
		t.Fatalf("expected a cached (failed) geoip entry for 198.51.100.9")
	}
	if !entry.LookupFailed {
		t.Errorf("entry.LookupFailed = false, want true")
	}
}

// TestRefreshGeoIPNilClientNoop confirms RefreshGeoIP does nothing at
// all -- not even a Storage query -- when GeoIPClient is nil, matching
// GeoIPClient's documented "disables the loop entirely" contract.
func TestRefreshGeoIPNilClientNoop(t *testing.T) {
	c := New(Config{})
	// Storage deliberately left nil too: if RefreshGeoIP tried to touch
	// it before checking GeoIPClient, this would panic.
	if err := c.RefreshGeoIP(context.Background()); err != nil {
		t.Fatalf("RefreshGeoIP with nil GeoIPClient: %v", err)
	}
}

// TestRefreshGeoIPIgnoresNonOwnerNodes confirms a node with no owner tag
// at all AND no recent (last-24h) reachable health check contributes no
// candidate IP -- RefreshGeoIP must never spend an ip-api.com request on
// a node outside BOTH the owner-tagged /map population and the
// anonymous-but-reachable-in-24h population (see
// anonymousReachableIPv4Addresses/BRIEF.md's "expand geoip refresh to
// also cover the anonymous population (bounded)"). This node
// deliberately has zero node_health rows at all, so it's excluded from
// the anonymous population purely on the ReachableSince bound --
// TestAnonymousReachableIPv4AddressesPredicate below covers that
// exclusion directly/unit-style; this test confirms RefreshGeoIP's own
// end-to-end wiring honors it too.
func TestRefreshGeoIPIgnoresNonOwnerNodes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.UpsertDiscoveredNode(ctx, "192.0.2.77:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed non-owner node: %v", err)
	}

	fake := &fakeGeoIPDoer{byIP: map[string]struct {
		lat, lon      float64
		city, country string
		fail          bool
	}{}}
	client := &geoip.Client{HTTPClient: fake, Limiter: rate.NewLimiter(rate.Inf, 10)}

	c := New(Config{})
	c.Storage = store
	c.GeoIPClient = client

	if err := c.RefreshGeoIP(ctx); err != nil {
		t.Fatalf("RefreshGeoIP: %v", err)
	}
	if fake.requests != 0 {
		t.Errorf("expected zero HTTP calls for a non-owner-tagged, never-reachable node, got %d", fake.requests)
	}
}

// TestAnonymousReachableIPv4AddressesPredicate exercises
// anonymousReachableIPv4Addresses' full candidate predicate directly
// (see BRIEF.md's Testing section): a reachable-in-24h, non-owner-tagged
// node's IPv4 is included; an owner-tagged node is excluded even though
// reachable; a non-owner-tagged node with NO recent health check is
// excluded; a role=collector-tagged node is excluded even if otherwise
// eligible (reachable, non-owner-tagged).
func TestAnonymousReachableIPv4AddressesPredicate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Eligible: non-owner-tagged, reachable within 24h.
	eligible, err := store.UpsertDiscoveredNode(ctx, "203.0.113.10:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed eligible node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{
		NodeID: eligible.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC,
	}); err != nil {
		t.Fatalf("record health check for eligible node: %v", err)
	}

	// Excluded: owner-tagged, even though reachable within 24h.
	owned, err := store.UpsertDiscoveredNode(ctx, "203.0.113.11:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Alice"}, nil)
	if err != nil {
		t.Fatalf("seed owner-tagged node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{
		NodeID: owned.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC,
	}); err != nil {
		t.Fatalf("record health check for owner-tagged node: %v", err)
	}

	// Excluded: non-owner-tagged, but no recent (or any) health check at all.
	_, err = store.UpsertDiscoveredNode(ctx, "203.0.113.12:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed never-reachable node: %v", err)
	}

	// Excluded: role=collector-tagged, even though reachable within 24h
	// and not owner-tagged (otherwise fully eligible).
	collector, err := store.UpsertDiscoveredNode(ctx, "203.0.113.13:18189", storage.DiscoverySourceP2P,
		map[string]any{"role": "collector"}, nil)
	if err != nil {
		t.Fatalf("seed role=collector node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{
		NodeID: collector.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC,
	}); err != nil {
		t.Fatalf("record health check for role=collector node: %v", err)
	}

	c := New(Config{})
	c.Storage = store

	ips, err := c.anonymousReachableIPv4Addresses(ctx)
	if err != nil {
		t.Fatalf("anonymousReachableIPv4Addresses: %v", err)
	}

	got := make(map[string]bool, len(ips))
	for _, ip := range ips {
		got[ip] = true
	}

	if !got["203.0.113.10"] {
		t.Errorf("expected 203.0.113.10 (eligible: non-owner, reachable-in-24h) to be included, got %v", ips)
	}
	if got["203.0.113.11"] {
		t.Errorf("expected 203.0.113.11 (owner-tagged) to be excluded, got %v", ips)
	}
	if got["203.0.113.12"] {
		t.Errorf("expected 203.0.113.12 (never reachable) to be excluded, got %v", ips)
	}
	if got["203.0.113.13"] {
		t.Errorf("expected 203.0.113.13 (role=collector) to be excluded, got %v", ips)
	}
	if len(ips) != 1 {
		t.Errorf("anonymousReachableIPv4Addresses = %v, want exactly [203.0.113.10]", ips)
	}
}

// TestRefreshGeoIPPopulatesAnonymousPopulation is the integration-style
// counterpart to TestAnonymousReachableIPv4AddressesPredicate above (see
// BRIEF.md's Testing section): it drives RefreshGeoIP itself, end to
// end, against a reachable-in-24h anonymous (non-owner-tagged) node and
// confirms a geoip_cache row gets written for its IP -- the actual bug
// this whole dispatch exists to fix (GET /nodes/map/extended's
// `anonymous` array was permanently empty because nothing upstream ever
// populated geoip_cache for non-owner-tagged nodes at all).
func TestRefreshGeoIPPopulatesAnonymousPopulation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	anon, err := store.UpsertDiscoveredNode(ctx, "198.51.100.42:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("seed anonymous node: %v", err)
	}
	if err := store.RecordHealthCheck(ctx, storage.HealthCheckInput{
		NodeID: anon.ID, Reachable: true, ProbeSource: storage.ProbeSourceGRPC,
	}); err != nil {
		t.Fatalf("record health check for anonymous node: %v", err)
	}

	fake := &fakeGeoIPDoer{byIP: map[string]struct {
		lat, lon      float64
		city, country string
		fail          bool
	}{
		"198.51.100.42": {lat: 37.77, lon: -122.42, city: "San Francisco", country: "United States"},
	}}
	client := &geoip.Client{HTTPClient: fake, Limiter: rate.NewLimiter(rate.Inf, 10)}

	c := New(Config{})
	c.Storage = store
	c.GeoIPClient = client

	if err := c.RefreshGeoIP(ctx); err != nil {
		t.Fatalf("RefreshGeoIP: %v", err)
	}
	if fake.requests != 1 {
		t.Fatalf("expected exactly 1 HTTP batch call, got %d", fake.requests)
	}

	cache, err := store.GetGeoIPCache(ctx, []string{"198.51.100.42"})
	if err != nil {
		t.Fatalf("GetGeoIPCache: %v", err)
	}
	entry, ok := cache["198.51.100.42"]
	if !ok {
		t.Fatalf("expected a cached geoip entry for 198.51.100.42 (anonymous, reachable-in-24h node)")
	}
	if entry.LookupFailed {
		t.Errorf("entry.LookupFailed = true, want false")
	}
	if entry.City != "San Francisco" || entry.Country != "United States" {
		t.Errorf("unexpected cached entry: %+v", entry)
	}
}
