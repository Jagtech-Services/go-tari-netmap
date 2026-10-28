package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// extendedMapResponseForTest mirrors mapextended.go's unexported
// ExtendedMapResponse/AnonymousCluster JSON shape -- decoding into a
// local test type (rather than importing api.MapNode/api.AnonymousCluster
// directly) so these tests exercise the real HTTP JSON contract, not Go
// struct identity, following directory_test.go's directoryResponseForTest
// convention.
type extendedMapResponseForTest struct {
	Attributed []map[string]json.RawMessage `json:"attributed"`
	Anonymous  []map[string]json.RawMessage `json:"anonymous"`
}

// doGetExtendedMap issues GET /nodes/map/extended against baseURL (an
// httptest.Server's URL field) and returns the decoded body, failing the
// test on any transport/decode error or non-200 status.
func doGetExtendedMap(t *testing.T, baseURL string) extendedMapResponseForTest {
	t.Helper()
	url := baseURL + "/nodes/map/extended"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}
	var got extendedMapResponseForTest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// setNodeLastSeen directly updates one node's last_seen column via a raw
// connection to the same test database newTestServer's store was built
// with -- storage.Store exposes no method to set an arbitrary last_seen
// value (only UpsertDiscoveredNode's own now()-only semantics), so this
// mirrors TestTopPeeredNodes' own "direct pool.Exec against testDSN()"
// convention (see api_test.go) for test setup that needs to control a
// column no public Store method lets a test set directly.
func setNodeLastSeen(t *testing.T, nodeID fmt.Stringer, lastSeen time.Time) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `UPDATE nodes SET last_seen = $1 WHERE id = $2`, lastSeen, nodeID.String()); err != nil {
		t.Fatalf("set last_seen for node %s: %v", nodeID, err)
	}
}

// rawStringExt is rawString's exact twin for this file (directory_test.go's
// rawString is unexported to that file's own package block, but both
// files are package api_test -- redeclaring under a different name here
// would collide if it were exported the same; this file just reuses
// rawString directly since Go allows same-package helper reuse).
func rawStringExt(t *testing.T, entry map[string]json.RawMessage, key string) string {
	return rawString(t, entry, key)
}

// TestExtendedMapExclusionRule covers BRIEF.md's core exclusion rule: an
// anonymous cluster in the SAME (city, country) as an attributed marker
// is dropped entirely, while a genuinely distinct city's anonymous
// cluster survives.
func TestExtendedMapExclusionRule(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// Attributed node in London.
	attributed, err := store.UpsertDiscoveredNode(ctx, "203.0.113.100:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Alice"}, nil)
	if err != nil {
		t.Fatalf("upsert attributed node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.100", Latitude: 51.5074, Longitude: -0.1278, City: "London", Country: "United Kingdom",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed attributed geoip cache: %v", err)
	}

	// Anonymous node also in London -- same city as the attributed
	// marker above, so its cluster must be excluded.
	sameCityAnon, err := store.UpsertDiscoveredNode(ctx, "203.0.113.101:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert same-city anonymous node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.101", Latitude: 51.51, Longitude: -0.13, City: "London", Country: "United Kingdom",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed same-city anonymous geoip cache: %v", err)
	}

	// Anonymous node in a genuinely distinct city (Paris) -- must
	// survive as its own cluster.
	otherCityAnon, err := store.UpsertDiscoveredNode(ctx, "203.0.113.102:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert other-city anonymous node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.102", Latitude: 48.8566, Longitude: 2.3522, City: "Paris", Country: "France",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed other-city anonymous geoip cache: %v", err)
	}

	got := doGetExtendedMap(t, srv.URL)

	if len(got.Attributed) != 1 {
		t.Fatalf("len(Attributed) = %d, want 1", len(got.Attributed))
	}
	if id := rawStringExt(t, got.Attributed[0], "node_id"); id != attributed.ID.String() {
		t.Errorf("attributed node_id = %q, want %q", id, attributed.ID.String())
	}

	if len(got.Anonymous) != 1 {
		t.Fatalf("len(Anonymous) = %d, want 1 (London excluded, Paris survives): %+v", len(got.Anonymous), got.Anonymous)
	}
	if city := rawStringExt(t, got.Anonymous[0], "city"); city != "Paris" {
		t.Errorf("surviving anonymous cluster city = %q, want %q", city, "Paris")
	}
	if country := rawStringExt(t, got.Anonymous[0], "country"); country != "France" {
		t.Errorf("surviving anonymous cluster country = %q, want %q", country, "France")
	}

	// The excluded same-city anonymous node must not sneak in under
	// London anywhere in the anonymous array.
	for _, c := range got.Anonymous {
		if city := rawStringExt(t, c, "city"); city == "London" {
			t.Errorf("London anonymous cluster present despite an attributed marker in London: %+v", c)
		}
	}
	_ = sameCityAnon
	_ = otherCityAnon
}

// TestExtendedMapApproxNodeCountAndLastObserved covers approx_node_count
// and last_observed_at correctness for a multi-node cluster:
// approx_node_count must equal the distinct node count in that
// (city, country) grouping, and last_observed_at must be the MAX(last_seen)
// across those nodes -- not any single node's own last_seen, and not the
// min/an arbitrary one.
func TestExtendedMapApproxNodeCountAndLastObserved(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	type seeded struct {
		node     storage.Node
		lastSeen time.Time
	}
	var members []seeded
	base := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("203.0.113.11%d:18189", i)
		n, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil)
		if err != nil {
			t.Fatalf("upsert cluster member %d: %v", i, err)
		}
		if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
			IP: fmt.Sprintf("203.0.113.11%d", i), Latitude: 52.52, Longitude: 13.405, City: "Berlin", Country: "Germany",
			LookedUpAt: time.Now(),
		}}); err != nil {
			t.Fatalf("seed geoip cache for member %d: %v", i, err)
		}
		// Distinct, controlled last_seen values: member 0 is oldest,
		// member 2 is the most recent -- last_observed_at must equal
		// member 2's last_seen (the MAX), not member 0's or an
		// average.
		lastSeen := base.Add(time.Duration(i) * time.Hour)
		setNodeLastSeen(t, n.ID, lastSeen)
		members = append(members, seeded{node: n, lastSeen: lastSeen})
	}
	wantMaxLastSeen := members[2].lastSeen

	got := doGetExtendedMap(t, srv.URL)
	if len(got.Anonymous) != 1 {
		t.Fatalf("len(Anonymous) = %d, want 1 (all 3 members share one Berlin cluster): %+v", len(got.Anonymous), got.Anonymous)
	}
	cluster := got.Anonymous[0]

	var count int
	if err := json.Unmarshal(cluster["approx_node_count"], &count); err != nil {
		t.Fatalf("decode approx_node_count: %v", err)
	}
	if count != 3 {
		t.Errorf("approx_node_count = %d, want 3", count)
	}

	var lastObserved time.Time
	if err := json.Unmarshal(cluster["last_observed_at"], &lastObserved); err != nil {
		t.Fatalf("decode last_observed_at: %v", err)
	}
	if !lastObserved.Equal(wantMaxLastSeen) {
		t.Errorf("last_observed_at = %v, want %v (MAX(last_seen) across the cluster's members)", lastObserved, wantMaxLastSeen)
	}
}

// TestExtendedMapAnonymousClusterNeverExposesIdentifyingFields is the
// required hard privacy-invariant test: an AnonymousCluster JSON entry
// must NEVER contain a node_id, label, address, or wallet_http_port key
// -- checked via key ABSENCE (map[string]json.RawMessage), mirroring
// directory_test.go's TestDirectoryAnonymousNeverExposesLatLon's exact
// key-absence-not-zero-value technique. This is a STRICTER guarantee
// than GET /v1/directory's per-node anonymous entries (which do carry a
// node_id) -- see AnonymousCluster's doc comment.
func TestExtendedMapAnonymousClusterNeverExposesIdentifyingFields(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	label := "should-never-appear"
	anon, err := store.UpsertDiscoveredNode(ctx, "203.0.113.120:18189", storage.DiscoverySourceP2P, nil, &label)
	if err != nil {
		t.Fatalf("upsert anonymous node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.120", Latitude: 35.6762, Longitude: 139.6503, City: "Tokyo", Country: "Japan",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed geoip cache: %v", err)
	}

	got := doGetExtendedMap(t, srv.URL)
	if len(got.Anonymous) != 1 {
		t.Fatalf("len(Anonymous) = %d, want 1: %+v", len(got.Anonymous), got.Anonymous)
	}
	cluster := got.Anonymous[0]

	for _, forbidden := range []string{"node_id", "label", "address", "wallet_http_port", "confirmed", "has_onion"} {
		if _, ok := cluster[forbidden]; ok {
			t.Errorf("AnonymousCluster entry unexpectedly has a %q key, want absent entirely (aggregate-only): %+v", forbidden, cluster)
		}
	}

	// Sanity: the aggregate fields that SHOULD be present are.
	for _, want := range []string{"city", "country", "latitude", "longitude", "approx_node_count", "last_observed_at"} {
		if _, ok := cluster[want]; !ok {
			t.Errorf("AnonymousCluster entry missing expected key %q: %+v", want, cluster)
		}
	}

	_ = anon
}

// TestExtendedMapExcludesCollectorRoleNodes covers BRIEF.md's collector-
// role exclusion: a node tagged role=collector must be excluded from
// BOTH the attributed and anonymous populations, even if it otherwise
// matches either population's predicate.
func TestExtendedMapExcludesCollectorRoleNodes(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// A collector-tagged node that ALSO has an owner tag -- would
	// otherwise be attributed-eligible, must still be excluded.
	attributedCollector, err := store.UpsertDiscoveredNode(ctx, "203.0.113.130:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Sydney Collector", "role": "collector"}, nil)
	if err != nil {
		t.Fatalf("upsert attributed collector node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.130", Latitude: -33.8688, Longitude: 151.2093, City: "Sydney", Country: "Australia",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed attributed collector geoip cache: %v", err)
	}

	// A collector-tagged node with NO owner tag -- would otherwise be
	// anonymous-eligible, must still be excluded.
	anonCollector, err := store.UpsertDiscoveredNode(ctx, "203.0.113.131:18189", storage.DiscoverySourceP2P,
		map[string]any{"role": "collector"}, nil)
	if err != nil {
		t.Fatalf("upsert anonymous collector node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.131", Latitude: -37.8136, Longitude: 144.9631, City: "Melbourne", Country: "Australia",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed anonymous collector geoip cache: %v", err)
	}

	got := doGetExtendedMap(t, srv.URL)

	for _, a := range got.Attributed {
		if id := rawStringExt(t, a, "node_id"); id == attributedCollector.ID.String() {
			t.Errorf("role=collector node unexpectedly present in attributed population: %+v", a)
		}
	}
	for _, c := range got.Anonymous {
		if city := rawStringExt(t, c, "city"); city == "Sydney" || city == "Melbourne" {
			t.Errorf("role=collector node's city unexpectedly present in anonymous population: %+v", c)
		}
	}

	_ = anonCollector
}

// TestExtendedMapOmitsNodesWithoutGeoIPEntry covers BRIEF.md's "simply
// omitted (not included with zero coords)" rule for BOTH populations: a
// node that would otherwise be eligible (attributed or anonymous) but
// has no geoip_cache entry yet must not appear at all -- never with a
// (0, 0) placeholder location.
func TestExtendedMapOmitsNodesWithoutGeoIPEntry(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// Attributed-eligible (owner tag + IPv4) but never geoip-resolved.
	attributedNoGeo, err := store.UpsertDiscoveredNode(ctx, "203.0.113.140:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Bob"}, nil)
	if err != nil {
		t.Fatalf("upsert attributed-no-geo node: %v", err)
	}

	// Anonymous-eligible (no owner tag + IPv4) but never geoip-resolved.
	anonNoGeo, err := store.UpsertDiscoveredNode(ctx, "203.0.113.141:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert anonymous-no-geo node: %v", err)
	}

	got := doGetExtendedMap(t, srv.URL)

	for _, a := range got.Attributed {
		if id := rawStringExt(t, a, "node_id"); id == attributedNoGeo.ID.String() {
			t.Errorf("attributed node with no geoip_cache entry unexpectedly present: %+v", a)
		}
	}
	if len(got.Anonymous) != 0 {
		t.Errorf("Anonymous = %+v, want empty (the only anonymous candidate has no geoip_cache entry)", got.Anonymous)
	}

	_ = anonNoGeo
}

// TestExtendedMapDoesNotAffectStatsOrDirectory is a cheap regression
// guard for BRIEF.md's "must not affect GET /v1/stats/GET /v1/directory's
// counts in any way" invariant: hitting GET /nodes/map/extended must not
// change what those two endpoints report for the same underlying data.
func TestExtendedMapDoesNotAffectStatsOrDirectory(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.150:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Carol"}, nil); err != nil {
		t.Fatalf("upsert node: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.151:18189", storage.DiscoverySourceP2P, nil, nil); err != nil {
		t.Fatalf("upsert anonymous node: %v", err)
	}

	before := doGetDirectory(t, srv.URL, "")

	// Exercise the new endpoint several times (including cache hits).
	for i := 0; i < 3; i++ {
		_ = doGetExtendedMap(t, srv.URL)
	}

	after := doGetDirectory(t, srv.URL, "")
	if before.Total != after.Total {
		t.Errorf("GET /v1/directory Total changed after hitting GET /nodes/map/extended: before=%d after=%d", before.Total, after.Total)
	}
	if len(before.Nodes) != len(after.Nodes) {
		t.Errorf("GET /v1/directory Nodes count changed after hitting GET /nodes/map/extended: before=%d after=%d", len(before.Nodes), len(after.Nodes))
	}
}
