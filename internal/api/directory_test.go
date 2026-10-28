package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// directoryResponseForTest mirrors directory.go's unexported
// directoryResponse JSON shape -- decoding into a local test type
// (rather than importing the unexported type, following this
// package's existing statsResponseForTest/listNodesResponse-decoding
// convention elsewhere in this file) so these tests exercise the real
// HTTP JSON contract, not Go-internal struct identity.
type directoryResponseForTest struct {
	Nodes   []map[string]json.RawMessage `json:"nodes"`
	Total   int                          `json:"total"`
	Limit   int                          `json:"limit"`
	Offset  int                          `json:"offset"`
	HasMore bool                         `json:"has_more"`
}

// doGetDirectory issues GET /v1/directory?<query> against baseURL
// (an httptest.Server's URL field) and returns the decoded body,
// failing the test on any transport/decode error or non-200 status.
// query may be empty.
func doGetDirectory(t *testing.T, baseURL, query string) directoryResponseForTest {
	t.Helper()
	url := baseURL + "/v1/directory"
	if query != "" {
		url += "?" + query
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, body)
	}
	var got directoryResponseForTest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// rawString decodes a json.RawMessage field expected to be a JSON
// string, failing the test if it isn't present/decodable.
func rawString(t *testing.T, entry map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, ok := entry[key]
	if !ok {
		t.Fatalf("entry missing key %q: %+v", key, entry)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("key %q is not a JSON string: %v", key, err)
	}
	return s
}

// TestDirectoryClassificationKeysOffOwnerTagNotDiscoverySource is the
// single most important classification test BRIEF.md calls out by
// name: a discovery_source=p2p_discovered node with an owner tag added
// on top must classify as "attributed" -- NOT "anonymous" -- because
// the attributed/anonymous split keys off collector.HasOwnerTag, never
// off storage.DiscoverySource. A genuinely untagged p2p_discovered node
// must classify as "anonymous".
func TestDirectoryClassificationKeysOffOwnerTagNotDiscoverySource(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// The exact real-world pattern Alex described: p2p_discovered PLUS
	// an owner tag added later. Must be "attributed".
	p2pWithOwner, err := store.UpsertDiscoveredNode(ctx, "203.0.113.40:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Jagtech"}, nil)
	if err != nil {
		t.Fatalf("upsert p2p+owner node: %v", err)
	}

	// A genuinely anonymous p2p_discovered node with no owner tag at
	// all -- must be "anonymous".
	p2pNoOwner, err := store.UpsertDiscoveredNode(ctx, "203.0.113.41:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert p2p-no-owner node: %v", err)
	}

	// A registry_submitted node, opted in, but this must NOT be
	// what drives classification either -- with no owner tag it must
	// still classify anonymous despite DiscoverySource being
	// "registry_submitted".
	registryNoOwner, err := store.UpsertDiscoveredNode(ctx, "203.0.113.42:18189", storage.DiscoverySourceRegistry, nil, nil)
	if err != nil {
		t.Fatalf("upsert registry-no-owner node: %v", err)
	}

	got := doGetDirectory(t, srv.URL, "")
	if len(got.Nodes) != 3 {
		t.Fatalf("len(got.Nodes) = %d, want 3", len(got.Nodes))
	}

	byID := make(map[string]map[string]json.RawMessage, len(got.Nodes))
	for _, n := range got.Nodes {
		byID[rawString(t, n, "node_id")] = n
	}

	entry, ok := byID[p2pWithOwner.ID.String()]
	if !ok {
		t.Fatalf("p2p+owner node missing from response")
	}
	if class := rawString(t, entry, "class"); class != "attributed" {
		t.Errorf("p2p_discovered node with owner tag: class = %q, want %q (must key off owner tag, not discovery_source)", class, "attributed")
	}
	if owner := rawString(t, entry, "owner"); owner != "Jagtech" {
		t.Errorf("p2p+owner node: owner = %q, want %q", owner, "Jagtech")
	}

	entry, ok = byID[p2pNoOwner.ID.String()]
	if !ok {
		t.Fatalf("p2p-no-owner node missing from response")
	}
	if class := rawString(t, entry, "class"); class != "anonymous" {
		t.Errorf("p2p_discovered node with no owner tag: class = %q, want %q", class, "anonymous")
	}
	if _, hasOwner := entry["owner"]; hasOwner {
		t.Errorf("anonymous entry unexpectedly has an %q key: %+v", "owner", entry)
	}

	entry, ok = byID[registryNoOwner.ID.String()]
	if !ok {
		t.Fatalf("registry-no-owner node missing from response")
	}
	if class := rawString(t, entry, "class"); class != "anonymous" {
		t.Errorf("registry_submitted node with no owner tag: class = %q, want %q (discovery_source must not drive classification)", class, "anonymous")
	}
}

// TestDirectoryOwnerFilter covers `?owner=` narrowing the attributed
// set to exactly one owner, excluding both other-owner attributed nodes
// and the entire anonymous population.
func TestDirectoryOwnerFilter(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	alice, err := store.UpsertDiscoveredNode(ctx, "203.0.113.50:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Alice"}, nil)
	if err != nil {
		t.Fatalf("upsert alice: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.51:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Bob"}, nil); err != nil {
		t.Fatalf("upsert bob: %v", err)
	}
	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.52:18189", storage.DiscoverySourceP2P, nil, nil); err != nil {
		t.Fatalf("upsert anonymous: %v", err)
	}

	got := doGetDirectory(t, srv.URL, "owner=Alice")
	if len(got.Nodes) != 1 || got.Total != 1 {
		t.Fatalf("got = %+v, want exactly 1 node (owner=Alice)", got)
	}
	if id := rawString(t, got.Nodes[0], "node_id"); id != alice.ID.String() {
		t.Errorf("node_id = %q, want %q", id, alice.ID.String())
	}
	if class := rawString(t, got.Nodes[0], "class"); class != "attributed" {
		t.Errorf("class = %q, want %q", class, "attributed")
	}
}

// TestDirectoryClassFilter covers `?class=attributed` and
// `?class=anonymous` each restricting the response to just that one
// population.
func TestDirectoryClassFilter(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	attributed, err := store.UpsertDiscoveredNode(ctx, "203.0.113.60:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Carol"}, nil)
	if err != nil {
		t.Fatalf("upsert attributed: %v", err)
	}
	anonymous, err := store.UpsertDiscoveredNode(ctx, "203.0.113.61:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert anonymous: %v", err)
	}

	gotAttributed := doGetDirectory(t, srv.URL, "class=attributed")
	if len(gotAttributed.Nodes) != 1 {
		t.Fatalf("class=attributed: len(Nodes) = %d, want 1", len(gotAttributed.Nodes))
	}
	if id := rawString(t, gotAttributed.Nodes[0], "node_id"); id != attributed.ID.String() {
		t.Errorf("class=attributed: node_id = %q, want %q", id, attributed.ID.String())
	}

	gotAnonymous := doGetDirectory(t, srv.URL, "class=anonymous")
	if len(gotAnonymous.Nodes) != 1 {
		t.Fatalf("class=anonymous: len(Nodes) = %d, want 1", len(gotAnonymous.Nodes))
	}
	if id := rawString(t, gotAnonymous.Nodes[0], "node_id"); id != anonymous.ID.String() {
		t.Errorf("class=anonymous: node_id = %q, want %q", id, anonymous.ID.String())
	}

	gotBoth := doGetDirectory(t, srv.URL, "")
	if len(gotBoth.Nodes) != 2 {
		t.Fatalf("no class filter: len(Nodes) = %d, want 2 (both populations)", len(gotBoth.Nodes))
	}
}

// TestDirectoryPagination covers `?limit=`/`?offset=` applying real
// pagination over the classified/filtered population, with Total/
// HasMore reflecting the full matching count independent of page size
// -- same semantics as GET /nodes' handleListNodes.
func TestDirectoryPagination(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	// Addresses named so ListNodes' ORDER BY address gives a
	// deterministic n1..n5 ordering.
	for i := 1; i <= 5; i++ {
		addr := fmt.Sprintf("dir-page-n%d:1", i)
		if _, err := store.UpsertDiscoveredNode(ctx, addr, storage.DiscoverySourceP2P, nil, nil); err != nil {
			t.Fatalf("upsert %s: %v", addr, err)
		}
	}

	firstPage := doGetDirectory(t, srv.URL, "limit=2&offset=0")
	if len(firstPage.Nodes) != 2 {
		t.Fatalf("firstPage: len(Nodes) = %d, want 2", len(firstPage.Nodes))
	}
	if firstPage.Total != 5 {
		t.Errorf("firstPage.Total = %d, want 5", firstPage.Total)
	}
	if !firstPage.HasMore {
		t.Errorf("firstPage.HasMore = false, want true (2 of 5 returned)")
	}

	lastPage := doGetDirectory(t, srv.URL, "limit=2&offset=4")
	if len(lastPage.Nodes) != 1 {
		t.Fatalf("lastPage: len(Nodes) = %d, want 1 (5 total, offset 4)", len(lastPage.Nodes))
	}
	if lastPage.Total != 5 {
		t.Errorf("lastPage.Total = %d, want 5", lastPage.Total)
	}
	if lastPage.HasMore {
		t.Errorf("lastPage.HasMore = true, want false (last page)")
	}
}

// TestDirectoryAnonymousNeverExposesLatLon is the required privacy-
// boundary test: an anonymous node with a real resolvable IPv4 AND a
// populated geoip_cache entry must still NEVER have a "latitude"/
// "longitude" JSON key anywhere in its response entry -- checked via
// key ABSENCE (map[string]json.RawMessage), not a zero-value check,
// since omitempty + a genuinely-zero real coordinate would be
// indistinguishable from an omitted field if only checked against 0.0.
func TestDirectoryAnonymousNeverExposesLatLon(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	anon, err := store.UpsertDiscoveredNode(ctx, "203.0.113.70:18189", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert anonymous node: %v", err)
	}
	// A real, non-zero, resolvable coordinate -- if this handler ever
	// regressed to including lat/lon for anonymous entries, this
	// coordinate is what would leak.
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.70", Latitude: 51.5074, Longitude: -0.1278, City: "London", Country: "United Kingdom",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed geoip cache: %v", err)
	}

	got := doGetDirectory(t, srv.URL, "class=anonymous")
	if len(got.Nodes) != 1 {
		t.Fatalf("len(got.Nodes) = %d, want 1", len(got.Nodes))
	}
	entry := got.Nodes[0]
	if id := rawString(t, entry, "node_id"); id != anon.ID.String() {
		t.Fatalf("node_id = %q, want %q", id, anon.ID.String())
	}

	// Top-level: no latitude/longitude key at all.
	if _, ok := entry["latitude"]; ok {
		t.Errorf("anonymous entry has a top-level %q key, want absent entirely: %+v", "latitude", entry)
	}
	if _, ok := entry["longitude"]; ok {
		t.Errorf("anonymous entry has a top-level %q key, want absent entirely: %+v", "longitude", entry)
	}
	// geo_precise must never be set on an anonymous entry either.
	if _, ok := entry["geo_precise"]; ok {
		t.Errorf("anonymous entry unexpectedly has a %q key: %+v", "geo_precise", entry)
	}

	// The coarse city/country projection must still be present (the
	// whole point: TariTalk still gets a coarse location).
	coarseRaw, ok := entry["geo_coarse"]
	if !ok {
		t.Fatalf("anonymous entry missing %q entirely -- coarse geo must still be resolved server-side", "geo_coarse")
	}
	var coarse map[string]json.RawMessage
	if err := json.Unmarshal(coarseRaw, &coarse); err != nil {
		t.Fatalf("decode geo_coarse: %v", err)
	}
	// Defensive: even nested inside geo_coarse, latitude/longitude must
	// never appear (structurally guaranteed by GeoCoarse's Go type
	// having no such fields, but asserted here at the JSON level too).
	if _, ok := coarse["latitude"]; ok {
		t.Errorf("geo_coarse unexpectedly has a %q key: %+v", "latitude", coarse)
	}
	if _, ok := coarse["longitude"]; ok {
		t.Errorf("geo_coarse unexpectedly has a %q key: %+v", "longitude", coarse)
	}
	if city := rawString(t, coarse, "city"); city != "London" {
		t.Errorf("geo_coarse.city = %q, want %q", city, "London")
	}
	if country := rawString(t, coarse, "country"); country != "United Kingdom" {
		t.Errorf("geo_coarse.country = %q, want %q", country, "United Kingdom")
	}
}

// TestDirectoryAttributedExposesPreciseLatLon is the mirror-image
// sanity check of the privacy-boundary test above: an attributed node
// with a resolvable IPv4 and a geoip_cache entry DOES get full-
// precision lat/lon (nested under geo_precise), the same population
// GET /nodes/map already exposes this for today.
func TestDirectoryAttributedExposesPreciseLatLon(t *testing.T) {
	srv, store := newTestServer(t, nil)
	ctx := context.Background()

	attributed, err := store.UpsertDiscoveredNode(ctx, "203.0.113.80:18189", storage.DiscoverySourceP2P,
		map[string]any{"owner": "Dave"}, nil)
	if err != nil {
		t.Fatalf("upsert attributed node: %v", err)
	}
	if err := store.UpsertGeoIPCache(ctx, []storage.GeoIPEntry{{
		IP: "203.0.113.80", Latitude: 48.8566, Longitude: 2.3522, City: "Paris", Country: "France",
		LookedUpAt: time.Now(),
	}}); err != nil {
		t.Fatalf("seed geoip cache: %v", err)
	}

	got := doGetDirectory(t, srv.URL, "class=attributed")
	if len(got.Nodes) != 1 {
		t.Fatalf("len(got.Nodes) = %d, want 1", len(got.Nodes))
	}
	entry := got.Nodes[0]
	if id := rawString(t, entry, "node_id"); id != attributed.ID.String() {
		t.Fatalf("node_id = %q, want %q", id, attributed.ID.String())
	}
	if _, ok := entry["geo_coarse"]; ok {
		t.Errorf("attributed entry unexpectedly has a %q key: %+v", "geo_coarse", entry)
	}
	preciseRaw, ok := entry["geo_precise"]
	if !ok {
		t.Fatalf("attributed entry missing %q entirely", "geo_precise")
	}
	var precise struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		City      string  `json:"city"`
		Country   string  `json:"country"`
	}
	if err := json.Unmarshal(preciseRaw, &precise); err != nil {
		t.Fatalf("decode geo_precise: %v", err)
	}
	if precise.Latitude != 48.8566 || precise.Longitude != 2.3522 {
		t.Errorf("geo_precise lat/lon = (%v, %v), want (48.8566, 2.3522)", precise.Latitude, precise.Longitude)
	}
	if precise.City != "Paris" || precise.Country != "France" {
		t.Errorf("geo_precise city/country = (%q, %q), want (%q, %q)", precise.City, precise.Country, "Paris", "France")
	}
}
