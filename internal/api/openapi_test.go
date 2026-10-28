package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Jagtech-Services/go-tari-netmap/internal/docs"
)

// ---- GET /spec (served as GET /api/spec once cmd/netmap/main.go's http.StripPrefix
// mount is applied in production) ----

func TestHandleAPISpec_YAML(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/spec")
	if err != nil {
		t.Fatalf("GET /spec: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/yaml; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", got, "application/yaml; charset=utf-8")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("body is empty, want non-empty YAML spec")
	}

	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid YAML: %v; body=%s", err, body)
	}
	if doc["openapi"] == nil {
		t.Errorf("parsed YAML missing top-level %q key, got: %+v", "openapi", doc)
	}
	if _, ok := doc["paths"].(map[string]any); !ok {
		t.Errorf("parsed YAML missing top-level %q map, got: %+v", "paths", doc["paths"])
	}
}

func TestHandleAPISpec_JSONFormat(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/spec?format=json")
	if err != nil {
		t.Fatalf("GET /spec?format=json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}

	jsonBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var jsonDoc map[string]any
	if err := json.Unmarshal(jsonBody, &jsonDoc); err != nil {
		t.Fatalf("body is not valid JSON: %v; body=%s", err, jsonBody)
	}
	if jsonDoc["openapi"] == nil {
		t.Errorf("parsed JSON missing top-level %q key, got: %+v", "openapi", jsonDoc)
	}

	paths, ok := jsonDoc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("parsed JSON missing top-level %q map, got: %+v", "paths", jsonDoc["paths"])
	}
	for _, route := range []string{
		"/api/healthz", "/api/nodes", "/api/nodes/{id}", "/api/topology",
		"/api/v1/stats", "/api/v1/directory", "/api/nodes/seeds",
		"/api/config/peer-seeds", "/api/wallet-nodes", "/api/admin/submissions",
		"/api/internal/collectors/report", "/api/spec", "/api/docs",
	} {
		if _, present := paths[route]; !present {
			t.Errorf("parsed JSON spec missing path %q", route)
		}
	}

	// Round-trip check (per BRIEF.md): the YAML and JSON forms must be the same
	// logical document -- spot-checked via info.title, which must survive both
	// yaml.Unmarshal (server-side, to produce the JSON form) and this test's own
	// JSON decode identically.
	var yamlDoc map[string]any
	if err := yaml.Unmarshal(docs.OpenAPISpecYAML, &yamlDoc); err != nil {
		t.Fatalf("unmarshal embedded yaml directly: %v", err)
	}
	yamlInfo, _ := yamlDoc["info"].(map[string]any)
	jsonInfo, _ := jsonDoc["info"].(map[string]any)
	if yamlInfo["title"] == nil || yamlInfo["title"] != jsonInfo["title"] {
		t.Errorf("info.title mismatch after round-trip: yaml=%v json=%v", yamlInfo["title"], jsonInfo["title"])
	}
}

// ---- GET /docs (served as GET /api/docs) ----

func TestHandleAPIDocs(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/docs")
	if err != nil {
		t.Fatalf("GET /docs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", got, "text/html; charset=utf-8")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "swagger-ui-bundle.js") {
		t.Errorf("body missing Swagger UI CDN script reference, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "/api/spec") {
		t.Errorf("body missing reference to /api/spec as the Swagger UI spec URL, got: %s", bodyStr)
	}
}

// TestHandleAPIDocs_NetmapPalette is a cheap regression guard: the Swagger UI
// dark-theme overrides must be retinted to netmap's OWN
// internal/web/static/style.css palette (not ootle-explorer's, or any other
// repo's), per BRIEF.md's explicit instruction.
func TestHandleAPIDocs_NetmapPalette(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/docs")
	if err != nil {
		t.Fatalf("GET /docs: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)

	if !strings.Contains(bodyStr, `<html lang="en" class="dark-mode">`) {
		t.Errorf(`body missing class="dark-mode" on <html>, got: %s`, bodyStr)
	}

	// netmap's own --bg/--bg-elevated/--text/--text-muted/--accent values (see
	// internal/web/static/style.css's :root block) -- NOT any other repo's palette.
	for _, want := range []string{"#10141a", "#171c24", "#1b212b", "#e4e8ee", "#93a0b3", "#5aa9ff"} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body missing netmap palette color %q, got: %s", want, bodyStr)
		}
	}
}

// ---- Spec/router drift check ----

// TestOpenAPISpecPathsMatchRouter spot-checks the full, real route list registered
// by NewRouter (internal/api/api.go) against the spec's paths: keys, per BRIEF.md's
// "catching spec drift is more valuable here than perfect OpenAPI-schema
// validation" instruction. Each entry below is (HTTP method, mux pattern as
// registered on NewRouter's own mux -- no "/api" prefix, since that's only added by
// cmd/netmap/main.go's http.StripPrefix mount in production) -- the spec itself
// documents the real, externally-reachable "/api"-prefixed path, so this test
// reconciles that offset explicitly rather than assuming the two path spaces are
// identical strings.
func TestOpenAPISpecPathsMatchRouter(t *testing.T) {
	registeredRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/healthz"},
		{"GET", "/spec"},
		{"GET", "/docs"},
		{"GET", "/nodes"},
		{"POST", "/nodes"},
		{"GET", "/nodes/{id}"},
		{"GET", "/nodes/{id}/history"},
		{"GET", "/nodes/{id}/edges"},
		{"GET", "/topology"},
		{"GET", "/topology/top-peered"},
		{"GET", "/nodes/map"},
		{"GET", "/nodes/map/extended"},
		{"GET", "/v1/stats"},
		{"GET", "/v1/directory"},
		{"GET", "/nodes/seeds"},
		{"GET", "/nodes/seed_list"},
		{"GET", "/config/peer-seeds"},
		{"GET", "/nodes/seed_list_tari"},
		{"POST", "/wallet-nodes"},
		{"GET", "/admin/submissions"},
		{"POST", "/admin/submissions/{id}/approve"},
		{"POST", "/admin/submissions/{id}/reject"},
		{"POST", "/admin/nodes/poll-now"},
		{"GET", "/admin/wallet-submissions"},
		{"POST", "/admin/wallet-submissions/{id}/approve"},
		{"POST", "/admin/wallet-submissions/{id}/reject"},
		{"POST", "/internal/collectors/report"},
	}

	var doc map[string]any
	if err := yaml.Unmarshal(docs.OpenAPISpecYAML, &doc); err != nil {
		t.Fatalf("unmarshal embedded yaml: %v", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("spec missing top-level %q map", "paths")
	}

	for _, rr := range registeredRoutes {
		specPath := "/api" + rr.path
		entry, present := paths[specPath]
		if !present {
			t.Errorf("router registers %s %s (public path %s) but the spec has no %q path entry", rr.method, rr.path, specPath, specPath)
			continue
		}
		methods, ok := entry.(map[string]any)
		if !ok {
			t.Errorf("spec path %q entry is not a map, got: %+v", specPath, entry)
			continue
		}
		if _, present := methods[strings.ToLower(rr.method)]; !present {
			t.Errorf("spec path %q is documented but missing the %s method used by the real router", specPath, rr.method)
		}
	}

	// The inverse check: every documented path must correspond to a real,
	// registered router route (plus /api/spec and /api/docs themselves, which
	// this file's own handlers implement) -- catches a stale/renamed doc entry
	// left behind after a router change.
	documented := make(map[string]bool, len(registeredRoutes))
	for _, rr := range registeredRoutes {
		documented["/api"+rr.path] = true
	}
	for specPath := range paths {
		if !documented[specPath] {
			t.Errorf("spec documents path %q, which does not correspond to any route registered by NewRouter", specPath)
		}
	}
}
