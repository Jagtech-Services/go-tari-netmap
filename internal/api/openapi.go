package api

import (
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"

	"gopkg.in/yaml.v3"

	"github.com/Jagtech-Services/go-tari-netmap/internal/docs"
)

//go:embed templates/*.html
var apiTemplatesFS embed.FS

// apiDocsTmpl renders templates/api_docs.html (see that file's own comment) --
// parsed once at package init time, following internal/web/web.go's exact
// //go:embed templates/*.tmpl + template.ParseFS convention, just for a single
// static page with no data model (Execute is always called with nil).
var apiDocsTmpl = template.Must(template.ParseFS(apiTemplatesFS, "templates/api_docs.html"))

// handleAPISpec serves GET /spec (reachable as GET /api/spec once
// cmd/netmap/main.go mounts this router behind its "/api" http.StripPrefix): the
// contents of internal/docs/openapi.yaml, embedded into the binary via
// docs.OpenAPISpecYAML (see that package's own doc comment for why the embed
// lives there rather than directly in this package), served as-is (Content-Type
// application/yaml).
//
// ?format=json transcodes the same spec to JSON instead, using the yaml.v3
// library (already a transitive dependency of this module -- see go.sum). A
// transcoding failure (which would only happen if the embedded YAML were
// malformed -- a build-time programming error, not a runtime condition) falls
// back to a 500 JSON error rather than serving broken output.
func handleAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("format") == "json" {
		var doc any
		if err := yaml.Unmarshal(docs.OpenAPISpecYAML, &doc); err != nil {
			log.Printf("api: spec: unmarshal embedded yaml: %v", err)
			writeError(w, http.StatusInternalServerError, errors.New("failed to transcode spec to json"))
			return
		}
		writeJSON(w, http.StatusOK, doc)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(docs.OpenAPISpecYAML); err != nil {
		log.Printf("api: spec: write response: %v", err)
	}
}

// handleAPIDocs serves GET /docs (reachable as GET /api/docs): a minimal static
// HTML page embedding Swagger UI via a CDN script tag (templates/api_docs.html --
// see that file's own comment), pointed at /api/spec as its spec URL.
func handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := apiDocsTmpl.Execute(w, nil); err != nil {
		log.Printf("api: render api docs: %v", err)
	}
}
