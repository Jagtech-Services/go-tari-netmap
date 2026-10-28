// Package geoip implements a minimal client for ip-api.com's free-tier
// batch geolocation endpoint, plus the rate-limiting policy its free
// tier imposes (45 requests/minute). This is explicitly the only GeoIP
// provider in scope for the /map feature's spike (see BRIEF.md's
// "Explicit non-goals" section) -- no MaxMind/paid-provider integration.
//
// This package has no dependency on any other
// github.com/Jagtech-Services/go-tari-netmap package (it doesn't even know what a
// storage.Node is) -- it is a pure network client, deliberately kept as
// a leaf package. internal/collector owns the cache-read-through/TTL
// policy and calls into this package only for the actual outbound HTTP
// lookups.
package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// DefaultBatchURL is ip-api.com's free-tier batch endpoint.
const DefaultBatchURL = "http://ip-api.com/batch"

// MaxBatchSize is the maximum number of IPs ip-api.com's batch endpoint
// accepts in a single call.
const MaxBatchSize = 100

// RateLimit is ip-api.com's free-tier requests-per-minute cap.
const RateLimit = 45

// requestFields is passed as every batch item's "fields" value, asking
// ip-api.com to return only what this package actually uses.
//
// "query" MUST stay in this list even though nothing in Result reads
// it directly: ip-api.com's batch endpoint only echoes a response
// item's "query" key back if it was explicitly requested (it is NOT
// included by default, unlike the singular-lookup endpoint) — and
// lookupBatch keys its result map by batchResponseItem.Query. Drop
// "query" from here and every response item's Query decodes as "",
// collapsing every IP's result onto the same out[""] map key.
const requestFields = "status,message,lat,lon,city,country,query"

// HTTPDoer is the subset of *http.Client Client needs, letting tests
// substitute a fake implementation with no real network access (see
// this package's tests) -- *http.Client itself satisfies this
// interface, so production code needs no adapter.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Result is one ip-api.com lookup result for a single IP.
type Result struct {
	Latitude  float64
	Longitude float64
	City      string
	Country   string

	// Failed reports whether ip-api.com itself reported a non-"success"
	// status for this IP (e.g. a private/reserved IP it refuses to
	// geolocate, or a malformed query) -- a normal, expected per-IP
	// outcome, distinct from a transport/decode-level error for the
	// whole batch call, which Lookup instead surfaces as a returned
	// error with the affected IPs simply absent from the result map
	// (see Lookup's doc comment).
	Failed bool
}

// batchRequestItem/batchResponseItem mirror ip-api.com's documented
// batch request/response JSON shapes (https://ip-api.com/docs/api:batch)
// exactly -- field names are the API's own, not this package's choice.
type batchRequestItem struct {
	Query  string `json:"query"`
	Fields string `json:"fields"`
}

type batchResponseItem struct {
	Query   string  `json:"query"`
	Status  string  `json:"status"`
	Message string  `json:"message"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city"`
	Country string  `json:"country"`
}

// Client is a rate-limited ip-api.com batch client. The zero value is a
// ready-to-use Client (HTTPClient defaults to http.DefaultClient,
// BatchURL to DefaultBatchURL, Limiter to a fresh RateLimit-per-minute
// limiter constructed lazily on first use).
type Client struct {
	// HTTPClient performs the actual HTTP round trip. Nil (the zero
	// value) means http.DefaultClient.
	HTTPClient HTTPDoer

	// BatchURL overrides DefaultBatchURL. Exposed so tests can point at
	// a fake httptest.Server instead of (or in addition to) faking
	// HTTPClient directly -- either approach works.
	BatchURL string

	// Limiter overrides the default RateLimit-requests/minute limiter.
	// Exposed so tests can inject a fast/non-blocking limiter (e.g.
	// rate.NewLimiter(rate.Inf, 1)) without needing to wait on the real
	// free-tier cadence. Nil (the default for every production caller)
	// lazily constructs the real RateLimit limiter on first use, one
	// token consumed per batch HTTP call (not per IP).
	Limiter *rate.Limiter
}

// NewClient returns a ready-to-use Client with every field at its
// default (HTTPClient: http.DefaultClient, BatchURL: DefaultBatchURL,
// Limiter: a fresh RateLimit-per-minute limiter). Equivalent to
// &Client{} -- provided as a named constructor purely for readability
// at production call sites (see cmd/netmap/main.go).
func NewClient() *Client {
	return &Client{}
}

func (c *Client) httpClient() HTTPDoer {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) batchURL() string {
	if c.BatchURL != "" {
		return c.BatchURL
	}
	return DefaultBatchURL
}

// rateLimiter lazily constructs the default limiter on first use if
// Limiter hasn't been set explicitly -- this keeps the zero-value
// Client usable directly (no required constructor call) while still
// letting tests inject their own Limiter before the first Lookup call.
func (c *Client) rateLimiter() *rate.Limiter {
	if c.Limiter == nil {
		// RateLimit requests per 60 seconds, burst 1: a strict
		// steady-state cap, not an initial allowance to burn through
		// RateLimit calls all at once -- a full node population can
		// need far more than one batch call back-to-back (see this
		// package's doc comment), so pacing every single call matters,
		// not just the first RateLimit of them.
		c.Limiter = rate.NewLimiter(rate.Every(time.Minute/RateLimit), 1)
	}
	return c.Limiter
}

// Lookup resolves every ip in ips, chunking into MaxBatchSize-sized
// batches and waiting on this Client's rate limiter (RateLimit
// requests/minute) before each batch's HTTP call.
//
// Returns a map keyed by IP. An IP ip-api.com itself reports a failure
// for is present in the map with Result.Failed == true (see Result's
// doc comment) -- NOT as a missing key and NOT as a returned error. A
// non-nil returned error means a transport/decode failure for at least
// one batch call; the IPs in any batch that failed that way are simply
// absent from the returned map (the caller -- see
// internal/collector.RefreshGeoIP -- decides how to treat a missing
// key) rather than this method aborting every other, already-succeeded
// batch. Only the first such error is returned even if multiple batches
// fail, since every batch is still attempted regardless.
func (c *Client) Lookup(ctx context.Context, ips []string) (map[string]Result, error) {
	out := make(map[string]Result, len(ips))

	var firstErr error
	for start := 0; start < len(ips); start += MaxBatchSize {
		end := start + MaxBatchSize
		if end > len(ips) {
			end = len(ips)
		}
		batch := ips[start:end]

		if err := c.rateLimiter().Wait(ctx); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("geoip: rate limiter wait: %w", err)
			}
			continue
		}

		results, err := c.lookupBatch(ctx, batch)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for ip, res := range results {
			out[ip] = res
		}
	}
	return out, firstErr
}

// lookupBatch performs exactly one HTTP POST to BatchURL for up to
// MaxBatchSize ips (the caller, Lookup, is responsible for chunking),
// matching ip-api.com's documented batch request/response array shapes.
func (c *Client) lookupBatch(ctx context.Context, ips []string) (map[string]Result, error) {
	items := make([]batchRequestItem, len(ips))
	for i, ip := range ips {
		items[i] = batchRequestItem{Query: ip, Fields: requestFields}
	}

	body, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("geoip: marshal batch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.batchURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("geoip: build batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("geoip: batch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("geoip: batch request: unexpected status %d", resp.StatusCode)
	}

	var respItems []batchResponseItem
	if err := json.NewDecoder(resp.Body).Decode(&respItems); err != nil {
		return nil, fmt.Errorf("geoip: decode batch response: %w", err)
	}

	out := make(map[string]Result, len(respItems))
	for _, item := range respItems {
		out[item.Query] = Result{
			Latitude:  item.Lat,
			Longitude: item.Lon,
			City:      item.City,
			Country:   item.Country,
			Failed:    item.Status != "success",
		}
	}
	return out, nil
}
