package api

import (
	"context"
	"log"
	"sync"
	"time"
)

// backgroundCacheInitialRetryInterval is how quickly a BackgroundCache
// retries its FIRST compute if it fails (e.g. storage isn't reachable
// yet at process startup) -- deliberately much shorter than any of this
// codebase's whole-population cache TTLs (60s, see
// DefaultStatsCacheTTL/DefaultDashboardCountsCacheTTL/
// DefaultExtendedMapCacheTTL), so a transient startup failure doesn't
// wedge every Get call behind a full TTL-sized wait. Once the first
// compute succeeds, a later failed refresh is just logged and left for
// the next regular ticker tick -- an already-warm cache keeps serving
// its last-known-good value rather than retrying aggressively.
const backgroundCacheInitialRetryInterval = 1 * time.Second

// RefreshFunc computes a BackgroundCache's value. A returned error is
// logged (see NewBackgroundCache's name parameter) and leaves the
// cache's current value (if any) in place -- a failed refresh never
// overwrites a valid cached value with a zero value.
type RefreshFunc[T any] func(ctx context.Context) (T, error)

// BackgroundCache is a generic, once-per-process, ticker-driven
// background-refresh cache: a single long-lived goroutine owns
// recomputing T on its own schedule and atomically swaps the new value
// in. Callers (HTTP handlers) only ever read the last-computed value
// via Get -- there is NO recompute-on-cache-miss path in the request
// path at all, by construction. This is the fix for a real,
// live-reproduced prod incident: a SIGQUIT goroutine dump captured
// directly from the failing process showed 12 concurrent GET /v1/stats
// requests, each independently missing the (then on-demand, not
// deduplicated) statsCache at the same moment right after a restart and
// each recomputing+holding its own full 115,397-node population
// snapshot in memory at once while blocked waiting on a saturated
// Postgres connection pool -- that pile of simultaneous whole-population
// result sets, not a goroutine leak, was the actual multi-GB RSS driver.
// A background-refresh cache makes that pile-up structurally
// impossible: there is only ever one in-flight compute for a given
// cache, ever, run by this type's own goroutine, never by an HTTP
// request.
//
// The goroutine itself is started LAZILY, by the first call to Get --
// not by NewBackgroundCache -- so a cache that's never actually
// requested never issues a single query, and (deliberately) so that
// construction time (e.g. NewRouter/web.NewHandler, typically called
// at process startup before any request has ever arrived) is decoupled
// from the data a caller's first real request sees: the first Get call
// triggers the goroutine's startup AND its first compute, and every
// Get call made while that first compute is outstanding (including the
// one that triggered it) blocks on it together rather than each
// triggering its own -- this is what makes the regression this type
// fixes impossible: N concurrent first-ever callers produce exactly
// ONE call to refresh, never N. Once that first compute succeeds, the
// SAME goroutine keeps running for the process/ctx's lifetime, ticking
// every ttl and recomputing on its own, completely independent of
// request volume from then on -- every Get call after the first
// successful compute is a plain RLock'd read, never a wait, never a
// recompute.
//
// ctx (passed to NewBackgroundCache, NOT the ctx a given Get call is
// made with) controls the background refresh loop's lifetime once
// started: when ctx is done, the loop exits for good (no further
// refreshes -- Get keeps serving whatever was last computed, or will
// block forever on a Get whose own ctx is never canceled if nothing was
// EVER successfully computed). ttl <= 0 means "compute once (lazily, on
// first Get), never again" (no periodic ticker at all) -- there is
// deliberately no "disable caching, recompute on every request" mode
// anymore now that the request path never recomputes by construction.
type BackgroundCache[T any] struct {
	ctx     context.Context
	name    string
	ttl     time.Duration
	refresh RefreshFunc[T]

	startOnce sync.Once

	mu    sync.RWMutex
	value T
	valid bool

	ready     chan struct{}
	readyOnce sync.Once
}

// NewBackgroundCache constructs a BackgroundCache. It does NOT start
// any work yet -- see this type's doc comment for why the background
// refresh goroutine's startup (and its first compute) is deferred until
// the first call to Get. ctx controls the refresh loop's lifetime once
// it does start. name is used only to label log output if a refresh
// fails, so it's obvious which cache failed.
func NewBackgroundCache[T any](ctx context.Context, name string, ttl time.Duration, refresh RefreshFunc[T]) *BackgroundCache[T] {
	return &BackgroundCache[T]{
		ctx:     ctx,
		name:    name,
		ttl:     ttl,
		refresh: refresh,
		ready:   make(chan struct{}),
	}
}

// run is the background refresh loop: an initial compute (retried every
// backgroundCacheInitialRetryInterval until it succeeds or ctx is done),
// then -- if ttl > 0 -- a tick every ttl for the remaining lifetime of
// ctx. Started exactly once, by the first call to Get (see startOnce).
func (c *BackgroundCache[T]) run() {
	for !c.refreshOnce() {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backgroundCacheInitialRetryInterval):
		}
	}

	if c.ttl <= 0 {
		return
	}

	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.refreshOnce()
		}
	}
}

// refreshOnce runs c.refresh exactly once, storing the result and
// marking the cache ready/valid on success. Returns whether it
// succeeded.
func (c *BackgroundCache[T]) refreshOnce() bool {
	v, err := c.refresh(c.ctx)
	if err != nil {
		log.Printf("%s: background cache refresh failed, continuing to serve last-known-good value: %v", c.name, err)
		return false
	}
	c.mu.Lock()
	c.value = v
	c.valid = true
	c.mu.Unlock()
	c.readyOnce.Do(func() { close(c.ready) })
	return true
}

// Get returns the cache's current value, starting the background
// refresh goroutine on the very first call (see this type's doc
// comment). If the first compute hasn't completed yet, Get blocks
// until it does, or until ctx is done, whichever happens first --
// callers should pass the request's own context so a slow/never-
// completing first compute doesn't leak a goroutine past the client
// giving up. Every call after the first successful compute returns
// immediately.
func (c *BackgroundCache[T]) Get(ctx context.Context) (T, error) {
	c.startOnce.Do(func() { go c.run() })

	c.mu.RLock()
	if c.valid {
		v := c.value
		c.mu.RUnlock()
		return v, nil
	}
	c.mu.RUnlock()

	select {
	case <-c.ready:
		c.mu.RLock()
		v := c.value
		c.mu.RUnlock()
		return v, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}
