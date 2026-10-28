// Package remotestore implements storage.Store for a remote collector satellite: a
// geo-distributed netmap-p2p-responder deployment that talks to the central go-tari-netmap
// system over its HTTP API (internal/api's POST /internal/collectors/report and GET
// /nodes/seed_list, see BRIEF.md) instead of opening a direct Postgres connection.
//
// # Reads
//
// ListNodes (and everything else that reads node state -- GetNode, ListNodeAddresses(ForNodes),
// CountNodes) is served entirely from a local, in-memory cache, refreshed on a background
// ticker (default 60s, see Config.CacheRefreshInterval) by polling the central GET
// /nodes/seed_list route. This is a deliberate design choice, not a limitation worth working
// around: with most clients connecting via Tor, satellite geographic locality doesn't matter
// for the peer list this store serves, so every satellite draws from the exact same central
// known-good population every other instance would, rather than a locally-observed subset.
//
// Nodes this satellite discovers or confirms ITSELF (via UpsertDiscoveredNode/
// UpsertConfirmedNode -- e.g. its own peer-graph walk, or a direct probe/handshake) are ALSO
// tracked locally and immediately visible to ListNodes/GetNode alongside the cached
// population -- a satellite's own active-scanner role is not purely a replay of the central
// cache. What IS a hard limitation of this design: a node's Owned status and DiscoverySource
// as reported by GET /nodes/seed_list are not fully faithful to the central database (the
// wire response, api.PublicSeedCandidate, does not carry a Tags field at all, and
// DiscoverySource is synthesized as storage.DiscoverySourceBoth for every cached entry) --
// see refreshCache's doc comment for the full accounting of what's approximated and why this
// is an acceptable tradeoff given this store's minimal, address-keyed wire contract.
//
// # Writes
//
// UpsertDiscoveredNode/UpsertConfirmedNode/RecordHealthCheck/RecordPeerEdgeObservation buffer
// their input in memory and flush it to the central POST /internal/collectors/report route on
// a timer (default 60s, see Config.FlushInterval) or once the buffer reaches
// Config.FlushBatchSize records, whichever comes first. A flush failure (network blip, central
// system down) never drops the buffered data -- see flushOnce's doc comment: the buffer is
// restored and retried on the next trigger, not cleared, on any POST failure.
//
// # Node identity
//
// This satellite has no central node IDs of its own -- every write it reports is keyed by
// address, and the central handler resolves address -> its own authoritative node ID
// server-side (see internal/api/collector_report.go). Locally, though, storage.Store's own
// method signatures (RecordHealthCheck/RecordPeerEdgeObservation) take a uuid.UUID, not an
// address -- so this Store still needs SOME uuid.UUID to hand back from
// UpsertDiscoveredNode/UpsertConfirmedNode for the caller (internal/collector's Poll/Discover
// loops) to pass back into those calls later. For an address that's already appeared in a
// GET /nodes/seed_list refresh, that ID is the real, central-authoritative one (SeedCandidate's
// own node_id). For an address this satellite is the first to see locally (not yet reflected in
// any seed_list refresh), a synthetic, per-address-deterministic ID is generated instead (see
// deterministicNodeID) purely so repeated local UpsertDiscoveredNode/UpsertConfirmedNode calls
// for the same address are self-consistent within this process — it is NEVER sent over the
// wire and never confused with a real central ID (every outbound report references addresses,
// never uuid.UUIDs at all, see collector_report.go's wire contract).
package remotestore

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// DefaultCacheRefreshInterval is Config.CacheRefreshInterval's default when unset/<= 0.
const DefaultCacheRefreshInterval = 60 * time.Second

// DefaultFlushInterval is Config.FlushInterval's default when unset/<= 0.
const DefaultFlushInterval = 60 * time.Second

// DefaultFlushBatchSize is Config.FlushBatchSize's default when unset/<= 0.
const DefaultFlushBatchSize = 500

// DefaultRequestTimeout bounds every individual outbound HTTP call this store makes (a single
// report flush or seed_list refresh), used to build Config.HTTPClient when the caller doesn't
// supply their own.
const DefaultRequestTimeout = 30 * time.Second

// Config configures a Store.
type Config struct {
	// BaseURL is the central go-tari-netmap system's API base URL, e.g.
	// "https://netmap.example.com/api" -- Store issues GET BaseURL+"/nodes/seed_list", GET
	// BaseURL+"/healthz", and POST BaseURL+"/internal/collectors/report" against it. Required.
	BaseURL string

	// APIKey is this collector's own API key, sent as the X-Collector-Key header on every
	// POST /internal/collectors/report request (see internal/api/collector_auth.go).
	// Required.
	APIKey string

	// CollectorName is this collector's own configured name, purely for this store's own log
	// messages -- it is NOT sent over the wire (the central API identifies a collector by
	// which configured APIKey matched, not by a name field in the request body).
	CollectorName string

	// SelfAddresses is this collector's own advertised P2P address(es) -- the same
	// "host:port"-convention addresses cmd/netmap-p2p-responder advertises via its own
	// -public-tcp-addr/-onion3-addr flags (converted from multiaddr form -- see that
	// binary's selfAdvertisedAddresses helper) -- sent as every flush's self_identity field,
	// so the central API tags the matching node row(s) tags.role = "collector" (see
	// collector_report.go). Sent on EVERY flush (even one with nothing else to report),
	// since self-identity tagging must not depend on this collector otherwise having
	// something to report.
	SelfAddresses []string

	// CacheRefreshInterval is how often the local node cache is refreshed from GET
	// /nodes/seed_list. Defaults to DefaultCacheRefreshInterval when <= 0.
	CacheRefreshInterval time.Duration

	// FlushInterval is how often buffered writes are flushed to POST
	// /internal/collectors/report, in addition to the size-triggered flush (see
	// FlushBatchSize). Defaults to DefaultFlushInterval when <= 0.
	FlushInterval time.Duration

	// FlushBatchSize is the total buffered-record count (summed across all four buffers)
	// that triggers an immediate flush, independent of FlushInterval's timer. Defaults to
	// DefaultFlushBatchSize when <= 0.
	FlushBatchSize int

	// HTTPClient is the client used for every outbound request. Defaults to a client with a
	// DefaultRequestTimeout timeout when nil.
	HTTPClient *http.Client

	// Logf is used for this store's own operational log messages (flush/refresh failures,
	// etc.). Defaults to log.Printf when nil.
	Logf func(format string, args ...any)

	// ReportChannelUnhealthyThreshold bounds how long Ping is willing to tolerate the report
	// channel (POST /internal/collectors/report) having failed before Ping itself starts
	// failing -- see this repo's readiness-review follow-up, Fix 1, and Ping's own doc
	// comment for the full rationale. Defaults to DefaultReportChannelUnhealthyThreshold
	// when <= 0.
	ReportChannelUnhealthyThreshold time.Duration

	// OnFlushResult, if non-nil, is called once per actual POST /internal/collectors/report
	// HTTP attempt (i.e. once per sub-batch -- see flush.go's flushOnce/splitBatch), success
	// or failure -- lets a caller (see cmd/netmap-p2p-responder/metrics.go) wire this
	// store's report-flush outcomes into its own Prometheus metrics, mirroring
	// collector.Collector.OnPollResult's existing callback convention elsewhere in this
	// repo. See this repo's readiness-review follow-up, Fix 2, for why this exists: before
	// it, the satellite's report channel had zero observability of its own.
	OnFlushResult func(success bool)
}

// DefaultReportChannelUnhealthyThreshold is Config.ReportChannelUnhealthyThreshold's default
// when unset/<= 0 -- see Ping's own doc comment for the full rationale. Five times
// DefaultFlushInterval (5 minutes, given DefaultFlushInterval's own 60s default) gives
// several missed flush cycles' worth of grace before Ping actually starts failing, so a
// single transient blip doesn't flip the satellite's own /healthz red, while a genuinely
// broken report channel (wrong/rotated API key, central outage, NETMAP_COLLECTOR_KEYS unset
// centrally) is caught well within any reasonable alerting window.
const DefaultReportChannelUnhealthyThreshold = 5 * DefaultFlushInterval

// trackedNode is one node this Store knows about, either because it was learned via a GET
// /nodes/seed_list refresh (cacheDerived == true, id is the real central-authoritative ID) or
// because this satellite itself upserted it locally via UpsertDiscoveredNode/
// UpsertConfirmedNode (cacheDerived == false, id is a deterministicNodeID synthetic value --
// see this package's doc comment).
type trackedNode struct {
	node            storage.Node
	addresses       []storage.NodeAddress
	hasHealthChecks bool
	cacheDerived    bool
}

// Store implements storage.Store against a central go-tari-netmap system's HTTP API. See this
// package's doc comment for the full read/write/identity model. The zero value is not usable;
// construct via New.
type Store struct {
	cfg Config

	mu     sync.Mutex
	closed bool

	nodes       map[uuid.UUID]*trackedNode
	idByAddress map[string]uuid.UUID
	addressByID map[uuid.UUID]string

	pendingConfirmed  []pendingConfirmedNode
	pendingDiscovered []pendingDiscoveredNode
	pendingHealth     []pendingHealthCheck
	pendingEdges      []pendingPeerEdge

	// flushTrigger is signaled (non-blocking, buffered 1) by maybeSignalFlushLocked once the
	// combined pending-buffer size crosses FlushBatchSize, so Run's select loop flushes
	// immediately rather than waiting for the next FlushInterval tick.
	flushTrigger chan struct{}

	// lastFlushAttempt/lastFlushSuccess/lastFlushErr track the report channel's own health
	// (see this repo's readiness-review follow-up, Fix 1) -- updated by flushOnce after
	// every actual POST /internal/collectors/report attempt (one update per sub-batch, see
	// splitBatch), consulted by Ping to decide whether the report channel itself (as
	// distinct from bare central-API reachability, which the existing GET /healthz proxy
	// check below still covers) has been failing for too long. lastFlushAttempt/
	// lastFlushSuccess are both the zero time.Time until the first attempt/success
	// respectively.
	lastFlushAttempt time.Time
	lastFlushSuccess time.Time
	lastFlushErr     error
}

// New validates cfg and returns a new Store. It does not itself start any background
// goroutine -- the caller must run Store.Run(ctx) in its own goroutine (mirroring
// collector.Collector.Run's convention) for the cache-refresh/flush loops to actually execute,
// and should defer Store.Close() to attempt one final flush of any still-buffered data at
// shutdown.
func New(cfg Config) (*Store, error) {
	if cfg.BaseURL == "" {
		return nil, errRemoteStore("BaseURL is required")
	}
	if cfg.APIKey == "" {
		return nil, errRemoteStore("APIKey is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: DefaultRequestTimeout}
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}

	return &Store{
		cfg:          cfg,
		nodes:        make(map[uuid.UUID]*trackedNode),
		idByAddress:  make(map[string]uuid.UUID),
		addressByID:  make(map[uuid.UUID]string),
		flushTrigger: make(chan struct{}, 1),
	}, nil
}

func (s *Store) cacheRefreshInterval() time.Duration {
	if s.cfg.CacheRefreshInterval > 0 {
		return s.cfg.CacheRefreshInterval
	}
	return DefaultCacheRefreshInterval
}

func (s *Store) flushInterval() time.Duration {
	if s.cfg.FlushInterval > 0 {
		return s.cfg.FlushInterval
	}
	return DefaultFlushInterval
}

func (s *Store) flushBatchSize() int {
	if s.cfg.FlushBatchSize > 0 {
		return s.cfg.FlushBatchSize
	}
	return DefaultFlushBatchSize
}

func (s *Store) reportChannelUnhealthyThreshold() time.Duration {
	if s.cfg.ReportChannelUnhealthyThreshold > 0 {
		return s.cfg.ReportChannelUnhealthyThreshold
	}
	return DefaultReportChannelUnhealthyThreshold
}

func (s *Store) logf(format string, args ...any) {
	s.cfg.Logf(format, args...)
}

// PendingRecordCount returns the current combined size of every pending-write buffer
// (confirmed nodes + discovered nodes + health checks + peer edges) -- the exact same "total"
// maybeSignalFlushLocked (writes.go) compares against FlushBatchSize. Exposed for a caller's
// own Prometheus pending-records gauge (see this repo's readiness-review follow-up, Fix 2 --
// cmd/netmap-p2p-responder/metrics.go polls this after every flush attempt).
func (s *Store) PendingRecordCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pendingConfirmed) + len(s.pendingDiscovered) + len(s.pendingHealth) + len(s.pendingEdges)
}

// LastSuccessfulFlushAt returns the time of this Store's most recent successful
// POST /internal/collectors/report attempt (one specific sub-batch, not necessarily "every
// buffer fully drained" -- see flushOnce/splitBatch), or the zero time.Time if none has ever
// succeeded. Exposed for a caller's own Prometheus last-successful-flush-timestamp gauge (Fix
// 2) and consulted by Ping (Fix 1).
func (s *Store) LastSuccessfulFlushAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFlushSuccess
}

// onFlushResultLocked records a single flush attempt's outcome and invokes
// Config.OnFlushResult, if configured. Callers must hold s.mu.
func (s *Store) recordFlushResultLocked(err error) {
	now := time.Now()
	s.lastFlushAttempt = now
	s.lastFlushErr = err
	if err == nil {
		s.lastFlushSuccess = now
	}
}

// var _ storage.Store = (*Store)(nil) is a compile-time assertion that *Store implements
// storage.Store in full -- required for it to be usable anywhere a storage.Store is expected
// (Collector.Storage, collector.PollOnce, dbBackedResponder.store), even though, per this
// package's doc comment, only a subset of the interface's methods are ever actually exercised
// against a *Store in practice.
var _ storage.Store = (*Store)(nil)
