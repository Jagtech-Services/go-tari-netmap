package api

// asyncProbePool runs best-effort, non-blocking submission probes (see
// probeSubmission in probe.go and probeWalletSubmission in wallet_nodes.go) on a
// small, FIXED-SIZE worker pool, bounding the number of goroutines -- and the
// outbound dials / DB connections they each hold for up to asyncCheckTimeout
// (190s) -- these informational-only probes can ever have in flight at once.
//
// Before this type existed, POST /nodes and POST /wallet-nodes each launched a
// brand-new, completely unbounded `go probeSubmission(...)` / `go
// probeWalletSubmission(...)` goroutine on EVERY accepted submission, with no cap
// and no backpressure of any kind -- unlike internal/collector's own scheduled
// poll loop, which dispatches the exact same shape of work (dial a NodeClient,
// record the result) through an errgroup.Group with SetLimit(maxWalletHTTPPollWorkers)
// (see collector.go's poll method). A sustained flood of POST /wallet-nodes
// requests (a public, unauthenticated route once -wallet-http-enabled is set --
// see NewRouter's walletHTTPEnabled gate) -- e.g. a scanner/bot hitting it
// repeatedly right after a restart -- could pile up goroutines/outbound dials/DB
// connections far faster than the pool below now permits, explaining the prod
// CPU-peg + Mem-peak-14.8G + "store.Ping: context deadline exceeded" livelock
// this fixes: with the DB connection pool starved by hundreds of in-flight
// probes each holding a connection for up to 190s, routine work (like the
// scheduled collector loop's own metrics-refresh Ping) could no longer get a
// connection at all.
//
// Submit is non-blocking: if every worker is already busy AND the backlog
// buffer is full, the job is dropped (never queued, never run) rather than
// blocking the calling HTTP handler or growing goroutine/queue count without
// bound. This is the correct behavior specifically BECAUSE these probes are
// already documented as best-effort/informational-only, never the enforcement
// gate (see probeSubmission's and probeWalletSubmission's own doc comments) --
// skipping one under sustained flood is strictly preferable to the unbounded
// resource growth it replaces.
type asyncProbePool struct {
	jobs chan func()
}

// AsyncProbePoolWorkers/AsyncProbePoolBacklog size this pool to match
// internal/collector's own wallet-http fan-out cap (maxWalletHTTPPollWorkers = 50,
// collector.go) -- these async submission probes are a lighter-weight analogue of
// that exact same "probe a NodeClient target, record the result" operation, so
// reusing its concurrency budget keeps this pool's worst-case resource usage in
// the same ballpark rather than inventing an unrelated number. The backlog buffer
// additionally absorbs short bursts (e.g. several submissions landing in the same
// instant) without dropping a probe that would otherwise have gotten a free
// worker within a moment anyway.
//
// Exported vars, not consts -- same rationale as api.go's MaxPendingSubmissions:
// so a test can temporarily lower them (rather than actually flooding the route
// with 50+ real concurrent submissions) to exercise the cap. See
// TestCreateWalletNodeSubmissionProbesAreBounded.
var (
	AsyncProbePoolWorkers = 50
	AsyncProbePoolBacklog = 50
)

// newAsyncProbePool starts AsyncProbePoolWorkers long-lived worker goroutines
// (never torn down -- matching ipRateLimiter/invalidSubmissionTracker's own "lives
// for the process lifetime, one instance per NewRouter call" convention, see
// ratelimit.go) and returns the pool ready to accept Submit calls. Exactly one
// instance is created per NewRouter call and shared by both handleCreateNode and
// handleCreateWalletNodeSubmission -- there is no reason to budget these two
// similar-risk-profile public write routes' background probes separately, any
// more than there's a reason for them to use separate rate limiters (see
// NewRouter's existing shared limiter/lockouts instances). Reads
// AsyncProbePoolWorkers/AsyncProbePoolBacklog at call time (not fixed at package
// init) so a test can lower them before calling NewRouter.
func newAsyncProbePool() *asyncProbePool {
	p := &asyncProbePool{jobs: make(chan func(), AsyncProbePoolBacklog)}
	for i := 0; i < AsyncProbePoolWorkers; i++ {
		go p.worker()
	}
	return p
}

func (p *asyncProbePool) worker() {
	for fn := range p.jobs {
		fn()
	}
}

// Submit enqueues fn to run on this pool's worker goroutines, returning
// immediately without blocking the caller. If every worker is busy and the
// backlog is already full, fn is silently dropped (never run) -- see
// asyncProbePool's doc comment for why this is the correct behavior for these
// best-effort probes rather than blocking the HTTP handler or growing without
// bound.
func (p *asyncProbePool) Submit(fn func()) {
	select {
	case p.jobs <- fn:
	default:
	}
}
