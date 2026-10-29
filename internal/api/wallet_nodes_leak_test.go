package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jagtech-Services/go-tari-netmap/internal/adminauth"
	"github.com/Jagtech-Services/go-tari-netmap/internal/api"
	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// blockingWalletHTTPClient is a collector.NodeClient fixture whose GetInfo blocks
// until release is closed, tracking how many GetInfo calls are concurrently in
// flight (and the high-water mark ever reached). Used by
// TestCreateWalletNodeSubmissionProbesAreBounded to prove the shared, bounded
// probePool (see asyncpool.go) actually bounds concurrency, rather than just
// plausibly sounding like it does.
type blockingWalletHTTPClient struct {
	release <-chan struct{}

	mu       sync.Mutex
	inFlight int
	peak     int
}

func (c *blockingWalletHTTPClient) GetPeers(ctx context.Context, addr string) ([]collector.DiscoveredPeer, error) {
	return nil, nil
}

func (c *blockingWalletHTTPClient) GetInfo(ctx context.Context, addr string) (collector.NodeInfo, error) {
	c.mu.Lock()
	c.inFlight++
	if c.inFlight > c.peak {
		c.peak = c.inFlight
	}
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.inFlight--
		c.mu.Unlock()
	}()

	select {
	case <-c.release:
	case <-ctx.Done():
	}
	return collector.NodeInfo{Reachable: true}, nil
}

// Peak returns the highest number of concurrently in-flight GetInfo calls
// observed so far.
func (c *blockingWalletHTTPClient) Peak() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peak
}

// TestCreateWalletNodeSubmissionProbesAreBounded is the regression test for the
// prod mainnet netmap livelock/memory-leak incident this fix addresses (see this
// fix's commit message / asyncpool.go's doc comment for the full writeup).
//
// Before this fix, handleCreateWalletNodeSubmission launched a brand-new,
// completely unbounded `go probeWalletSubmission(...)` goroutine on EVERY
// accepted POST /wallet-nodes submission -- a public, unauthenticated route once
// -wallet-http-enabled is set (internal/api/api.go's NewRouter, walletHTTPEnabled
// gate) -- with no concurrency cap of any kind. A flood of submissions (e.g. a
// scanner/bot hitting the route repeatedly right after a restart, from many
// distinct source IPs so the existing per-IP rate limiter never meaningfully
// engages) could pile up goroutines/outbound wallet-HTTP dials/DB connections far
// faster than they drained, which is exactly what prod observed: CPU pegged
// across multiple cores, Mem peak 14.8G after only 3m22s of uptime, and
// "store.Ping: context deadline exceeded" (the DB connection pool starved by
// hundreds of in-flight probes each holding a connection for up to
// asyncCheckTimeout = 190s).
//
// This test floods the endpoint with many more concurrent submissions than the
// shared probePool's worker count, using a NodeClient whose GetInfo blocks until
// released (so in-flight probes accumulate instead of finishing instantly) and
// counts the high-water mark of CONCURRENTLY in-flight probes. Each request uses
// a distinct simulated source IP (bypassing the pre-existing, separate per-IP
// rate limiter on purpose, since that limiter is not what this test is about --
// it does not, by itself, bound TOTAL concurrency across many distinct sources,
// which is exactly the scenario the incident's "many distinct scanner IPs"
// explanation describes) by calling the router's ServeHTTP directly rather than
// going through a single real TCP loopback connection.
//
// AsyncProbePoolWorkers/AsyncProbePoolBacklog are deliberately lowered for this
// test (exported vars, see asyncpool.go, mirroring MaxPendingSubmissions' own
// "exported var so a test can shrink it" convention) so this test doesn't need to
// fire 50+ real concurrent requests to prove the bound -- a small number is
// enough to prove the mechanism.
//
// This test FAILS against the original code (a bare `go probeWalletSubmission(...)`
// per request): the observed peak would equal floodSize (every probe starts
// immediately, all block on release concurrently). It PASSES once probes are
// routed through the bounded pool: the observed peak is capped at
// AsyncProbePoolWorkers regardless of floodSize.
func TestCreateWalletNodeSubmissionProbesAreBounded(t *testing.T) {
	const (
		poolWorkers = 5
		poolBacklog = 5
		floodSize   = 40 // comfortably more than poolWorkers+poolBacklog
	)

	origWorkers, origBacklog := api.AsyncProbePoolWorkers, api.AsyncProbePoolBacklog
	api.AsyncProbePoolWorkers = poolWorkers
	api.AsyncProbePoolBacklog = poolBacklog
	t.Cleanup(func() {
		api.AsyncProbePoolWorkers = origWorkers
		api.AsyncProbePoolBacklog = origBacklog
	})

	release := make(chan struct{})
	client := &blockingWalletHTTPClient{release: release}
	// Always let every blocked probe finish once the test is done asserting,
	// regardless of how/where it returns, so no goroutine from this test is
	// ever left blocked past the test's lifetime.
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	store := newTestStore(t)
	ctx := context.Background()

	// Every flood request targets the SAME already-known host -- irrelevant to
	// what this test asserts (CreatePendingWalletSubmission updates the same
	// pending row in place for repeat submissions of the same host, per its own
	// doc comment); what matters here is purely how many concurrent
	// probeWalletSubmission goroutines the handler ever lets run at once, not DB
	// row accumulation.
	if _, err := store.UpsertDiscoveredNode(ctx, "203.0.113.99:18142", storage.DiscoverySourceRegistry, nil, nil); err != nil {
		t.Fatalf("upsert node: %v", err)
	}

	handler := api.NewRouter(t.Context(), store, nil, nil, client, true,
		adminauth.Credentials{Username: testAdminUser, Password: testAdminPassword},
		testCollectorKeys(), api.DefaultStatsCacheTTL, api.DefaultDirectoryCacheTTL, api.DefaultExtendedMapCacheTTL)

	var wg sync.WaitGroup
	var accepted int32
	for i := 0; i < floodSize; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"host":"203.0.113.99","wallet_http_port":9000}`
			req := httptest.NewRequest(http.MethodPost, "/wallet-nodes", strings.NewReader(body))
			// Distinct simulated source IP per request -- see this test's doc
			// comment for why: isolates this test to the concurrency-cap
			// regression, independent of the pre-existing per-IP rate limiter.
			req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:12345", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusAccepted {
				atomic.AddInt32(&accepted, 1)
			}
		}(i)
	}
	wg.Wait()

	if accepted != floodSize {
		t.Fatalf("accepted = %d, want %d (every flood request should be a well-formed, accepted submission)", accepted, floodSize)
	}

	// Give every spawned probe (bounded or not) a moment to actually start and
	// block on release -- a short, generous fixed sleep is simplest/least flaky
	// here since there is no external signal for "every probe that WILL start
	// has started" when the whole point is that some excess ones must NOT start
	// at all.
	time.Sleep(300 * time.Millisecond)

	peak := client.Peak()
	if peak > poolWorkers {
		t.Fatalf("peak concurrent in-flight wallet-http probes = %d, want <= %d (AsyncProbePoolWorkers) -- "+
			"probeWalletSubmission is not being bounded by the shared probePool; a flood of POST /wallet-nodes "+
			"submissions can still spawn unbounded concurrent probe goroutines/DB connections, reproducing the "+
			"prod livelock this test guards against", peak, poolWorkers)
	}
	if peak == 0 {
		t.Fatal("peak concurrent in-flight wallet-http probes = 0, want > 0 -- no probe ever ran at all, this test isn't exercising the probe path")
	}

	close(release)

	// Drain: let whatever probes were actually running finish their (now
	// instant, since release is closed) RecordWalletSubmissionProbeResult call
	// before this test returns and newTestStore's t.Cleanup closes the DB pool
	// out from under them -- purely cosmetic (avoids harmless-but-noisy "closed
	// pool" log lines racing test teardown), not load-bearing for the assertion
	// above.
	time.Sleep(100 * time.Millisecond)
}
