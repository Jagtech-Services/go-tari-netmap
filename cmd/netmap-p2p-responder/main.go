// Command netmap-p2p-responder is a remote collector satellite: it does BOTH of
// go-tari-netmap's collector roles -- the passive inbound Tari P2P responder (Noise_XX
// handshake + identity exchange, advertising COMMUNICATION_NODE features + real addresses,
// see go-tari-lib/p2p's Serve/ResponderConfig, and serving get_peers over `t/dht/1`) AND the
// active peer-graph-walking/health-checking scanner (internal/collector's Collector, the same
// logic cmd/netmap's own binary runs) -- against a REMOTE storage.Store implementation
// (internal/remotestore) that talks to the central go-tari-netmap system over its HTTP API
// instead of ever holding a direct Postgres connection of its own. See this repo's governing
// remote-collector-satellite brief: ALL deployments of this binary, including previously
// on-LAN ones, use this remote-API-backed mode now -- no deployment of this binary holds a
// direct Postgres connection anymore; only the central cmd/netmap process does.
//
// This binary itself was originally introduced to supersede go-tari-lib's throwaway
// cmd/p2p-responder-spike/main.go (see BRIEF3.md): that binary stored everything in a plain
// in-memory map, so nothing survived a restart and nothing was queryable. It has since moved
// off a direct Postgres connection entirely (see internal/remotestore) in favor of reporting
// everything to the central system's HTTP API.
//
// # Advertised addresses
//
// A COMMUNICATION_NODE peer that advertises ZERO addresses is exactly the case a real Tari
// node's `comms/dht/src/peer_validator.rs` PeerHasNoAddresses/PeerHasNoUsableAddresses checks
// reject -- so this binary REQUIRES at least one advertised address via two optional CLI
// flags (at least one of which must be set, or this binary fails fast at startup rather than
// silently running unreachable):
//
//	-public-tcp-addr /ip4/<public-ip>/tcp/<port>   e.g. -public-tcp-addr /ip4/203.0.113.7/tcp/18189
//	-onion3-addr     /onion3/<addr>:<port>          e.g. -onion3-addr /onion3/abc...xyz:18189
//
// These same two addresses (converted to this repo's plain "host:port" storage convention,
// see selfAdvertisedAddresses) are also this collector's own self_identity, reported on every
// flush to the central API so it can tag the matching node row(s) tags.role = "collector" --
// see internal/remotestore's doc comment and internal/api/collector_report.go.
//
// # Central API connection (remote-collector mode)
//
// This binary always talks to the central system over HTTP, never Postgres directly:
//
//	-central-api-url / NETMAP_CENTRAL_API_URL     REQUIRED: the central system's API base URL,
//	                                                e.g. https://netmap.example.com/api
//	NETMAP_COLLECTOR_API_KEY (env var ONLY, no flag) REQUIRED: this collector's own API key
//	                                                (must match an entry in the central
//	                                                system's own NETMAP_COLLECTOR_KEYS) --
//	                                                deliberately NOT also accepted as a CLI
//	                                                flag, unlike the other two below: a flag's
//	                                                value is visible to any local user via
//	                                                `ps`/`/proc/<pid>/cmdline` and lands in
//	                                                shell history, which is exactly the
//	                                                exposure this repo's other secrets
//	                                                (NETMAP_DATABASE_URL, NETMAP_ADMIN_PASSWORD)
//	                                                already avoid by being env-var-only -- see
//	                                                this repo's readiness-review follow-up,
//	                                                Fix 7 / finding I34.
//	-collector-name  / NETMAP_COLLECTOR_NAME       REQUIRED: this collector's own name (e.g.
//	                                                "sydney") -- used only for this binary's own
//	                                                log messages, never sent over the wire (the
//	                                                central API identifies a collector by which
//	                                                configured key matched, not by a name field)
//
// A flag, if set, takes precedence over its corresponding env var; each env var is otherwise
// used as that flag's default, mirroring storage.DSNFromEnv's env-var convention elsewhere in
// this repo (this applies to -central-api-url/-collector-name only -- NETMAP_COLLECTOR_API_KEY
// has no flag counterpart at all, see above). All three fail fast at startup if neither the
// flag (where one exists) nor the env var provides a value.
//
// # Network flag (mainnet/testnet)
//
// This exact same binary is deployed unchanged to both a mainnet host and a testnet host, and
// both get scraped into a single shared Prometheus backend -- so every metric this binary
// exposes must be prefixed by which network produced it (see metrics.go's doc comment). The
// required -network flag (values: mainnet|testnet, no default) drives that prefix; this binary
// fails fast at startup if it's unset or an unrecognized value, mirroring the existing
// -public-tcp-addr/-onion3-addr fail-fast pattern above:
//
//	-network mainnet   e.g. on CT129
//	-network testnet    e.g. on CT132
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/flynn/noise"

	"github.com/Jagtech-Services/go-tari-lib/v3/p2p"

	"github.com/Jagtech-Services/go-tari-netmap/internal/remotestore"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("netmap-p2p-responder: %v", err)
	}
}

func run() error {
	var (
		addr          = flag.String("addr", ":18189", "TCP address to listen on (matches real Tari base node p2p port conventions by default)")
		keyPath       = flag.String("key", "", "path to a file holding our long-term Ristretto255 private key (32 raw bytes); if empty or the file doesn't exist, a fresh key is generated and, if -key was given, saved there for reuse across restarts")
		publicTCPAddr = flag.String("public-tcp-addr", "", "our own publicly-dialable clearnet multiaddr to advertise, e.g. /ip4/203.0.113.7/tcp/18189 (optional, but at least one of -public-tcp-addr/-onion3-addr is REQUIRED -- a COMMUNICATION_NODE peer with zero advertised addresses is rejected by real Tari nodes' peer validation)")
		onion3Addr    = flag.String("onion3-addr", "", "our own onion-v3 multiaddr to advertise, e.g. /onion3/<56-char-base32-addr>:18189 (optional, but at least one of -public-tcp-addr/-onion3-addr is REQUIRED, see -public-tcp-addr)")
		metricsAddr   = flag.String("metrics-addr", "", "address to serve Prometheus /metrics + /healthz on (default empty = disabled, opt-in like -public-tcp-addr/-onion3-addr). "+
			"CRITICAL: bind to an INTERNAL-ONLY address, e.g. 192.168.40.x:PORT or 127.0.0.1:PORT -- NEVER the public IP this binary also advertises via -public-tcp-addr. "+
			"If you set this at all, prefer a loopback-only address such as 127.0.0.1:9471; do NOT use a bare :PORT form (binds ALL interfaces, including the public one).")
		network = flag.String("network", "", "REQUIRED, no default: which Tari network this deployment monitors -- \"mainnet\" or \"testnet\". "+
			"Both networks' deployments of this exact same binary get scraped into one shared Prometheus backend, so every metric name this binary exposes is prefixed netmap_<network>_p2p_responder_... "+
			"(e.g. netmap_mainnet_p2p_responder_connections_accepted_total on the mainnet deployment). Fails fast at startup if unset or not exactly one of these two values.")

		// Remote-collector mode: this binary always talks to the central system over HTTP
		// (internal/remotestore), never a direct Postgres connection -- see this binary's
		// own doc comment for the full "Central API connection" section. -central-api-url/
		// -collector-name each default to their corresponding env var, so either works and
		// an explicit flag always wins if both are set, mirroring storage.DSNFromEnv's
		// env-var convention elsewhere in this repo.
		//
		// -collector-api-key is the one exception (see this repo's readiness-review
		// follow-up, Fix 7 / I34): the API key is deliberately NOT accepted as a plain flag
		// default/value -- a flag's value is visible to any local user via `ps`/
		// /proc/<pid>/cmdline and lands in shell history, unlike NETMAP_DATABASE_URL/
		// NETMAP_ADMIN_PASSWORD elsewhere in this repo, which are env-var-only for exactly
		// that reason. NETMAP_COLLECTOR_API_KEY (env var only) is required; there is no
		// -collector-api-key flag at all.
		centralAPIURL = flag.String("central-api-url", os.Getenv("NETMAP_CENTRAL_API_URL"), "REQUIRED (or NETMAP_CENTRAL_API_URL): the central go-tari-netmap system's API base URL, e.g. https://netmap.example.com/api")
		collectorName = flag.String("collector-name", os.Getenv("NETMAP_COLLECTOR_NAME"), "REQUIRED (or NETMAP_COLLECTOR_NAME): this collector's own name (e.g. \"sydney\") -- used only for this binary's own log messages, never sent over the wire")
	)
	flag.Parse()

	// collectorAPIKey is intentionally env-var-ONLY (see the flag block's own doc comment
	// above for why): NETMAP_COLLECTOR_API_KEY, sent as the X-Collector-Key header on every
	// report -- must match an entry in the central system's own NETMAP_COLLECTOR_KEYS.
	collectorAPIKey := os.Getenv("NETMAP_COLLECTOR_API_KEY")

	metrics, err := newResponderMetrics(*network)
	if err != nil {
		return err
	}

	ourAddresses, err := parseAdvertisedAddresses(*publicTCPAddr, *onion3Addr)
	if err != nil {
		return err
	}

	selfAddresses, err := selfAdvertisedAddresses(*publicTCPAddr, *onion3Addr)
	if err != nil {
		return err
	}

	if *centralAPIURL == "" {
		return fmt.Errorf("-central-api-url (or NETMAP_CENTRAL_API_URL) is required")
	}
	if collectorAPIKey == "" {
		return fmt.Errorf("NETMAP_COLLECTOR_API_KEY is required (env-var only, deliberately no -collector-api-key flag -- see this repo's readiness-review follow-up, Fix 7: a flag value is visible via ps/shell history)")
	}
	if *collectorName == "" {
		return fmt.Errorf("-collector-name (or NETMAP_COLLECTOR_NAME) is required")
	}

	staticKeypair, err := loadOrGenerateKeypair(*keyPath)
	if err != nil {
		return fmt.Errorf("setting up static keypair: %w", err)
	}
	log.Printf("main: our static public key: %x", staticKeypair.Public)
	log.Printf("main: advertising %d address(es): public-tcp=%q onion3=%q", len(ourAddresses), *publicTCPAddr, *onion3Addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remote-collector mode (see this binary's own doc comment): storage.Store is backed by
	// internal/remotestore, which talks to the central system's HTTP API -- this binary
	// never opens a direct Postgres connection, and never calls store.Migrate (schema
	// migrations are the central system's responsibility alone).
	//
	// onFlushResult (Fix 2, see this repo's readiness-review follow-up) wraps
	// metrics.onReportFlushResult (the counter-only half) with a poll of the *remotestore.
	// Store's own PendingRecordCount/LastSuccessfulFlushAt for the two gauges -- captured by
	// reference (var store *remotestore.Store, assigned below) since remotestore.New (which
	// needs this callback already built) necessarily runs BEFORE it returns the very Store
	// this callback needs to poll; by the time this callback is actually invoked (from
	// flushOnce, only after Run starts), store is always already assigned.
	var store *remotestore.Store
	onFlushResult := func(success bool) {
		metrics.onReportFlushResult(success)
		if store == nil {
			return
		}
		metrics.reportPendingRecords.Set(float64(store.PendingRecordCount()))
		if last := store.LastSuccessfulFlushAt(); !last.IsZero() {
			metrics.reportLastSuccessTimestamp.Set(float64(last.Unix()))
		}
	}
	store, err = remotestore.New(remotestore.Config{
		BaseURL:       *centralAPIURL,
		APIKey:        collectorAPIKey,
		CollectorName: *collectorName,
		SelfAddresses: selfAddresses,
		OnFlushResult: onFlushResult,
	})
	if err != nil {
		return fmt.Errorf("configuring remote store: %w", err)
	}
	defer store.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := store.Run(ctx); err != nil {
			log.Printf("main: remote store run error: %v", err)
		}
	}()

	// Active-scanner role: the same internal/collector.Collector logic cmd/netmap's own
	// binary runs, wired against the exact same remote store above -- mirroring
	// cmd/netmap/main.go's own collector wiring, minus anything Postgres-specific (there is
	// none left to remove beyond storage.New/store.Migrate, already absent above).
	activeScanner := newActiveScanner(store, metrics)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := activeScanner.Run(ctx); err != nil {
			log.Printf("main: active scanner run error: %v", err)
		}
	}()

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *addr, err)
	}
	defer listener.Close()
	log.Printf("main: listening on %s", listener.Addr())

	go func() {
		<-ctx.Done()
		log.Printf("main: shutting down")
		listener.Close()
	}()

	var metricsWG sync.WaitGroup
	if *metricsAddr != "" {
		// CRITICAL: this listener MUST be internal-only (see -metrics-addr's own help text
		// above) -- it is a completely separate net.Listener/http.Server from the P2P listener
		// above, bound to whatever address the operator configured. This binary does not
		// enforce or validate that the given address isn't the public one; that's on the
		// operator, per the flag's help text -- but never default *metricsAddr to a bare
		// ":PORT" form yourself, and never wire it to *publicTCPAddr/listener.Addr() by
		// accident. If you're reading this because you're about to change this call: binding
		// 0.0.0.0 (or a public IP) here exposes internal metrics -- including per-substream
		// protocol/DB-write detail -- to the same public network this responder's P2P port is
		// deliberately exposed to; that is NOT the intent of this flag.
		metricsListener, err := net.Listen("tcp", *metricsAddr)
		if err != nil {
			return fmt.Errorf("listening on -metrics-addr %s: %w", *metricsAddr, err)
		}
		metricsServer := newMetricsServer(store, metrics)
		log.Printf("main: serving /metrics and /healthz on %s (internal-only -- never expose this address publicly)", metricsListener.Addr())

		metricsWG.Add(1)
		go func() {
			defer metricsWG.Done()
			if err := metricsServer.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("main: metrics server error: %v", err)
			}
		}()

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = metricsServer.Shutdown(shutdownCtx)
		}()
	}

	responder := &dbBackedResponder{store: store, logf: log.Printf, metrics: metrics}

	// NOTE: go-tari-lib/v3 v3.1.0 (the tagged release this repo pins post-migration) does
	// NOT have OnConnectionAccepted/OnHandshakeResult/OnIdentityExchangeResult/
	// OnGetPeersServed/OnSubstreamProtocolDeclined on p2p.ResponderConfig at all -- those
	// hooks only ever existed on go-tari-lib's feat/db-backed-peer-list branch (commit
	// 5339107, "add observability callbacks to ResponderConfig"), which was never merged
	// into go-tari-lib's main and never released/tagged. metrics.onConnectionAccepted etc.
	// (metrics.go) and their matching netmap_<network>_p2p_responder_{connections_accepted,
	// handshake_result,identity_exchange_result,get_peers_served,get_peers_peer_count,
	// substream_protocol_declined}_total/_bucket series therefore can no longer be
	// incremented by this binary and will always read zero -- they remain registered (so
	// /metrics and existing dashboards don't break) pending go-tari-lib merging and tagging
	// a release of that branch. This is a genuine upstream capability loss surfaced by this
	// migration, not an intentional feature removal -- flag it back if these metrics are
	// relied on operationally.
	cfg := p2p.ResponderConfig{
		StaticKeypair:    staticKeypair,
		OurFeatures:      p2p.FeaturesCommunicationNode,
		OurAddresses:     ourAddresses,
		PeerListProvider: responder.peerListProvider,
		OnPeerIdentity:   responder.onPeerIdentity,
		Logf:             log.Printf,
	}

	err = p2p.Serve(ctx, listener, cfg)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("serving: %w", err)
	}
	log.Printf("main: responder loop exited cleanly")
	metricsWG.Wait()
	wg.Wait()
	return nil
}

// parseAdvertisedAddresses validates and encodes this binary's -public-tcp-addr/-onion3-addr
// flag values into the raw binary rust-multiaddr wire encoding p2p.ResponderConfig.OurAddresses
// expects (see go-tari-lib's p2p/multiaddr.go EncodeMultiaddrString doc comment for exactly why
// that, and not a UTF-8 string, is required). At least one of the two flags MUST be non-empty --
// fails fast with a clear error otherwise, rather than silently starting an unreachable
// COMMUNICATION_NODE peer (a real Tari node's comms/dht/src/peer_validator.rs
// PeerHasNoAddresses/PeerHasNoUsableAddresses checks reject a peer with zero advertised
// addresses).
func parseAdvertisedAddresses(publicTCPAddr, onion3Addr string) ([][]byte, error) {
	if publicTCPAddr == "" && onion3Addr == "" {
		return nil, fmt.Errorf("at least one of -public-tcp-addr or -onion3-addr must be set: a COMMUNICATION_NODE peer with no advertised addresses is rejected by real Tari nodes' peer validation and would start unreachable")
	}

	var out [][]byte
	if publicTCPAddr != "" {
		encoded, err := p2p.EncodeMultiaddrString(publicTCPAddr)
		if err != nil {
			return nil, fmt.Errorf("-public-tcp-addr %q: %w", publicTCPAddr, err)
		}
		out = append(out, encoded)
	}
	if onion3Addr != "" {
		encoded, err := p2p.EncodeMultiaddrString(onion3Addr)
		if err != nil {
			return nil, fmt.Errorf("-onion3-addr %q: %w", onion3Addr, err)
		}
		out = append(out, encoded)
	}
	return out, nil
}

// keyFileSize is the size, in bytes, of the file loadOrGenerateKeypair reads/writes: the 32-byte
// private scalar followed by the 32-byte public point, i.e. exactly noise.DHKey's two fields
// concatenated. Storing both (rather than just the private key and re-deriving the public key on
// load) avoids needing to export Ristretto255 scalar-base-multiplication from package p2p purely
// for this binary's key-persistence convenience.
const keyFileSize = 64

// loadOrGenerateKeypair loads a keypair from path (see keyFileSize) if path is non-empty and the
// file exists; otherwise it generates a fresh keypair and, if path is non-empty, saves it there
// (mode 0600) for reuse across restarts. An empty path always generates an ephemeral, unsaved
// keypair.
func loadOrGenerateKeypair(path string) (noise.DHKey, error) {
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			if len(raw) != keyFileSize {
				return noise.DHKey{}, fmt.Errorf("key file %s has %d bytes, want %d", path, len(raw), keyFileSize)
			}
			return noise.DHKey{
				Private: append([]byte(nil), raw[:32]...),
				Public:  append([]byte(nil), raw[32:]...),
			}, nil
		} else if !os.IsNotExist(err) {
			return noise.DHKey{}, fmt.Errorf("reading key file %s: %w", path, err)
		}
	}

	keypair, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("generating a fresh keypair: %w", err)
	}

	if path != "" {
		raw := append(append([]byte(nil), keypair.Private...), keypair.Public...)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return noise.DHKey{}, fmt.Errorf("saving fresh keypair to %s: %w", path, err)
		}
	}
	return keypair, nil
}
