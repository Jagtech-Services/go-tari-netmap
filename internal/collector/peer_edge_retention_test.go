package collector

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// TestPruneOldPeerEdgeObservationsDisabledNoop confirms PeerEdgeRetentionEnabled == false (the
// zero value, and the default for every existing caller/test) makes PruneOldPeerEdgeObservations
// a pure no-op that never even touches Storage -- mirroring RefreshGeoIP's nil-GeoIPClient
// no-op convention (see TestRefreshGeoIPNilClientNoop). Storage is deliberately left nil too:
// if PruneOldPeerEdgeObservations tried to touch it before checking PeerEdgeRetentionEnabled,
// this would panic.
func TestPruneOldPeerEdgeObservationsDisabledNoop(t *testing.T) {
	c := New(Config{})
	deleted, err := c.PruneOldPeerEdgeObservations(context.Background())
	if err != nil {
		t.Fatalf("PruneOldPeerEdgeObservations with PeerEdgeRetentionEnabled=false: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 (disabled loop must never touch Storage)", deleted)
	}
}

// TestPruneOldPeerEdgeObservationsRequiresStorage confirms enabling the loop without a
// configured Storage is a genuine misconfiguration error, not a silent no-op -- unlike the
// disabled case above (mirroring RefreshGeoIP's own Storage-nil-is-an-error-once-opted-in
// convention, see RefreshGeoIP's doc comment).
func TestPruneOldPeerEdgeObservationsRequiresStorage(t *testing.T) {
	c := New(Config{})
	c.PeerEdgeRetentionEnabled = true
	if _, err := c.PruneOldPeerEdgeObservations(context.Background()); err == nil {
		t.Fatal("expected an error with PeerEdgeRetentionEnabled=true and Storage unset, got nil")
	}
}

// TestPruneOldPeerEdgeObservationsDeletesOldRowsOnly is the end-to-end proof, against the real
// test Postgres store, that enabling the loop with a short retention window deletes only rows
// older than that window and reports the correct deleted count -- while a peer edge observed
// "now" (well within the window) survives. Backdating is done via a raw pgxpool connection
// (mirroring newTestStore's own truncate connection above) since storage.Store's public
// interface has no method for writing an arbitrary past observed_at directly.
func TestPruneOldPeerEdgeObservationsDeletesOldRowsOnly(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	a, err := store.UpsertDiscoveredNode(ctx, "collector-prune-a:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	b, err := store.UpsertDiscoveredNode(ctx, "collector-prune-b:2", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert b: %v", err)
	}

	// One "old" observation (backdated past the retention window below) and one "recent"
	// one (left at its real insert-time observed_at).
	if err := store.RecordPeerEdgeObservation(ctx, a.ID, b.ID); err != nil {
		t.Fatalf("record old edge observation: %v", err)
	}
	if err := store.RecordPeerEdgeObservation(ctx, a.ID, b.ID); err != nil {
		t.Fatalf("record recent edge observation: %v", err)
	}

	pool, err := pgxpool.New(ctx, testDSN())
	if err != nil {
		t.Fatalf("connect for backdate: %v", err)
	}
	defer pool.Close()

	backdateTo := time.Now().Add(-10 * 24 * time.Hour)
	tag, err := pool.Exec(ctx, `
		UPDATE peer_edge_observations
		SET observed_at = $1
		WHERE id = (
			SELECT id FROM peer_edge_observations
			WHERE from_node_id = $2 AND to_node_id = $3
			ORDER BY observed_at
			LIMIT 1
		)
	`, backdateTo, a.ID, b.ID)
	if err != nil {
		t.Fatalf("backdate old observation: %v", err)
	}
	if got := tag.RowsAffected(); got != 1 {
		t.Fatalf("backdated %d rows, want 1", got)
	}

	c := New(Config{})
	c.Storage = store
	c.PeerEdgeRetentionEnabled = true
	c.PeerEdgeObservationRetention = 24 * time.Hour

	deleted, err := c.PruneOldPeerEdgeObservations(ctx)
	if err != nil {
		t.Fatalf("PruneOldPeerEdgeObservations: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (only the backdated row)", deleted)
	}

	var remaining int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM peer_edge_observations WHERE from_node_id = $1 AND to_node_id = $2
	`, a.ID, b.ID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining rows = %d, want 1 (the recent row must survive)", remaining)
	}
}

// TestPruneOldPeerEdgeObservationsDefaultsRetentionWindow confirms leaving
// PeerEdgeObservationRetention unset falls back to defaultPeerEdgeObservationRetention (30
// days) rather than pruning everything (e.g. a bug that treated the zero value as "no
// retention at all" and deleted every row unconditionally) -- a peer edge observed moments ago
// must never be pruned by an enabled loop with default settings.
func TestPruneOldPeerEdgeObservationsDefaultsRetentionWindow(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	a, err := store.UpsertDiscoveredNode(ctx, "collector-prune-default-a:1", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	b, err := store.UpsertDiscoveredNode(ctx, "collector-prune-default-b:2", storage.DiscoverySourceP2P, nil, nil)
	if err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	if err := store.RecordPeerEdgeObservation(ctx, a.ID, b.ID); err != nil {
		t.Fatalf("record edge observation: %v", err)
	}

	c := New(Config{})
	c.Storage = store
	c.PeerEdgeRetentionEnabled = true
	// PeerEdgeObservationRetention deliberately left unset -- must default to
	// defaultPeerEdgeObservationRetention (30 days), not to "prune everything".

	deleted, err := c.PruneOldPeerEdgeObservations(ctx)
	if err != nil {
		t.Fatalf("PruneOldPeerEdgeObservations: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 (a just-recorded observation must survive the default 30-day window)", deleted)
	}
}
