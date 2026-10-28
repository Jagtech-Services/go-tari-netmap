package api

import (
	"context"
	"log"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// probeSubmission runs a best-effort, non-blocking connectivity check
// against a freshly-submitted (still pending, unapproved) address and
// records ONLY reachability back onto the pending_submissions row via
// RecordSubmissionProbeResult. It must never write to node_health or
// nodes — this address hasn't been approved yet. Height/version/etc are
// deliberately discarded even if GetInfo returns them; only GetInfo's
// error-vs-success (and NodeInfo.Reachable, if present) matters here.
//
// It uses its own context.Background()-derived timeout rather than the
// originating HTTP request's context: that request's context is
// canceled once the response is written, but this probe is launched via
// `go probeSubmission(...)` specifically so it keeps running after the
// response has already returned to the caller.
func probeSubmission(store storage.Store, grpcClient, p2pClient collector.NodeClient, id uuid.UUID, address string) {
	ctx, cancel := context.WithTimeout(context.Background(), asyncCheckTimeout)
	defer cancel()

	reachable := false
	for _, client := range []collector.NodeClient{grpcClient, p2pClient} {
		if client == nil {
			continue
		}
		info, err := client.GetInfo(ctx, address)
		if err == nil && info.Reachable {
			reachable = true
			break
		}
	}

	if err := store.RecordSubmissionProbeResult(ctx, id, reachable); err != nil {
		log.Printf("api: record submission probe result for %s: %v", id, err)
	}
}
