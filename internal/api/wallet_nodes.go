package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/Jagtech-Services/go-tari-netmap/internal/collector"
	"github.com/Jagtech-Services/go-tari-netmap/internal/storage"
)

// createWalletNodeSubmissionRequest is the POST /wallet-nodes request body -- the SEPARATE,
// mainnet-only wallet-sync-HTTP-port registration flow (see
// storage.PendingWalletSubmission's doc comment and this feature's dispatch brief for the
// full rationale for why this is its OWN resource, not a field on createNodeRequest).
type createWalletNodeSubmissionRequest struct {
	// Host is the public IP being registered -- deliberately just the host, NOT
	// "host:port" (see PendingWalletSubmission.Host's doc comment): this flow links to
	// an already-known node purely by matching this value against that node's own known
	// address(es)' host part (see storage.Store.FindNodeByHost) -- the submitter never
	// needs to know/reference that node's internal id.
	Host string `json:"host"`

	// WalletHTTPPort is REQUIRED -- unlike the old, reworked-away bundled draft's
	// optional field on POST /nodes, this endpoint's entire purpose is registering this
	// port, so it is never optional here (see handleCreateWalletNodeSubmission's
	// validation, which rejects a missing/zero/out-of-range value with 400).
	WalletHTTPPort flexPort `json:"wallet_http_port"`
}

// handleCreateWalletNodeSubmission implements POST /wallet-nodes. Validation order (per
// this feature's dispatch brief):
//  1. wallet_http_port required, 1-65535 (never optional here, contrast createNodeRequest).
//  2. host must resolve (via storage.Store.FindNodeByHost) to an EXISTING node already
//     known to netmap -- this endpoint NEVER creates a new node record; if no matching
//     node exists, this is rejected with 404 (chosen over 409: there is no existing
//     wallet-node resource to conflict with -- the failure is "the thing you're trying to
//     attach this to doesn't exist", which is squarely what 404 means in this codebase's
//     existing convention, e.g. handleGetNode/handleGetPendingSubmission's own 404s for an
//     unknown id). This is directive #2's "link via public IP only" requirement enforced
//     at submission time, not just documentation.
//  3. Same SSRF-style host validation POST /nodes already applies (validateSubmittedHost)
//     -- defense-in-depth even though the host must already match a known node's own
//     recorded (already-validated-at-its-own-submission-time) address.
//  4. A best-effort, non-blocking, INFORMATIONAL-ONLY sanity probe is kicked off via `go`
//     (never awaited) -- for the admin reviewer's benefit only; this is NOT the
//     enforcement gate, see handleApproveWalletSubmission for that.
//
// Reuses the SAME limiter/lockouts instances POST /nodes already uses (see NewRouter) --
// deliberately not a second, independently-configured rate limiter for a
// similar-risk-profile public write route.
func handleCreateWalletNodeSubmission(store storage.Store, walletHTTPClient collector.NodeClient, limiter *ipRateLimiter, lockouts *invalidSubmissionTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createWalletNodeSubmissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}

		ip := clientIP(r)

		if locked, remaining := lockouts.IsLockedOut(ip); locked {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
			writeError(w, http.StatusTooManyRequests, errors.New("this source has been temporarily blocked after repeated invalid submissions"))
			return
		}

		if !limiter.Allow(ip) {
			w.Header().Set("Retry-After", "3600")
			writeError(w, http.StatusTooManyRequests, errors.New("too many submissions from this source, try again later"))
			return
		}

		// (1) wallet_http_port required, 1-65535 -- NEVER optional here, see this
		// handler's doc comment.
		if req.WalletHTTPPort < 1 || req.WalletHTTPPort > 65535 {
			lockouts.RecordInvalidStrike(ip)
			writeError(w, http.StatusBadRequest, errors.New("wallet_http_port is required and must be between 1 and 65535"))
			return
		}
		walletHTTPPort := int(req.WalletHTTPPort)

		if req.Host == "" {
			lockouts.RecordInvalidStrike(ip)
			writeError(w, http.StatusBadRequest, errors.New("host is required"))
			return
		}

		// (3) SSRF-style host validation -- see this handler's doc comment for why this
		// runs even though step (2) below additionally requires a match against an
		// already-known (and thus already-once-validated) node's own address.
		if err := validateSubmittedHost(req.Host); err != nil {
			lockouts.RecordInvalidStrike(ip)
			writeError(w, http.StatusBadRequest, err)
			return
		}

		// (2) host must resolve to an existing node -- this endpoint never creates one.
		_, found, err := store.FindNodeByHost(r.Context(), req.Host)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			// A well-formed submission for a host netmap simply doesn't know about
			// yet is not a malicious/malformed-input signal (mirrors
			// handleCreateNode's IsAddressPubliclyOptedIn 409 case, which also
			// doesn't record an invalid strike for a well-formed-but-conflicting
			// submission) -- no lockouts.RecordInvalidStrike here.
			writeError(w, http.StatusNotFound, errors.New("host does not match any node already known to netmap -- register the base node first via POST /nodes"))
			return
		}

		submission, err := store.CreatePendingWalletSubmission(r.Context(), req.Host, walletHTTPPort)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// (4) Best-effort, non-blocking, informational-only probe -- launched via `go`
		// and never awaited, mirroring probeSubmission's exact pattern (own
		// context.Background()-derived timeout, since r.Context() is canceled once this
		// handler returns). NOT the enforcement gate -- see handleApproveWalletSubmission.
		go probeWalletSubmission(store, walletHTTPClient, submission.ID, req.Host, walletHTTPPort)

		writeJSON(w, http.StatusAccepted, submission)
	}
}

// probeWalletSubmission mirrors probeSubmission's exact shape (internal/api/probe.go) but
// for the wallet-node registration queue: a best-effort, non-blocking connectivity check
// against a freshly-submitted (still pending, unapproved) host:port, recording ONLY
// reachability back onto the pending_wallet_submissions row via
// store.RecordWalletSubmissionProbeResult. This is informational only, for the admin
// reviewer's benefit -- it must never write to node_health/nodes, and it is NOT the
// approval-gating probe (see handleApproveWalletSubmission for that, which runs its OWN
// synchronous probe rather than trusting this one's result, since the queue may have sat
// for a while and conditions may have changed).
func probeWalletSubmission(store storage.Store, walletHTTPClient collector.NodeClient, id uuid.UUID, host string, port int) {
	if walletHTTPClient == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), asyncCheckTimeout)
	defer cancel()

	target := net.JoinHostPort(host, strconv.Itoa(port))
	info, err := walletHTTPClient.GetInfo(ctx, target)
	reachable := err == nil && info.Reachable

	if err := store.RecordWalletSubmissionProbeResult(ctx, id, reachable); err != nil {
		log.Printf("api: record wallet submission probe result for %s: %v", id, err)
	}
}

func handleListWalletSubmissions(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")

		submissions, err := store.ListPendingWalletSubmissions(r.Context(), status)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, submissions)
	}
}

// approveWalletSubmissionResponse is the POST /admin/wallet-submissions/{id}/approve
// response body: the resulting node (with its now-set WalletHTTPPort) alongside the
// now-approved submission.
type approveWalletSubmissionResponse struct {
	Node       storage.Node                    `json:"node"`
	Submission storage.PendingWalletSubmission `json:"submission"`
}

// errWalletSanityProbeFailed wraps every "the approval-gating sanity probe did not
// succeed" error returned by handleApproveWalletSubmission -- a single, greppable sentinel
// distinguishing this specific, expected-to-happen-sometimes rejection reason from any
// other internal error in this handler, for callers/tests that want to assert on it via
// errors.Is rather than string-matching.
var errWalletSanityProbeFailed = errors.New("api: wallet-http sanity probe failed")

// handleApproveWalletSubmission implements POST /admin/wallet-submissions/{id}/approve --
// this is the REAL "sanity checker" this feature's dispatch brief (operator directive #3)
// asks for: ACTIVE, SYNCHRONOUS verification of an EXPLICITLY, manually-submitted port,
// gating approval -- never automatic discovery of a value nobody submitted (see
// storage.Node.WalletHTTPPort's doc comment for the hard, non-negotiable rule this upholds
// in full).
//
// Steps, in order:
//  1. Re-resolve the target node by host (storage.Store.FindNodeByHost) -- NOT a cached
//     node id from submission time; the node set may have changed since (e.g. the node was
//     merged into a different id via a later pubkey confirmation) -- if the host no longer
//     resolves to any node at all, this is a 409 Conflict (mirrors handleApproveSubmission's
//     own "state changed since submission, leave it pending for a human to decide" 409 for
//     the IsAddressPubliclyOptedIn re-check -- NOT a 404, since unlike submission time this
//     is re-validating an ALREADY-ACCEPTED submission's precondition, not validating a new
//     one).
//  2. SYNCHRONOUSLY call walletHTTPClient.GetInfo against host:wallet_http_port (bounded by
//     asyncCheckTimeout, same convention as every other bounded probe in this file). A
//     dial error, non-200, bad decode, OR a response with Reachable == false is ALL treated
//     as probe failure -- the approval is REJECTED (409, wrapping errWalletSanityProbeFailed)
//     with a clear message. NOTHING is written to the submission or the node on this path:
//     the row stays exactly 'pending', ready for the admin to retry later or reject it
//     outright.
//  3. ONLY on a successful probe: store.SetNodeWalletHTTPPort writes the port onto the
//     node, and store.ApprovePendingWalletSubmission marks the submission approved AND
//     records the "permissions matrix" outcome fields in the SAME call.
func handleApproveWalletSubmission(store storage.Store, walletHTTPClient collector.NodeClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid submission id"))
			return
		}

		submission, err := store.GetPendingWalletSubmission(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, errors.New("wallet submission not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if submission.Status != storage.SubmissionStatusPending {
			writeError(w, http.StatusConflict, fmt.Errorf("wallet submission already reviewed (status=%s)", submission.Status))
			return
		}

		// Step 1: re-resolve by host, never trust a cached node id.
		node, found, err := store.FindNodeByHost(r.Context(), submission.Host)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusConflict, fmt.Errorf("host %s no longer matches any known node -- reject this submission instead of approving it", submission.Host))
			return
		}

		// Step 2: SYNCHRONOUS sanity probe -- the hard precondition for approval.
		if walletHTTPClient == nil {
			writeError(w, http.StatusInternalServerError, errors.New("wallet-http probe client is not configured"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), asyncCheckTimeout)
		defer cancel()

		target := net.JoinHostPort(submission.Host, strconv.Itoa(submission.WalletHTTPPort))
		info, probeErr := walletHTTPClient.GetInfo(ctx, target)
		if probeErr != nil {
			writeError(w, http.StatusConflict, fmt.Errorf("%w: %v", errWalletSanityProbeFailed, probeErr))
			return
		}
		if !info.Reachable {
			writeError(w, http.StatusConflict, fmt.Errorf("%w: endpoint responded but reported unreachable", errWalletSanityProbeFailed))
			return
		}

		// Step 3: only now, after a successful probe, is anything written.
		port := submission.WalletHTTPPort
		if err := store.SetNodeWalletHTTPPort(r.Context(), node.ID, &port); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		node.WalletHTTPPort = &port

		outcome := storage.WalletProbeOutcome{Height: info.Height}
		if info.IsSynced != nil {
			outcome.IsSynced = *info.IsSynced
		}
		if err := store.ApprovePendingWalletSubmission(r.Context(), id, node.ID, outcome); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		submission.Status = storage.SubmissionStatusApproved
		submission.PromotedNodeID = &node.ID
		probeSucceeded := true
		submission.ProbeSucceeded = &probeSucceeded
		now := time.Now()
		submission.ProbeCheckedAt = &now
		submission.ProbeIsSynced = &outcome.IsSynced
		submission.ProbeHeight = outcome.Height

		writeJSON(w, http.StatusOK, approveWalletSubmissionResponse{Node: node, Submission: submission})
	}
}

// rejectWalletSubmissionRequest is the optional POST /admin/wallet-submissions/{id}/reject
// request body -- mirrors rejectSubmissionRequest exactly.
type rejectWalletSubmissionRequest struct {
	Reason string `json:"reason"`
}

func handleRejectWalletSubmission(store storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid submission id"))
			return
		}

		var req rejectWalletSubmissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}

		submission, err := store.GetPendingWalletSubmission(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, errors.New("wallet submission not found"))
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if submission.Status != storage.SubmissionStatusPending {
			writeError(w, http.StatusConflict, fmt.Errorf("wallet submission already reviewed (status=%s)", submission.Status))
			return
		}

		var reason *string
		if req.Reason != "" {
			reason = &req.Reason
		}
		if err := store.RejectPendingWalletSubmission(r.Context(), id, reason); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		submission.Status = storage.SubmissionStatusRejected
		submission.RejectionReason = reason

		writeJSON(w, http.StatusOK, submission)
	}
}
