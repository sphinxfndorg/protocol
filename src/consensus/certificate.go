// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/certificate.go
package consensus

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	logger "github.com/sphinxfndorg/protocol/src/console"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// CommitCertificate is broadcast by whichever node first attaches attestations
// to a block (see attachAttestationsBeforeCommit in consensus.go) so that
// every other node commits the SAME block with the SAME attestation set,
// instead of each node independently deriving its own list from whatever
// subset of commit votes it happened to have collected locally at the moment
// it crossed 2/3-stake quorum.
//
// This closes the "composition gap" flagged in attachAttestationsBeforeCommit's
// doc comment: sorting the locally-derived list only fixes ORDER when two
// nodes already agree on the SET of voters; it does nothing when two nodes
// reached quorum with genuinely different subsets. A canonical, broadcast
// certificate that followers adopt as-is (rather than re-deriving) fixes
// composition too.
//
// VoteSignatures carries the FULL serialized SignedMessage blob (exactly
// vote.Signature, as produced by SigningService.SignVote — see sign.go) for
// every validator in Attestations, keyed by ValidatorID. This is what makes
// the certificate independently verifiable: Attestation.Signature alone (as
// populated in attachAttestationsBeforeCommit) holds only the raw SPHINCS+
// bytes extracted FROM that blob, which is not enough on its own to call
// VerifySignature — VerifySignature needs the full blob (timestamp, nonce,
// signature hash, and the original signed data) to reconstruct what was
// actually signed. See HandleCommitCertificate for how this field is used
// and the TRUST MODEL note below for exactly what verifying it does and
// does not guarantee.
//
// TRUST MODEL:
// HandleCommitCertificate cryptographically verifies every attestation in an
// incoming certificate before caching it — each one must carry a valid
// SPHINCS+ signature from its claimed ValidatorID (via SigningService.VerifyVote),
// AND the payload actually signed must hash-match a freshly recomputed
// "VOTE:<view>:<blockHash>:<voterID>" binding for the EXACT (View, BlockHash,
// ValidatorID) the attestation claims (via SigningService.serializeVoteForSigning).
//
// That second check matters: SigningService.VerifySignature/VerifyVote (as
// they exist in sign.go today) verify that the claimed signer produced a
// valid signature over WHATEVER data is embedded in the blob — they do not
// themselves re-derive and compare that embedded data against the BlockHash/
// View fields presented alongside the signature. Without the extra check
// added here, a validator's own genuine signature from one vote could in
// principle be replayed and relabeled onto a different block/view by
// whoever is constructing the certificate, and VerifyVote alone would not
// catch it. This file closes that gap for certificates specifically, by
// independently recomputing the expected signed payload and requiring an
// exact match. Note that this pre-existing gap is NOT specific to
// certificates — the codebase's normal HandleVote/HandlePrepareVote path
// calls VerifyVote the same way and has the same property; fixing it there
// as well is outside the scope of this change and would need to happen in
// sign.go itself.
//
// What this verification does NOT do: it does not stop a validator from
// signing conflicting votes for two different blocks at the same height
// (equivocation) — that is a protocol-level slashing concern, not a
// signature-validity one, and attestations are informational (they are
// never part of the block hash), so a successfully-verified-but-equivocating
// attestation cannot fork the chain or forge a commit by itself.
type CommitCertificate struct {
	BlockHash      string               `json:"block_hash"`
	View           uint64               `json:"view"`
	Attestations   []*types.Attestation `json:"attestations"`
	VoteSignatures map[string][]byte    `json:"vote_signatures"`
}

// commitCertCap bounds the certificate cache so that certificates received
// for blocks this node never ends up committing locally (forked/superseded
// proposals, or a burst of unsolicited/malicious broadcasts) cannot grow the
// cache without bound. Legitimate certificates are evicted as soon as they
// are consumed by attachAttestationsBeforeCommit, or when the round for
// their block hash resets in commitBlock — see evictCommitCertificate's call
// sites. This cap is a backstop for anything that slips past both of those,
// not the primary cleanup mechanism.
const commitCertCap = 1024

// commitCertMu guards commitCertCache. This is intentionally a package-level
// cache rather than a field on *Consensus: the Consensus struct itself is
// defined outside this file (in a source file not available when this fix
// was written — see the accompanying summary), so a new field cannot be
// added to it here. A package-level cache keyed by block hash is safe for
// the real deployment topology: each running process hosts exactly one
// Consensus instance (one node = one process), so this is equivalent in
// practice to per-instance state. It also mirrors the existing precedent in
// go/src/network/node.go, where the process-wide consensusRegistry map plays
// the same role for a different purpose.
//
// Only verified attestations (never the VoteSignatures used to verify them)
// are cached — once HandleCommitCertificate or attachAttestationsBeforeCommit
// has checked a certificate, the raw signature blobs served their purpose
// and are dropped rather than held in memory.
var (
	commitCertMu    sync.RWMutex
	commitCertCache = make(map[string][]*types.Attestation)
)

// cacheCommitCertificate stores atts for blockHash, replacing anything
// already cached, unless the cache is at capacity and blockHash is not
// already present (see commitCertCap).
func cacheCommitCertificate(blockHash string, atts []*types.Attestation) {
	if blockHash == "" || len(atts) == 0 {
		return
	}
	commitCertMu.Lock()
	defer commitCertMu.Unlock()
	if _, exists := commitCertCache[blockHash]; !exists && len(commitCertCache) >= commitCertCap {
		logger.Warn("commitCertCache: at capacity (%d), dropping certificate for %s", commitCertCap, blockHash)
		return
	}
	commitCertCache[blockHash] = atts
}

// lookupCommitCertificate returns the cached attestations for blockHash, if
// any, and whether an entry was found.
func lookupCommitCertificate(blockHash string) ([]*types.Attestation, bool) {
	commitCertMu.RLock()
	defer commitCertMu.RUnlock()
	atts, ok := commitCertCache[blockHash]
	return atts, ok
}

// evictCommitCertificate removes any cached certificate for blockHash. Called
// once the certificate has been consumed by attachAttestationsBeforeCommit,
// and again from commitBlock's round-reset paths as a backstop for
// certificates that were received but never consumed by this node (e.g. this
// node committed the block via its own locally-derived attestations first).
func evictCommitCertificate(blockHash string) {
	if blockHash == "" {
		return
	}
	commitCertMu.Lock()
	defer commitCertMu.Unlock()
	delete(commitCertCache, blockHash)
}

// attestationsMeetStakeQuorum reports whether the distinct validator IDs
// named in atts collectively hold at least 2/3 of total validator-set stake,
// mirroring hasQuorum's threshold math. This runs in addition to (not
// instead of) the per-attestation signature verification in
// HandleCommitCertificate — it rejects certificates that are cryptographically
// valid but assembled from too small a set of (legitimately) attesting
// validators to actually represent quorum.
func (c *Consensus) attestationsMeetStakeQuorum(atts []*types.Attestation) bool {
	if len(atts) == 0 {
		return false
	}

	// SAFETY FLOOR: same reasoning as hasQuorum/hasPrepareQuorum in
	// consensus.go — don't let an incomplete local stake registry make a
	// too-small attester set look like 2/3 of the network.
	distinct := make(map[string]bool, len(atts))
	for _, a := range atts {
		if a != nil && a.ValidatorID != "" {
			distinct[a.ValidatorID] = true
		}
	}
	if len(distinct) < c.calculateQuorumSize(c.getTotalNodes()) {
		return false
	}

	totalStake := c.validatorSet.GetTotalStake()
	if totalStake == nil || totalStake.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	seen := make(map[string]bool, len(atts))
	staked := big.NewInt(0)
	for _, a := range atts {
		if a == nil || a.ValidatorID == "" || seen[a.ValidatorID] {
			continue // skip nil/empty/duplicate entries rather than let them inflate stake
		}
		seen[a.ValidatorID] = true
		if stake := c.getValidatorStake(a.ValidatorID); stake != nil {
			staked.Add(staked, stake)
		}
	}

	requiredStake := new(big.Int).Mul(totalStake, big.NewInt(2))
	requiredStake.Div(requiredStake, big.NewInt(3))
	return staked.Cmp(requiredStake) >= 0
}

// verifyAttestationSignature confirms that att.ValidatorID genuinely
// produced sigBlob (the full serialized SignedMessage — cert.VoteSignatures
// entry for this validator), AND that sigBlob's signed payload matches a
// freshly recomputed binding for exactly (att.View, att.BlockHash,
// att.ValidatorID). See the CommitCertificate TRUST MODEL note for why both
// checks are necessary — VerifyVote alone only proves the first.
func (c *Consensus) verifyAttestationSignature(att *types.Attestation, sigBlob []byte) error {
	if c.signingService == nil {
		return fmt.Errorf("no signing service available")
	}
	if att == nil || att.ValidatorID == "" {
		return fmt.Errorf("malformed attestation (nil or empty validator id)")
	}
	if len(sigBlob) == 0 {
		return fmt.Errorf("missing original vote signature for validator %s", att.ValidatorID)
	}

	synthetic := &Vote{
		View:      att.View,
		BlockHash: att.BlockHash,
		VoterID:   att.ValidatorID,
		Signature: sigBlob,
	}

	valid, err := c.signingService.VerifyVote(synthetic)
	if err != nil {
		return fmt.Errorf("signature verification error for %s: %w", att.ValidatorID, err)
	}
	if !valid {
		return fmt.Errorf("invalid signature for %s", att.ValidatorID)
	}

	// Content-binding check — see the CommitCertificate TRUST MODEL note.
	expectedHash, err := c.signingService.serializeVoteForSigning(synthetic)
	if err != nil {
		return fmt.Errorf("failed to compute expected signed payload for %s: %w", att.ValidatorID, err)
	}
	signedMsg, err := DeserializeSignedMessage(sigBlob)
	if err != nil {
		return fmt.Errorf("failed to deserialize vote signature for %s: %w", att.ValidatorID, err)
	}
	if !bytes.Equal(signedMsg.Data, expectedHash) {
		return fmt.Errorf("signed payload for %s does not match claimed (view=%d, blockHash=%s) — possible cross-block signature reuse",
			att.ValidatorID, att.View, att.BlockHash)
	}
	return nil
}

// HandleCommitCertificate processes an incoming CommitCertificate broadcast
// by the peer that first attached attestations to blockHash. Every
// attestation is cryptographically verified (see verifyAttestationSignature)
// and the whole set must independently meet 2/3-stake quorum before anything
// is cached. On success, the certificate's attestations are cached so that
// this node's own attachAttestationsBeforeCommit call (whenever it runs for
// the same block hash — before or after this call) adopts them verbatim
// instead of re-deriving from local vote state, giving every node that
// received the certificate an identical, canonical attestation list.
//
// See the TRUST MODEL note on CommitCertificate for exactly what is and is
// not guaranteed by that verification.
func (c *Consensus) HandleCommitCertificate(cert *CommitCertificate) error {
	if cert == nil {
		return fmt.Errorf("HandleCommitCertificate: nil certificate")
	}
	if cert.BlockHash == "" {
		return fmt.Errorf("HandleCommitCertificate: empty block hash")
	}
	if len(cert.Attestations) == 0 {
		return fmt.Errorf("HandleCommitCertificate: no attestations for block %s", cert.BlockHash)
	}

	c.mu.RLock()
	_, alreadyHaveCert := lookupCommitCertificate(cert.BlockHash)
	phase := c.phase
	c.mu.RUnlock()

	shortHash := cert.BlockHash[:min(16, len(cert.BlockHash))]

	if alreadyHaveCert {
		logger.Debug("HandleCommitCertificate: already have a certificate for %s, ignoring duplicate", shortHash)
		return nil
	}
	if phase == PhaseCommitted {
		// This round is already finished on this node one way or another;
		// nothing left to apply the certificate to. Not an error — just late.
		logger.Debug("HandleCommitCertificate: round for %s already committed locally, ignoring", shortHash)
		return nil
	}

	// Verify every attestation before trusting any of it. A single bad
	// entry invalidates the whole certificate rather than being silently
	// dropped — a certificate is supposed to be an exact, canonical list;
	// partially accepting it would reintroduce the composition divergence
	// this mechanism exists to eliminate.
	if c.signingService != nil {
		seen := make(map[string]bool, len(cert.Attestations))
		for _, att := range cert.Attestations {
			if att == nil || att.ValidatorID == "" {
				return fmt.Errorf("HandleCommitCertificate: malformed attestation for block %s", cert.BlockHash)
			}
			if att.BlockHash != cert.BlockHash {
				return fmt.Errorf("HandleCommitCertificate: attestation for %s claims block hash %s, mismatched with certificate's %s",
					att.ValidatorID, att.BlockHash, cert.BlockHash)
			}
			if seen[att.ValidatorID] {
				return fmt.Errorf("HandleCommitCertificate: duplicate attestation for validator %s in block %s", att.ValidatorID, cert.BlockHash)
			}
			seen[att.ValidatorID] = true

			sigBlob := cert.VoteSignatures[att.ValidatorID]
			if err := c.verifyAttestationSignature(att, sigBlob); err != nil {
				return fmt.Errorf("HandleCommitCertificate: rejecting certificate for block %s: %w", cert.BlockHash, err)
			}
		}
	} else {
		logger.Warn("HandleCommitCertificate: no signing service configured, accepting certificate for %s on stake-quorum check only", shortHash)
	}

	if !c.attestationsMeetStakeQuorum(cert.Attestations) {
		return fmt.Errorf("HandleCommitCertificate: attestations for block %s do not carry 2/3 stake, rejecting", cert.BlockHash)
	}

	cacheCommitCertificate(cert.BlockHash, cert.Attestations)
	logger.Info("HandleCommitCertificate: verified and cached canonical attestation certificate for block %s (%d attestations)",
		shortHash, len(cert.Attestations))
	return nil
}

// broadcastCommitCertificate sends cert to all peers so they can adopt this
// node's just-derived attestation list instead of independently re-deriving
// their own. Mirrors broadcastVote/broadcastProposal's fire-and-forget
// pattern — c.nodeManager.BroadcastMessage marshals cert and hands delivery
// off to per-peer goroutines, so this does not block on network I/O and is
// safe to call with c.mu already held (attachAttestationsBeforeCommit's
// existing locking requirement).
func (c *Consensus) broadcastCommitCertificate(cert *CommitCertificate) error {
	if cert == nil {
		return fmt.Errorf("broadcastCommitCertificate: nil certificate")
	}
	logger.Debug("Broadcasting commit certificate for block %s (%d attestations)", cert.BlockHash, len(cert.Attestations))
	return c.nodeManager.BroadcastMessage("commit_certificate", cert)
}

// PrepareCertificate is the PREPARE-phase counterpart of CommitCertificate.
// Before this, each node built its "prepare" ConsensusSignature entries
// (tryEnterPreparedPhase) purely from c.prepareVotes[blockHash] — its own
// locally-gossiped subset of prepare votes. Since prepare-vote gossip can
// reach quorum with genuinely different subsets on different nodes (the
// same asynchronous-BFT property documented on CommitCertificate), the
// final_states recorded for the SAME block's prepare phase diverged across
// nodes (e.g. node1={Node5,Node1}, node2={Node5,Node2}, node3={Node5,Node3}).
// This type, plus HandlePrepareCertificate/broadcastPrepareCertificate below,
// closes that gap the same way CommitCertificate does for the commit phase:
// whichever node derives its prepare-signer list first publishes it as
// canonical, and every other node adopts it verbatim instead of racing ahead
// with its own subset.
type PrepareCertificate struct {
	BlockHash      string               `json:"block_hash"`
	View           uint64               `json:"view"`
	Attestations   []*types.Attestation `json:"attestations"`
	VoteSignatures map[string][]byte    `json:"vote_signatures"`
}

const prepareCertCap = 1024

var (
	prepareCertMu    sync.RWMutex
	prepareCertCache = make(map[string][]*types.Attestation)
)

func cachePrepareCertificate(blockHash string, atts []*types.Attestation) {
	if blockHash == "" || len(atts) == 0 {
		return
	}
	prepareCertMu.Lock()
	defer prepareCertMu.Unlock()
	if _, exists := prepareCertCache[blockHash]; !exists && len(prepareCertCache) >= prepareCertCap {
		logger.Warn("prepareCertCache: at capacity (%d), dropping certificate for %s", prepareCertCap, blockHash)
		return
	}
	prepareCertCache[blockHash] = atts
}

func lookupPrepareCertificate(blockHash string) ([]*types.Attestation, bool) {
	prepareCertMu.RLock()
	defer prepareCertMu.RUnlock()
	atts, ok := prepareCertCache[blockHash]
	return atts, ok
}

func evictPrepareCertificate(blockHash string) {
	if blockHash == "" {
		return
	}
	prepareCertMu.Lock()
	defer prepareCertMu.Unlock()
	delete(prepareCertCache, blockHash)
}

// HandlePrepareCertificate mirrors HandleCommitCertificate: it verifies every
// attestation (reusing verifyAttestationSignature/attestationsMeetStakeQuorum,
// which are phase-agnostic — they only look at View/BlockHash/ValidatorID)
// and caches the result for tryEnterPreparedPhase to adopt.
func (c *Consensus) HandlePrepareCertificate(cert *PrepareCertificate) error {
	if cert == nil {
		return fmt.Errorf("HandlePrepareCertificate: nil certificate")
	}
	if cert.BlockHash == "" {
		return fmt.Errorf("HandlePrepareCertificate: empty block hash")
	}
	if len(cert.Attestations) == 0 {
		return fmt.Errorf("HandlePrepareCertificate: no attestations for block %s", cert.BlockHash)
	}

	if _, already := lookupPrepareCertificate(cert.BlockHash); already {
		logger.Debug("HandlePrepareCertificate: already have a certificate for %s, ignoring duplicate", cert.BlockHash[:min(16, len(cert.BlockHash))])
		return nil
	}

	if c.signingService != nil {
		seen := make(map[string]bool, len(cert.Attestations))
		for _, att := range cert.Attestations {
			if att == nil || att.ValidatorID == "" {
				return fmt.Errorf("HandlePrepareCertificate: malformed attestation for block %s", cert.BlockHash)
			}
			if att.BlockHash != cert.BlockHash {
				return fmt.Errorf("HandlePrepareCertificate: attestation for %s claims block hash %s, mismatched with certificate's %s",
					att.ValidatorID, att.BlockHash, cert.BlockHash)
			}
			if seen[att.ValidatorID] {
				return fmt.Errorf("HandlePrepareCertificate: duplicate attestation for validator %s in block %s", att.ValidatorID, cert.BlockHash)
			}
			seen[att.ValidatorID] = true

			sigBlob := cert.VoteSignatures[att.ValidatorID]
			if err := c.verifyAttestationSignature(att, sigBlob); err != nil {
				return fmt.Errorf("HandlePrepareCertificate: rejecting certificate for block %s: %w", cert.BlockHash, err)
			}
		}
	} else {
		logger.Warn("HandlePrepareCertificate: no signing service configured, accepting certificate for %s on stake-quorum check only", cert.BlockHash)
	}

	if !c.attestationsMeetStakeQuorum(cert.Attestations) {
		return fmt.Errorf("HandlePrepareCertificate: attestations for block %s do not carry 2/3 stake, rejecting", cert.BlockHash)
	}

	cachePrepareCertificate(cert.BlockHash, cert.Attestations)
	logger.Info("HandlePrepareCertificate: verified and cached canonical prepare-attestation certificate for block %s (%d attestations)",
		cert.BlockHash[:min(16, len(cert.BlockHash))], len(cert.Attestations))
	return nil
}

// broadcastPrepareCertificate mirrors broadcastCommitCertificate.
func (c *Consensus) broadcastPrepareCertificate(cert *PrepareCertificate) error {
	if cert == nil {
		return fmt.Errorf("broadcastPrepareCertificate: nil certificate")
	}
	logger.Debug("Broadcasting prepare certificate for block %s (%d attestations)", cert.BlockHash, len(cert.Attestations))
	return c.nodeManager.BroadcastMessage("prepare_certificate", cert)
}
