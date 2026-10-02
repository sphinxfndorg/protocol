// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// consensus/staking.go
package consensus

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	logger "github.com/sphinxfndorg/protocol/src/console"

	denom "github.com/sphinxfndorg/protocol/src/params/denom"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// sips0013 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0013/sips0013.md

const MaxValidatorSetSize = 100

// NewValidatorSet creates a validator set with minimum stake configuration.
func NewValidatorSet(minStakeAmount *big.Int) *ValidatorSet {
	if minStakeAmount == nil {
		panic("minStakeAmount cannot be nil - must be provided from chain parameters")
	}
	return &ValidatorSet{
		validators:     make(map[string]*StakedValidator),
		totalStake:     big.NewInt(0),
		minStakeAmount: minStakeAmount,
	}
}

// GetMinStakeAmount returns a copy of the minimum stake amount.
func (vs *ValidatorSet) GetMinStakeAmount() *big.Int {
	return new(big.Int).Set(vs.minStakeAmount)
}

// GetMinStakeSPX returns the minimum stake in SPX (human-readable).
func (vs *ValidatorSet) GetMinStakeSPX() uint64 {
	minSPX := new(big.Int).Div(vs.minStakeAmount, big.NewInt(1e18))
	return minSPX.Uint64()
}

// ---------------------------------------------------------------------------
// Genesis seeding — the ONLY path that creates live members
// ---------------------------------------------------------------------------

// AddGenesisValidator adds or updates a GENESIS member's stake, in nSPX.
//
// ★ WHY big.Int AND NOT SPX (Checkpoint 1b 1b). The previous signature took
// `stakeSPX uint64` and did `big.NewInt(int64(stakeSPX))`. That conversion
// wraps NEGATIVE for any stake above 2^63-1 SPX, and it also truncated stake to
// whole SPX before the comparison against the minimum. Both are silent
// corruption on a value that becomes a quorum denominator. nSPX is a *big.Int
// end to end here: no narrowing cast, no truncation.
//
// ★ WHY NO FREE MINIMUM (Checkpoint 1b 1a). The old code clamped a
// below-minimum stake UP to the minimum and returned nil. So
// AddValidator(id, 0) silently produced a full 32 SPX validator: a zero-cost
// seat. It now returns an error, and only an explicitly-authorised genesis
// seeding path can create a member at all.
//
// ★ GENESIS-ONLY (Checkpoint 1b 1d). Membership is chain state. This function
// mutates the live set with no activation epoch and no boundary, so it is
// restricted to genesis seeding (bind.seedGenesisValidators and
// initializePhase2Stakes) and is guarded at runtime by genesisSealed. Runtime
// admission goes through QueueValidator, which defers weight to a boundary.
func (vs *ValidatorSet) AddGenesisValidator(id string, stakeNSPX *big.Int) error {
	if id == "" {
		return fmt.Errorf("genesis validator: empty node ID")
	}
	if stakeNSPX == nil {
		return fmt.Errorf("genesis validator %s: nil stake", id)
	}
	if stakeNSPX.Sign() < 0 {
		return fmt.Errorf("genesis validator %s: negative stake %s", id, stakeNSPX.String())
	}
	// ★ 1a: a below-minimum or zero stake is an ERROR, never a silent grant.
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		return fmt.Errorf("genesis validator %s: stake %s is below the minimum %s",
			id, stakeNSPX.String(), vs.minStakeAmount.String())
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if vs.sealed {
		return fmt.Errorf("genesis validator %s: the set is sealed; membership can now only change at an epoch boundary", id)
	}

	if val, exists := vs.validators[id]; exists {
		if !vs.validatorCountsLocked(val) && vs.validatorCountLocked() >= MaxValidatorSetSize {
			return fmt.Errorf("genesis validator set is full (%d validators maximum)", MaxValidatorSetSize)
		}
		val.StakeAmount = new(big.Int).Set(stakeNSPX)
		val.ActivationEpoch = 0 // a genesis member is active from epoch 0
		logger.Info("Genesis validator %s stake set to %s", id, stakeNSPX.String())
		return nil
	}
	if vs.validatorCountLocked() >= MaxValidatorSetSize {
		return fmt.Errorf("genesis validator set is full (%d validators maximum)", MaxValidatorSetSize)
	}
	vs.validators[id] = &StakedValidator{
		ID:          id,
		StakeAmount: new(big.Int).Set(stakeNSPX),
		// ActivationEpoch 0 == active from genesis.
	}
	vs.rebuildTotalLocked(0)
	logger.Info("Genesis validator %s seeded with %s", id, stakeNSPX.String())
	return nil
}

// SealGenesis closes the set to genesis seeding. It is called once genesis
// seeding is complete, so no later code path can add a member immediately —
// from that point the only way into the set is QueueValidator (which defers
// weight to a boundary) or ProcessEpochTransition.
func (vs *ValidatorSet) SealGenesis() {
	vs.mu.Lock()
	vs.sealed = true
	vs.mu.Unlock()
	logger.Info("Validator set sealed: membership now changes only at epoch boundaries")
}

// Sealed reports whether the set has been closed to genesis seeding.
func (vs *ValidatorSet) Sealed() bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return vs.sealed
}

// QueueValidator admits a RUNTIME validator, deferring all weight to
// `activationEpoch`.
//
// This is the only path for a validator that is not in the genesis document.
// It records the stake but adds NOTHING to the total and NOTHING to the active
// set: weight arrives when ProcessEpochTransition rebuilds the total at the
// boundary, which is the same rebuild every other member goes through. A node
// admitted here is by definition still syncing, so granting it weight at
// admission would put an unvalidated node into the quorum denominator.
func (vs *ValidatorSet) QueueValidator(id string, stakeNSPX *big.Int, activationEpoch uint64) error {
	return vs.QueueValidatorWithRewardAddress(id, stakeNSPX, activationEpoch, "")
}

// QueueValidatorWithRewardAddress is QueueValidator plus the chain-state
// reward destination associated with the committed stake transaction.
func (vs *ValidatorSet) QueueValidatorWithRewardAddress(id string, stakeNSPX *big.Int, activationEpoch uint64, rewardAddress string) error {
	if id == "" {
		return fmt.Errorf("queued validator: empty node ID")
	}
	if stakeNSPX == nil {
		return fmt.Errorf("queued validator %s: nil stake", id)
	}
	if stakeNSPX.Sign() < 0 {
		return fmt.Errorf("queued validator %s: negative stake %s", id, stakeNSPX.String())
	}
	// ★ 1a: no free minimum here either.
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		return fmt.Errorf("queued validator %s: stake %s is below the minimum %s",
			id, stakeNSPX.String(), vs.minStakeAmount.String())
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[id]
	if (!exists || !vs.validatorCountsLocked(v)) && vs.validatorCountLocked() >= MaxValidatorSetSize {
		return fmt.Errorf("validator set is full (%d validators maximum); stake admission rejected", MaxValidatorSetSize)
	}
	if !exists {
		v = &StakedValidator{ID: id}
		vs.validators[id] = v
	}
	v.StakeAmount = new(big.Int).Set(stakeNSPX)
	v.ActivationEpoch = activationEpoch
	if rewardAddress != "" {
		v.RewardAddress = rewardAddress
	}
	// The total is deliberately NOT touched: this member is pending, and the
	// next ProcessEpochTransition rebuild will include it exactly when it
	// becomes active.
	logger.Info("Validator %s queued with %s nSPX, active from epoch %d", id, stakeNSPX.String(), activationEpoch)
	return nil
}

func (vs *ValidatorSet) validatorCountLocked() int {
	count := 0
	for _, validator := range vs.validators {
		if vs.validatorCountsLocked(validator) {
			count++
		}
	}
	return count
}

func (vs *ValidatorSet) validatorCountsLocked(validator *StakedValidator) bool {
	return validator != nil && !validator.IsSlashed && validator.StakeAmount != nil &&
		validator.StakeAmount.Sign() > 0 &&
		(validator.ExitEpoch == 0 || validator.ExitEpoch > vs.currentEpoch)
}

// QueueUnstake schedules a full validator exit at an epoch boundary.
func (vs *ValidatorSet) QueueUnstake(id string, exitEpoch uint64) error {
	if id == "" {
		return fmt.Errorf("queued unstake: empty validator ID")
	}
	vs.mu.Lock()
	defer vs.mu.Unlock()
	v := vs.validators[id]
	if v == nil || v.IsSlashed {
		return fmt.Errorf("queued unstake: validator %s is not active chain state", id)
	}
	if v.ActivationEpoch > vs.currentEpoch {
		return fmt.Errorf("queued unstake: validator %s is not active yet", id)
	}
	if exitEpoch <= vs.currentEpoch {
		return fmt.Errorf("queued unstake: exit epoch %d is not in the future", exitEpoch)
	}
	if v.ExitEpoch != 0 && v.ExitEpoch <= exitEpoch {
		return fmt.Errorf("queued unstake: validator %s already exits at epoch %d", id, v.ExitEpoch)
	}
	v.ExitEpoch = exitEpoch
	return nil
}

// rebuildTotalLocked recomputes vs.totalStake from members that count AT
// `epoch`: not slashed, not retired, and not still pending.
//
// ★ THIS IS THE ONLY WRITER of totalStake. It existed as a field mutated
// incrementally by four different functions, which is how a slashed or ejected
// validator could keep its full stake in the denominator (Checkpoint 1b 1c).
// Rebuilding is O(n) per epoch boundary, which is irrelevant next to signing a
// block, and it cannot drift.
//
// Callers must hold vs.mu.
func (vs *ValidatorSet) rebuildTotalLocked(epoch uint64) {
	total := big.NewInt(0)
	for _, v := range vs.validators {
		if v == nil || v.IsSlashed || v.StakeAmount == nil {
			continue
		}
		if v.ActivationEpoch > epoch {
			continue // still pending: no weight
		}
		if v.ExitEpoch != 0 && v.ExitEpoch <= epoch {
			continue // retired: no weight
		}
		total.Add(total, v.StakeAmount)
	}
	vs.totalStake = total
	// The epoch the total was computed AT. GetTotalStake() reads membership
	// against this same epoch, so the cached field and the live read can never
	// disagree about which epoch they mean.
	vs.currentEpoch = epoch
}

// IsValidStakeAmount checks if a stake amount meets the minimum requirement.
func (vs *ValidatorSet) IsValidStakeAmount(stakeNSPX *big.Int) bool {
	if stakeNSPX == nil {
		return false
	}
	return stakeNSPX.Cmp(vs.minStakeAmount) >= 0
}

// GetMinimumStakeInSPX returns the minimum stake in SPX as float64.
func (vs *ValidatorSet) GetMinimumStakeInSPX() float64 {
	minStakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(vs.minStakeAmount),
		new(big.Float).SetFloat64(denom.SPX),
	)
	result, _ := minStakeSPX.Float64()
	return result
}

// GetActiveValidators returns a sorted slice of validators active in epoch.
// Sort order is by validator ID (lexicographic) so every node producing the
// same slice is deterministic — required for consistent VDF slash tracking.
func (vs *ValidatorSet) GetActiveValidators(epoch uint64) []*StakedValidator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	active := make([]*StakedValidator, 0, len(vs.validators))
	for _, v := range vs.validators {
		if v.IsSlashed {
			continue
		}
		if v.ActivationEpoch > epoch {
			continue
		}
		if v.ExitEpoch != 0 && v.ExitEpoch <= epoch {
			continue
		}
		active = append(active, v)
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].ID < active[j].ID
	})

	return active
}

// GetValidators returns all validators in the set (for dashboard/status queries).
// This returns all validators regardless of epoch status.
func (vs *ValidatorSet) GetValidators() []*StakedValidator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	validators := make([]*StakedValidator, 0, len(vs.validators))
	for _, v := range vs.validators {
		validators = append(validators, v)
	}
	return validators
}

// ActiveValidatorIDs is a convenience wrapper used by the VDF epoch finaliser.
// It returns just the IDs of active validators for epoch, in the same
// deterministic order as GetActiveValidators.
func (vs *ValidatorSet) ActiveValidatorIDs(epoch uint64) []string {
	active := vs.GetActiveValidators(epoch)
	ids := make([]string, len(active))
	for i, v := range active {
		ids[i] = v.ID
	}
	return ids
}

// GetTotalStake returns total active stake in nSPX.
// GetTotalStake returns the stake that counts toward quorum RIGHT NOW: the sum
// of members that are active, not slashed and not retired as of the most recent
// epoch boundary.
//
// ★ 1c: it RECOMPUTES rather than returning the cached field. The field used to
// be maintained by four separate incremental updates, so a validator that was
// slashed or ejected after the last boundary kept its FULL stake in the
// denominator — inflating the threshold every honest node had to reach, and in
// the ejected case permanently. Recomputing over the members is O(n) on a
// read; n is the size of the validator set, and a read already walks it in
// GetActiveValidators, so this is not a new cost class.
//
// The epoch used is vs.currentEpoch, i.e. the last boundary actually
// processed. Membership between boundaries does not change (that is the whole
// point of boundary activation), so this is exact, not an approximation.
func (vs *ValidatorSet) GetTotalStake() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	total := big.NewInt(0)
	for _, v := range vs.validators {
		if v == nil || v.IsSlashed || v.StakeAmount == nil {
			continue
		}
		if v.ActivationEpoch > vs.currentEpoch {
			continue // pending
		}
		if v.ExitEpoch != 0 && v.ExitEpoch <= vs.currentEpoch {
			continue // ejected
		}
		total.Add(total, v.StakeAmount)
	}
	return total
}

// GetValidator returns the validator details mapped into core.StakedValidator.
//
// It is retained for the diagnostic and RPC paths that want a decoupled view.
// NOTE: block verification no longer calls this — it reads the snapshot's own
// rows directly, so a stale live view cannot influence what is accepted.
func (vs *ValidatorSet) GetValidator(id string) interface{} {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	v, exists := vs.validators[id]
	if !exists || v == nil {
		return nil
	}

	cs := &StakedValidator{ // reuse consensus.StakedValidator type
		ID:          v.ID,
		StakeAmount: new(big.Int).Set(v.StakeAmount),
		// remaining fields are ignored by callers that only need identity
	}

	if v.StakeAmount != nil {
		cs.StakeAmount = new(big.Int).Set(v.StakeAmount)
	} else {
		cs.StakeAmount = big.NewInt(0)
	}
	cs.ActivationEpoch = v.ActivationEpoch
	cs.ExitEpoch = v.ExitEpoch
	cs.IsSlashed = v.IsSlashed
	cs.LastAttested = v.LastAttested
	cs.RewardAddress = v.RewardAddress
	return cs
}

// GetStakeInSPX returns a validator's stake in SPX as float64.
func (v *StakedValidator) GetStakeInSPX() float64 {
	stakeSPX := new(big.Float).Quo(
		new(big.Float).SetInt(v.StakeAmount),
		new(big.Float).SetFloat64(denom.SPX),
	)
	result, _ := stakeSPX.Float64()
	return result
}

// GetValidatorSet returns this consensus instance's validator set.
func (c *Consensus) GetValidatorSet() *ValidatorSet {
	if c == nil {
		return nil
	}
	return c.validatorSet
}

// SlashValidator reduces a validator's stake by penaltyBps basis points
// and marks them slashed if their remaining stake drops below the minimum.
// penaltyBps: 100 = 1 %, 1000 = 10 %.
//
// The penalty amount is computed by the shared policy maths
// (policy.CalculateSlashingPenaltyBPS) so consensus and policy always agree
// on the economics; policy.SlashDowntimeBPS / SlashDoubleSignBPS /
// SlashLivenessBPS are the canonical rates.
//
// ★ THIS FUNCTION CURRENTLY HAS ZERO CALLERS, AND THAT IS THE POINT (Phase 1,
// decision 3). It is retained ONLY for the executor path that applies
// ON-CHAIN EVIDENCE at an epoch boundary. It must never be called from a
// consensus, VDF, or peer-observation path: slashing a validator because THIS
// node saw it miss a VDF submission makes the validator set a function of local
// observation, so two nodes reach different sets — and therefore different
// quorums — for the same height.
//
// TestNoLocalObservationSlashing in the consensus package enforces that no
// such caller is reintroduced.
func (vs *ValidatorSet) SlashValidator(id, reason string, penaltyBps uint64) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[id]
	if !exists {
		logger.Warn("SlashValidator: unknown validator %s", id)
		return
	}

	// Exact integer penalty — single source of truth in policy.
	penalty := policy.CalculateSlashingPenaltyBPS(v.StakeAmount, penaltyBps)
	if penalty.Sign() <= 0 {
		return
	}

	vs.totalStake.Sub(vs.totalStake, penalty)
	v.StakeAmount.Sub(v.StakeAmount, penalty)

	if v.StakeAmount.Cmp(vs.minStakeAmount) < 0 {
		v.IsSlashed = true
		logger.Warn("🔪 Validator %s SLASHED and ejected — reason: %s (stake now %.2f SPX)",
			id, reason, v.GetStakeInSPX())
	} else {
		logger.Warn("🔪 Validator %s slashed %.2f SPX — reason: %s (remaining %.2f SPX)",
			id, new(big.Float).Quo(
				new(big.Float).SetInt(penalty),
				new(big.Float).SetFloat64(denom.SPX),
			), reason, v.GetStakeInSPX())
	}
}

// ★ FinaliseEpochAndSlash HAS BEEN DELETED (Phase 1, decision 3).
//
// It tied RANDAO's VDF bookkeeping directly to SlashValidator, i.e. it let a
// node mutate the LIVE validator set from what that node happened to observe
// locally. Two nodes that saw different sets of VDF submissions at the same
// height would compute different validator sets, different totals, and
// different quorums for the same block — exactly the divergence the
// snapshot-based model exists to prevent.
//
// Slashing is now an EXECUTOR responsibility: an on-chain evidence record is
// what justifies it, it is applied at an epoch boundary through the same queue
// as Stake/Unstake, and every node applies the same evidence identically.
// The one remaining caller of SlashValidator must be that executor path.
//
// RANDAO.FinaliseEpoch survives for its bookkeeping only (recording who
// submitted, finalising the epoch, and the missed-set for observability). It
// no longer returns a slash list, so no caller can turn local observation into
// a stake mutation.

// UpdateStake sets a validator's stake to `stakeNSPX`.
//
// ★ 1b: the parameter is nSPX *big.Int, not SPX uint64. The old
// `stakeSPX uint64` -> `big.NewInt(int64(stakeSPX))` conversion wraps NEGATIVE
// above 2^63-1, and the whole-SPX truncation meant a 32.9-SPX stake compared as
// 32. Both are silent corruption of a quorum denominator.
//
// ★ The total is rebuilt, never adjusted incrementally: GetTotalStake()
// recomputes from membership, so keeping a parallel running total in sync was
// both redundant and the source of the drift this removes.
func (vs *ValidatorSet) UpdateStake(id string, stakeNSPX *big.Int) error {
	if stakeNSPX == nil {
		return fmt.Errorf("validator %s: nil stake", id)
	}
	// ★ 1a: zero or below-minimum is an ERROR, never a silent grant.
	if stakeNSPX.Sign() <= 0 {
		return fmt.Errorf("validator %s: stake %s is not positive", id, stakeNSPX.String())
	}
	if stakeNSPX.Cmp(vs.minStakeAmount) < 0 {
		return fmt.Errorf("validator %s: stake %s is below the minimum %s",
			id, stakeNSPX.String(), vs.minStakeAmount.String())
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[id]
	if !exists {
		return fmt.Errorf("validator %s not found", id)
	}
	old := new(big.Int).Set(v.StakeAmount)
	v.StakeAmount = new(big.Int).Set(stakeNSPX)
	vs.rebuildTotalLocked(vs.currentEpoch)
	logger.Info("Validator %s stake updated from %s to %s nSPX", id, old.String(), stakeNSPX.String())
	return nil
}

// SetStakeFromBalance sets a validator's stake from their actual balance
func (vs *ValidatorSet) SetStakeFromBalance(validatorID string, balanceNSPX *big.Int) error {
	// ★ 1a: NO FREE MINIMUM. The old body had two clamps — "balance < 1 SPX =>
	// use minimum" and "stake < min => use minimum" — so a ZERO balance, or any
	// dust balance, produced a full-stake validator and returned nil. A claim
	// that proves nothing could therefore buy a seat. Below-minimum is now an
	// error.
	if balanceNSPX == nil {
		return fmt.Errorf("validator %s: nil balance", validatorID)
	}
	if balanceNSPX.Sign() <= 0 {
		return fmt.Errorf("validator %s: balance %s is not positive", validatorID, balanceNSPX.String())
	}
	// ★ 1b: the comparison is against the balance in nSPX directly. The old
	// path truncated to whole SPX, compared that, then re-multiplied — so a
	// 32.9-SPX balance compared as 32 and a 1.5-SPX balance was treated as
	// below-minimum-then-clamped-up. big.Int end to end, no narrowing.
	if balanceNSPX.Cmp(vs.minStakeAmount) < 0 {
		return fmt.Errorf("validator %s: balance %s is below the minimum stake %s",
			validatorID, balanceNSPX.String(), vs.minStakeAmount.String())
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	v, exists := vs.validators[validatorID]
	if !exists {
		v = &StakedValidator{ID: validatorID}
		vs.validators[validatorID] = v
	}
	old := new(big.Int).Set(v.StakeAmount)
	v.StakeAmount = new(big.Int).Set(balanceNSPX)
	// Rebuild rather than adjust: the total is derived from membership, never
	// maintained in parallel.
	vs.rebuildTotalLocked(vs.currentEpoch)
	logger.Info("Validator %s stake set to %s nSPX from balance (was %s)",
		validatorID, balanceNSPX.String(), old.String())
	return nil
}

// SetStakeFromBalanceAtEpoch is SetStakeFromBalance for a validator that must
// NOT be able to vote immediately.
//
// ★ WHY THIS EXISTS. SetStakeFromBalance above credits the stake to
// vs.totalStake at once and leaves ActivationEpoch at 0, which reads as "active
// since genesis". For a GENESIS validator that is right. For a validator
// admitted at RUNTIME it is a stake-integrity hole: the node is by definition
// still syncing at the moment it is admitted, and it would immediately hold a
// full share of the quorum DENOMINATOR — voting on, and being weighted in, a
// tip it has not validated. It also inflates the denominator the rest of the
// set must reach, which is how a chain stalls rather than admits.
//
// So a runtime admitter passes an activation epoch strictly ahead of the
// current one, via ActivationEpochForStake(height) = height/EpochBlocks + 2.
// The node then has a full epoch to catch up, and gains weight only at a
// boundary, through the same ProcessEpochTransition rebuild every other member
// uses.
//
// The stake is recorded but deliberately NOT added to vs.totalStake here: the
// total is REBUILT from active membership at the next transition, and counting
// a pending validator early is precisely the incremental-update bug the rebuild
// exists to prevent.
func (vs *ValidatorSet) SetStakeFromBalanceAtEpoch(validatorID string, balanceNSPX *big.Int, activationEpoch uint64) error {
	// A member already in the set is being topped up, not admitted: it keeps
	// its existing activation, and the below-minimum check below still applies
	// to the new balance.
	vs.mu.RLock()
	_, preExisting := vs.validators[validatorID]
	vs.mu.RUnlock()

	if preExisting {
		if err := vs.SetStakeFromBalance(validatorID, balanceNSPX); err != nil {
			return err
		}
		return nil
	}

	// A new member is QUEUED, not admitted: no weight, no place in the
	// denominator, until ProcessEpochTransition rebuilds at its boundary.
	return vs.QueueValidator(validatorID, balanceNSPX, activationEpoch)
}

// BroadcastCheckpoint broadcasts the current checkpoint to all peers
func (c *Consensus) BroadcastCheckpoint() error {
	if c.blockChain == nil { // FIX: blockChain (not blockchain)
		return fmt.Errorf("blockchain not available")
	}

	// Get checkpoint from blockchain
	cp, err := c.blockChain.GetCheckpointMessage() // FIX: blockChain
	if err != nil {
		return fmt.Errorf("failed to get checkpoint: %w", err)
	}

	// Broadcast to all peers
	return c.nodeManager.BroadcastMessage("checkpoint", cp)
}

// HandleCheckpointMessage processes a checkpoint message from a peer
func (c *Consensus) HandleCheckpointMessage(data []byte, fromNodeID string) error {
	var cp CheckpointMessage
	if err := json.Unmarshal(data, &cp); err != nil {
		var encoded string
		if stringErr := json.Unmarshal(data, &encoded); stringErr != nil {
			return fmt.Errorf("failed to unmarshal checkpoint: %w", err)
		}
		if err := json.Unmarshal([]byte(encoded), &cp); err != nil {
			return fmt.Errorf("failed to unmarshal string-wrapped checkpoint: %w", err)
		}
	}

	logger.Info("Received checkpoint from %s: height=%d, phase=%s, supply=%s SPX",
		fromNodeID, cp.TipHeight, cp.Phase, cp.MintedSPX)

	if c.blockChain == nil { // FIX: blockChain
		return fmt.Errorf("blockchain not available")
	}

	// Check if peer is ahead. An empty late-joiner has no local chain to
	// compare against yet; the block-sync loop will install genesis first and a
	// later checkpoint will be handled normally.
	latest := c.blockChain.GetLatestBlock() // FIX: blockChain
	if latest == nil {
		logger.Debug("Ignoring checkpoint from %s until local genesis is installed", fromNodeID)
		return nil
	}
	if cp.TipHeight <= latest.GetHeight() {
		// Peer is not ahead or equal, ignore
		return nil
	}

	// Apply checkpoint to blockchain
	return c.blockChain.ApplyCheckpointFromPeer(&cp) // FIX: blockChain
}

// GetCheckpoint returns the current checkpoint message
func (c *Consensus) GetCheckpoint() (*CheckpointMessage, error) {
	if c.blockChain == nil { // FIX: blockChain
		return nil, fmt.Errorf("blockchain not available")
	}
	return c.blockChain.GetCheckpointMessage() // FIX: blockChain
}
