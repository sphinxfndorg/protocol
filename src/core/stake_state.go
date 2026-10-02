// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/stake_state.go
package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

const (
	stakeQueueKey             = "protocol:stake_queue"
	validatorIdentityPrefix   = "protocol:validator_identity:"
	missedRoundPrefix         = "protocol:missed_rounds:"
	validatorPausePrefix      = "protocol:validator_pause_epoch:"
	stakeOwnerKeyPrefix       = "protocol:stake_owner:"
	stakePublicKeyPrefix      = "protocol:validator_public_key:"
	slashingEvidenceKeyPrefix = "protocol:slashing_evidence:"
	genesisStakeEscrowKey     = "protocol:genesis_stake_escrowed:"
	pendingWithdrawalPrefix   = "protocol:pending_withdrawal:"
	// operatorKeyIndexPrefix is a REVERSE INDEX: hash(operator key) -> validator
	// ID. It exists so operator-key uniqueness is one lookup at admission rather
	// than a scan over every identity, which would be the wrong shape on the hot
	// path. The reservation is permanent (see reserveOperatorKey) so a replayed
	// snapshot can never observe one key mapping to two validator IDs.
	operatorKeyIndexPrefix = "protocol:operator_key_index:"
)

// OperatorPublicKeyLength is the exact byte length of a serialized SPHINCS+
// public key. Genesis has always required it (GenesisStateFile.Validate); this
// constant is the single definition both paths now use, so admission and
// genesis cannot disagree about what a well-formed key is.
const OperatorPublicKeyLength = 32

// operatorKeyIndexKey is the reverse-index slot for a public key. The key is
// hashed rather than stored raw so the index does not duplicate the full key
// material a second time, and so a malformed key can never be used as a
// composite key fragment.
func operatorKeyIndexKey(publicKey []byte) string {
	return operatorKeyIndexPrefix + hex.EncodeToString(common.SpxHash(publicKey))
}

const DowntimePauseMisses uint64 = 5

const (
	MaxEvidenceAgeEpochs uint64 = 2
	UnbondingEpochs      uint64 = 3
)

var ErrNoPendingWithdrawal = errors.New("validator has no pending withdrawal")

type queuedStakeChange struct {
	Action          string `json:"action"`
	ValidatorID     string `json:"validator_id"`
	Owner           string `json:"owner"`
	PublicKey       string `json:"public_key,omitempty"`
	AmountNSPX      string `json:"amount_nspx"`
	ActivationEpoch uint64 `json:"activation_epoch"`
}

type pendingWithdrawal struct {
	ValidatorID  string `json:"validator_id"`
	Owner        string `json:"owner"`
	AmountNSPX   string `json:"amount_nspx"`
	ReleaseEpoch uint64 `json:"release_epoch"`
}

type validatorIdentity struct {
	OwnerAddress      string `json:"owner_address,omitempty"`
	OperatorPublicKey string `json:"operator_public_key,omitempty"`
}

// reserveOperatorKey claims publicKey for validatorID, and is the single
// uniqueness gate for operator keys.
//
// ★ IT MUST BE CALLED AT QUEUE TIME, not at activation. Activation is deferred
// to the e+2 boundary, so reserving there would leave a window in which two
// Stake transactions carrying the same key could both be accepted into the
// queue and only collide later — after the sender was told it succeeded.
//
// ★ THE RESERVATION IS PERMANENT. It is not released on exit. An exited
// validator's identity record survives (getValidatorIdentity still resolves it,
// and later-epoch snapshots and replays still reference it), so releasing the
// key would let a second validator claim it and produce a state where one key
// maps to two validator IDs — exactly the ambiguity attestation verification
// depends on not existing.
//
// Re-admitting the SAME validator with the SAME key is idempotent and allowed:
// that is the re-stake-after-exit case, and it must not be a permanent ban.
func (s *StateDB) reserveOperatorKey(validatorID string, publicKey []byte) error {
	if validatorID == "" {
		return fmt.Errorf("operator key reservation: empty validator ID")
	}
	if len(publicKey) != OperatorPublicKeyLength {
		return fmt.Errorf("validator %s: operator public key is %d bytes, want exactly %d",
			validatorID, len(publicKey), OperatorPublicKeyLength)
	}
	indexKey := operatorKeyIndexKey(publicKey)
	raw, err := s.GetContractValue(indexKey)
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("read operator key index for %s: %w", validatorID, err)
	}
	if err == nil && len(raw) > 0 {
		if owner := string(raw); owner != validatorID {
			return fmt.Errorf("operator key is already registered to validator %s and cannot also be registered to %s",
				owner, validatorID)
		}
		return nil // same validator, same key: idempotent re-reservation
	}
	s.SetContractValue(indexKey, []byte(validatorID))
	return nil
}

// setValidatorIdentity writes the owner/operator pair for a validator.
//
// ★ C2a. The operator key must be exactly OperatorPublicKeyLength. This path
// previously accepted any non-empty key, while genesis required 32 — so a
// malformed key could be admitted and then fail every later replay for
// everyone. Both paths now use one constant.
//
// ★ C4. The operator key is IMMUTABLE once recorded, and the owner may change
// only while the validator holds no live stake. A blanket "refuse if an
// identity exists" would permanently bar a validator ID from re-staking after
// exit, because the identity record deliberately outlives the stake. So:
//   - same ID + same key  -> accepted (idempotent re-stake)
//   - same ID + new key   -> rejected
//   - owner change       -> only when there is no queued, active or pending
//     withdrawal stake
//
// Callers that validate the whole transaction (admission) should have reserved
// the key first, so a rejected transaction leaves no index write behind.
func (s *StateDB) setValidatorIdentity(validatorID, ownerAddress string, operatorPublicKey []byte) error {
	if validatorID == "" || ownerAddress == "" {
		return fmt.Errorf("validator identity requires validator ID and owner address")
	}
	if len(operatorPublicKey) != OperatorPublicKeyLength {
		return fmt.Errorf("validator %s: operator public key is %d bytes, want exactly %d",
			validatorID, len(operatorPublicKey), OperatorPublicKeyLength)
	}
	existing, err := s.getValidatorIdentity(validatorID)
	if err != nil {
		return fmt.Errorf("validator %s: read existing identity: %w", validatorID, err)
	}
	if existing.OperatorPublicKey != "" {
		if existing.OperatorPublicKey != hex.EncodeToString(operatorPublicKey) {
			return fmt.Errorf("validator %s: operator key is immutable once admitted (recorded %s)",
				validatorID, existing.OperatorPublicKey)
		}
		if existing.OwnerAddress != ownerAddress {
			live, err := s.validatorHasLiveStake(validatorID)
			if err != nil {
				return fmt.Errorf("validator %s: check live stake before owner change: %w", validatorID, err)
			}
			if live {
				return fmt.Errorf("validator %s: owner may not change while the validator has live stake", validatorID)
			}
		}
	}
	if err := s.reserveOperatorKey(validatorID, operatorPublicKey); err != nil {
		return err
	}
	identity := validatorIdentity{
		OwnerAddress:      ownerAddress,
		OperatorPublicKey: hex.EncodeToString(operatorPublicKey),
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("encode validator identity for %s: %w", validatorID, err)
	}
	s.SetContractValue(validatorIdentityPrefix+validatorID, data)
	s.SetContractValue(stakeOwnerKeyPrefix+validatorID, []byte(ownerAddress))
	s.SetContractValue(stakePublicKeyPrefix+validatorID, operatorPublicKey)
	return nil
}

// validatorHasLiveStake reports whether a validator currently holds a
// position: active stake, a queued stake change, or a pending withdrawal.
// "Live" is what gates an owner change, because all three mean the existing
// owner still has something at risk.
func (s *StateDB) validatorHasLiveStake(validatorID string) (bool, error) {
	if stake, err := s.GetValidatorStake(validatorID); err == nil && stake != nil && stake.Sign() > 0 {
		return true, nil
	} else if err != nil && !errors.Is(err, database.ErrNotFound) {
		return false, fmt.Errorf("read active stake for %s: %w", validatorID, err)
	}
	if _, err := s.GetContractValue(pendingWithdrawalPrefix + validatorID); err == nil {
		return true, nil
	} else if err != nil && !errors.Is(err, database.ErrNotFound) {
		return false, fmt.Errorf("read pending withdrawal for %s: %w", validatorID, err)
	}
	queue, err := s.readStakeQueue()
	if err != nil {
		return false, err
	}
	for _, change := range queue {
		if change.ValidatorID == validatorID {
			return true, nil
		}
	}
	return false, nil
}

func (s *StateDB) getValidatorIdentity(validatorID string) (*validatorIdentity, error) {
	if validatorID == "" {
		return nil, fmt.Errorf("validator ID is empty")
	}
	identity := &validatorIdentity{}
	data, err := s.GetContractValue(validatorIdentityPrefix + validatorID)
	if err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, identity); err != nil {
			return nil, fmt.Errorf("decode validator identity for %s: %w", validatorID, err)
		}
		if identity.OperatorPublicKey != "" {
			if _, err := hex.DecodeString(identity.OperatorPublicKey); err != nil {
				return nil, fmt.Errorf("validator identity for %s has invalid operator key: %w", validatorID, err)
			}
		}
	} else if err != nil && !errors.Is(err, database.ErrNotFound) {
		return nil, fmt.Errorf("read validator identity for %s: %w", validatorID, err)
	}
	if identity.OwnerAddress == "" {
		owner, err := s.GetContractValue(stakeOwnerKeyPrefix + validatorID)
		if err == nil {
			identity.OwnerAddress = string(owner)
		} else if !errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("read legacy stake owner for %s: %w", validatorID, err)
		}
	}
	if identity.OperatorPublicKey == "" {
		publicKey, err := s.GetContractValue(stakePublicKeyPrefix + validatorID)
		if err == nil {
			identity.OperatorPublicKey = hex.EncodeToString(publicKey)
		} else if !errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("read legacy operator key for %s: %w", validatorID, err)
		}
	}
	if identity.OperatorPublicKey != "" {
		if _, err := hex.DecodeString(identity.OperatorPublicKey); err != nil {
			return nil, fmt.Errorf("validator identity for %s has invalid operator key: %w", validatorID, err)
		}
	}
	return identity, nil
}

func missedRoundKey(epoch uint64, validatorID string) string {
	return missedRoundPrefix + strconv.FormatUint(epoch, 10) + ":" + validatorID
}

// applyMissedRoundPolicy is DISABLED, and deliberately so.
//
// ★ WHY IT IS OFF. It previously derived a miss from a validator's ABSENCE
// from block.Body.Attestations. That is forgeable and proposer-controlled, in
// two independent ways:
//
//  1. Malicious. The proposer builds Body.Attestations from its own collected
//     vote map (consensus.go attachAttestationsBeforeCommit) and needs only
//     2f+1 to reach quorum. In a 4-validator set it can include 3 and omit a
//     targeted honest validator, charging that validator a miss it never
//     earned. Repeat over 5 blocks and the target is paused.
//
//  2. WITHOUT any malice, which is the worse case. PBFT requires a validator's
//     own vote inside the 3-votes-in-cutoff window. The slowest honest node is
//     the one that routinely misses that cutoff, so the node most likely to be
//     charged is the one behaving correctly. An honest operator can be paused
//     for being slow, with no adversary anywhere.
//
// Neither is acceptable for a penalty, and #1 of the fix is worse still: these
// attestations are NOT signature-verified on the sync path (see
// core.VerifyBlockAttestations, which checks shape and stake arithmetic but
// never att.Signature), so until that is closed the input is forgeable by a
// peer as well as by the proposer.
//
// The REPLACEMENT counts a miss against the designated leader of a view that
// timed out, using a timeout certificate carried in the block body and
// committed by the next header. A proposer cannot manufacture a view timeout,
// so it cannot charge anyone a miss. That is a consensus-format change and is
// tracked as the next step; until it lands, the honest behaviour is to charge
// nobody rather than charge the wrong person.
//
// The function is retained — returning nil without touching state — so the
// call site in ExecuteBlock stays correct when the real policy lands, and so
// no caller needs to special-case its absence.
//
// IsValidatorPausedForHeight and the consensus participation gate are left
// IN PLACE and wired. They are inert in practice because nothing can now write
// a pause record, which is exactly the intended state: the gate is correct and
// ready, and the policy that feeds it is the part that was unsafe.
func (bc *Blockchain) applyMissedRoundPolicy(block *types.Block, stateDB *StateDB) error {
	if block == nil || stateDB == nil {
		return fmt.Errorf("apply missed-round policy: missing block or state DB")
	}
	logger.Debug("Missed-round policy disabled: misses are no longer derived from proposer-chosen block attestations (see applyMissedRoundPolicy)")
	return nil
}

// IsValidatorPausedForHeight reports whether chain state has paused a validator
// for the epoch that governs height. The pause is local-participation gating;
// it does not alter the immutable epoch snapshot or its quorum denominator.
func (bc *Blockchain) IsValidatorPausedForHeight(validatorID string, height uint64) (bool, error) {
	if bc == nil || validatorID == "" {
		return false, fmt.Errorf("validator pause lookup requires blockchain and validator ID")
	}
	stateDB, err := bc.newStateDB()
	if err != nil {
		return false, fmt.Errorf("open state DB for validator pause lookup: %w", err)
	}
	raw, err := stateDB.GetContractValue(validatorPausePrefix + validatorID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("read pause epoch for validator %s: %w", validatorID, err)
	}
	pausedEpoch, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return false, fmt.Errorf("decode pause epoch for validator %s: %w", validatorID, err)
	}
	return pausedEpoch == consensus.EpochForHeight(height), nil
}

func (s *StateDB) readStakeQueue() ([]queuedStakeChange, error) {
	data, err := s.GetContractValue(stakeQueueKey)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("read queued stake changes: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var queue []queuedStakeChange
	if err := json.Unmarshal(data, &queue); err != nil {
		return nil, fmt.Errorf("decode queued stake changes: %w", err)
	}
	return queue, nil
}

func (s *StateDB) writeStakeQueue(queue []queuedStakeChange) error {
	data, err := json.Marshal(queue)
	if err != nil {
		return fmt.Errorf("encode queued stake changes: %w", err)
	}
	s.SetContractValue(stakeQueueKey, data)
	return nil
}

func (s *StateDB) queueStakeChange(change queuedStakeChange) error {
	queue, err := s.readStakeQueue()
	if err != nil {
		return err
	}
	for _, queued := range queue {
		if queued.ValidatorID == change.ValidatorID {
			return fmt.Errorf("validator %s already has a pending stake change", change.ValidatorID)
		}
	}
	queue = append(queue, change)
	return s.writeStakeQueue(queue)
}

func (bc *Blockchain) validateStakeAdmission(stateDB *StateDB, validatorID string) error {
	if stateDB == nil || validatorID == "" {
		return fmt.Errorf("stake admission requires state DB and validator ID")
	}
	if _, err := bc.getPendingWithdrawal(stateDB, validatorID); err == nil {
		return fmt.Errorf("validator %s has stake pending withdrawal", validatorID)
	} else if !errors.Is(err, ErrNoPendingWithdrawal) {
		return err
	}

	members := make(map[string]struct{})
	keys, err := stateDB.GetContractKeysWithPrefix(validatorPrefix)
	if err != nil {
		return fmt.Errorf("list validator stakes for admission: %w", err)
	}
	for _, key := range keys {
		id := key[len(validatorPrefix):]
		stake, err := stateDB.GetValidatorStake(id)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				continue
			}
			return fmt.Errorf("read validator stake for %s: %w", id, err)
		}
		if stake != nil && stake.Sign() > 0 {
			members[id] = struct{}{}
		}
	}
	queue, err := stateDB.readStakeQueue()
	if err != nil {
		return err
	}
	for _, change := range queue {
		if change.Action == "stake" {
			members[change.ValidatorID] = struct{}{}
		}
	}
	if _, exists := members[validatorID]; !exists && len(members) >= consensus.MaxValidatorSetSize {
		return fmt.Errorf("validator set is full (%d validators maximum); stake admission rejected", consensus.MaxValidatorSetSize)
	}
	return nil
}

func (bc *Blockchain) escrowGenesisStakes(stateDB *StateDB) error {
	if stateDB == nil {
		return fmt.Errorf("escrow genesis stakes: state DB is nil")
	}
	stakes, err := stateDB.GetAllValidatorStakes()
	if err != nil {
		return fmt.Errorf("read genesis validator stakes: %w", err)
	}
	for validatorID, amount := range stakes {
		if amount == nil || amount.Sign() <= 0 {
			continue
		}
		markerKey := genesisStakeEscrowKey + validatorID
		if _, err := stateDB.GetContractValue(markerKey); err == nil {
			continue
		} else if !errors.Is(err, database.ErrNotFound) {
			return fmt.Errorf("check genesis stake escrow marker for %s: %w", validatorID, err)
		}

		identity, err := stateDB.getValidatorIdentity(validatorID)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				continue
			}
			return fmt.Errorf("read genesis stake owner for %s: %w", validatorID, err)
		}
		if identity.OwnerAddress == "" {
			continue
		}
		if err := stateDB.Transfer(identity.OwnerAddress, types.StakingEscrowAddress, amount); err != nil {
			return fmt.Errorf("escrow genesis stake for %s: %w", validatorID, err)
		}
		stateDB.SetContractValue(markerKey, []byte("1"))
	}
	return nil
}

func (bc *Blockchain) applyQueuedStakeChanges(block *types.Block, stateDB *StateDB) error {
	if block == nil || stateDB == nil {
		return fmt.Errorf("apply queued stake changes: missing block or state DB")
	}
	epoch := consensus.EpochForHeight(block.GetHeight())
	queue, err := stateDB.readStakeQueue()
	if err != nil {
		return err
	}
	pending := make([]queuedStakeChange, 0, len(queue))
	for _, change := range queue {
		if change.ActivationEpoch > epoch {
			pending = append(pending, change)
			continue
		}
		switch change.Action {
		case "stake":
			amount, ok := new(big.Int).SetString(change.AmountNSPX, 10)
			if !ok || amount.Sign() <= 0 {
				return fmt.Errorf("queued stake for %s has invalid amount %q", change.ValidatorID, change.AmountNSPX)
			}
			stateDB.SetValidatorStake(change.ValidatorID, amount)
			publicKey, err := hex.DecodeString(change.PublicKey)
			if err != nil || len(publicKey) != OperatorPublicKeyLength {
				return fmt.Errorf("queued stake for %s has a validator public key of %d bytes, want exactly %d",
					change.ValidatorID, len(publicKey), OperatorPublicKeyLength)
			}
			if err := stateDB.setValidatorIdentity(change.ValidatorID, change.Owner, publicKey); err != nil {
				return err
			}
		case "unstake":
			amount, err := stateDB.GetValidatorStake(change.ValidatorID)
			if err != nil {
				return fmt.Errorf("read active stake for %s: %w", change.ValidatorID, err)
			}
			if amount == nil || amount.Sign() <= 0 {
				return fmt.Errorf("queued unstake for %s has no active stake", change.ValidatorID)
			}
			withdrawal := pendingWithdrawal{
				ValidatorID:  change.ValidatorID,
				Owner:        change.Owner,
				AmountNSPX:   amount.String(),
				ReleaseEpoch: epoch + UnbondingEpochs,
			}
			data, err := json.Marshal(withdrawal)
			if err != nil {
				return fmt.Errorf("encode pending withdrawal for %s: %w", change.ValidatorID, err)
			}
			stateDB.SetContractValue(pendingWithdrawalPrefix+change.ValidatorID, data)
			stateDB.SetContractValue(validatorPrefix+change.ValidatorID, []byte("0"))
			stateDB.SetContractValue(stakeOwnerKeyPrefix+change.ValidatorID, []byte{})
		default:
			return fmt.Errorf("unknown queued stake action %q", change.Action)
		}
	}
	if err := stateDB.writeStakeQueue(pending); err != nil {
		return err
	}
	return bc.releaseMaturedWithdrawals(epoch, stateDB)
}

func (bc *Blockchain) getPendingWithdrawal(stateDB *StateDB, validatorID string) (*pendingWithdrawal, error) {
	data, err := stateDB.GetContractValue(pendingWithdrawalPrefix + validatorID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, ErrNoPendingWithdrawal
		}
		return nil, fmt.Errorf("read pending withdrawal for %s: %w", validatorID, err)
	}
	if len(data) == 0 {
		return nil, ErrNoPendingWithdrawal
	}
	var withdrawal pendingWithdrawal
	if err := json.Unmarshal(data, &withdrawal); err != nil {
		return nil, fmt.Errorf("decode pending withdrawal for %s: %w", validatorID, err)
	}
	amount, ok := new(big.Int).SetString(withdrawal.AmountNSPX, 10)
	if withdrawal.ValidatorID != validatorID || withdrawal.Owner == "" || !ok || amount.Sign() <= 0 {
		return nil, fmt.Errorf("pending withdrawal for %s is malformed", validatorID)
	}
	return &withdrawal, nil
}

func (bc *Blockchain) releaseMaturedWithdrawals(epoch uint64, stateDB *StateDB) error {
	keys, err := stateDB.GetContractKeysWithPrefix(pendingWithdrawalPrefix)
	if err != nil {
		return fmt.Errorf("list pending withdrawals: %w", err)
	}
	for _, key := range keys {
		validatorID := key[len(pendingWithdrawalPrefix):]
		withdrawal, err := bc.getPendingWithdrawal(stateDB, validatorID)
		if err != nil {
			if errors.Is(err, ErrNoPendingWithdrawal) {
				continue
			}
			return err
		}
		if withdrawal.ReleaseEpoch > epoch {
			continue
		}
		amount, ok := new(big.Int).SetString(withdrawal.AmountNSPX, 10)
		if !ok || amount.Sign() <= 0 {
			return fmt.Errorf("pending withdrawal for %s has invalid amount", validatorID)
		}
		if err := stateDB.Transfer(types.StakingEscrowAddress, withdrawal.Owner, amount); err != nil {
			return fmt.Errorf("release matured withdrawal for %s: %w", validatorID, err)
		}
		stateDB.SetContractValue(pendingWithdrawalPrefix+validatorID, []byte{})
	}
	return nil
}

func (bc *Blockchain) applyDoubleSignPenalty(stateDB *StateDB, validatorID string) error {
	active, err := stateDB.GetValidatorStake(validatorID)
	if err != nil && !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("read active stake for %s: %w", validatorID, err)
	}
	if active == nil {
		active = new(big.Int)
	}
	withdrawal, withdrawalErr := bc.getPendingWithdrawal(stateDB, validatorID)
	if withdrawalErr != nil && !errors.Is(withdrawalErr, ErrNoPendingWithdrawal) {
		return withdrawalErr
	}
	pending := new(big.Int)
	if withdrawal != nil {
		pending, _ = new(big.Int).SetString(withdrawal.AmountNSPX, 10)
	}
	total := new(big.Int).Add(active, pending)
	if total.Sign() <= 0 {
		return fmt.Errorf("validator %s has no slashable active or pending stake", validatorID)
	}
	penalty := policy.CalculateSlashingPenaltyBPS(total, policy.SlashDoubleSignBPS)
	if penalty.Sign() <= 0 {
		return fmt.Errorf("double-sign penalty for %s is zero", validatorID)
	}
	if err := stateDB.Transfer(
		types.StakingEscrowAddress,
		common.CanonicalAddress(common.DefaultBurnAddress),
		penalty,
	); err != nil {
		return fmt.Errorf("burn escrowed slashing penalty for %s: %w", validatorID, err)
	}
	left := new(big.Int).Set(penalty)
	if active.Sign() > 0 {
		activePenalty := new(big.Int).Set(active)
		if activePenalty.Cmp(left) > 0 {
			activePenalty.Set(left)
		}
		active.Sub(active, activePenalty)
		left.Sub(left, activePenalty)
		stateDB.SetContractValue(validatorPrefix+validatorID, []byte(active.String()))
	}
	if left.Sign() > 0 {
		pending.Sub(pending, left)
		withdrawal.AmountNSPX = pending.String()
		data, err := json.Marshal(withdrawal)
		if err != nil {
			return fmt.Errorf("encode slashed withdrawal for %s: %w", validatorID, err)
		}
		stateDB.SetContractValue(pendingWithdrawalPrefix+validatorID, data)
	}
	return nil
}

func (bc *Blockchain) applyStakeTransactionsToValidatorSet(block *types.Block) error {
	if block == nil {
		return fmt.Errorf("apply stake transactions: block is nil")
	}
	for _, tx := range block.Body.TxsList {
		if tx == nil {
			return fmt.Errorf("apply stake transactions: nil transaction")
		}
		action, isStakeAction, err := types.ParseStakeAction(tx.ReturnData)
		if err != nil {
			return fmt.Errorf("parse stake transaction %s: %w", tx.ID, err)
		}
		if !isStakeAction {
			evidence, isEvidence, err := types.ParseDoubleSignEvidence(tx.ReturnData)
			if err != nil {
				return fmt.Errorf("parse double-sign evidence transaction %s: %w", tx.ID, err)
			}
			if isEvidence {
				validatorSet := bc.liveValidatorSet()
				if validatorSet == nil {
					return fmt.Errorf("apply slashing evidence: validator set is unavailable")
				}
				validatorSet.SlashValidator(evidence.First.ValidatorID, "on-chain double-sign evidence", policy.SlashDoubleSignBPS)
			}
			continue
		}
		validatorSet := bc.liveValidatorSet()
		if validatorSet == nil {
			return fmt.Errorf("apply stake transactions: validator set is unavailable")
		}
		activationEpoch := consensus.ActivationEpochForStake(block.GetHeight())
		switch action.Action {
		case "stake":
			if err := validatorSet.QueueValidatorWithRewardAddress(
				action.ValidatorID, tx.Amount, activationEpoch, tx.Sender,
			); err != nil {
				return fmt.Errorf("queue validator %s from committed stake transaction: %w", action.ValidatorID, err)
			}
		case "unstake":
			if err := validatorSet.QueueUnstake(action.ValidatorID, activationEpoch); err != nil {
				return fmt.Errorf("queue validator %s exit from committed unstake transaction: %w", action.ValidatorID, err)
			}
		default:
			return fmt.Errorf("unknown committed stake action %q", action.Action)
		}
	}
	return nil
}

// ReplayStakeTransactions rebuilds pending and active membership changes from
// committed blocks after genesis validators have been seeded at startup.
func (bc *Blockchain) ReplayStakeTransactions() error {
	if bc == nil || bc.storage == nil {
		return fmt.Errorf("replay stake transactions: blockchain storage is unavailable")
	}
	validatorSet := bc.liveValidatorSet()
	if validatorSet == nil {
		return fmt.Errorf("replay stake transactions: validator set is unavailable")
	}
	blocks, err := bc.storage.GetAllBlocks()
	if err != nil {
		return fmt.Errorf("read committed blocks for stake replay: %w", err)
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].GetHeight() < blocks[j].GetHeight() })
	for _, block := range blocks {
		if block == nil {
			return fmt.Errorf("replay stake transactions: nil committed block")
		}
		if err := bc.applyStakeTransactionsToValidatorSet(block); err != nil {
			return err
		}
		nextHeight := block.GetHeight() + 1
		if consensus.IsEpochBoundary(nextHeight) && nextHeight > 0 {
			validatorSet.ProcessEpochTransition(consensus.EpochForHeight(nextHeight))
		}
	}
	return nil
}
