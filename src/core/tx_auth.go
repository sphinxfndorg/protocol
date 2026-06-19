// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/tx_auth.go
package core

import (
	"encoding/binary"
	"fmt"

	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxorg/protocol/src/core/transaction"
)

func transactionAuthTimestamp(tx *types.Transaction) []byte {
	if len(tx.AuthTimestamp) == 8 {
		out := make([]byte, 8)
		copy(out, tx.AuthTimestamp)
		return out
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(tx.Timestamp))
	return out
}

func transactionAuthNonce(tx *types.Transaction) []byte {
	if len(tx.AuthNonce) == 16 {
		out := make([]byte, 16)
		copy(out, tx.AuthNonce)
		return out
	}
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[:8], tx.Nonce)
	return out
}

func (bc *Blockchain) validateTransactionAuth(tx *types.Transaction, storeEvidence bool) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.IsSystemTransaction() {
		return nil
	}
	if !tx.HasFullAuthBundle() {
		return fmt.Errorf("transaction %s missing full SPHINCS auth bundle", tx.ID)
	}
	if bc.sphincsManager == nil {
		return fmt.Errorf("transaction %s cannot be verified: STHINCS manager is not configured", tx.ID)
	}

	if err := bc.sphincsManager.VerifyTransactionAuth(
		[]byte(tx.ID),
		transactionAuthTimestamp(tx),
		transactionAuthNonce(tx),
		tx.Signature,
		tx.PublicKey,
		tx.SignatureHash,
		tx.MerkleRootHash,
		tx.Commitment,
		tx.Proof,
		storeEvidence,
	); err != nil {
		return fmt.Errorf("transaction %s SPHINCS auth failed: %w", tx.ID, err)
	}

	if storeEvidence {
		if err := bc.sphincsManager.StoreTransactionReceipt(tx.Commitment, tx.MerkleRootHash, tx.Proof); err != nil {
			return fmt.Errorf("transaction %s receipt storage failed: %w", tx.ID, err)
		}
	}

	return nil
}

func (bc *Blockchain) validateBlockTransactionAuth(block *types.Block, storeEvidence bool) error {
	if block == nil {
		return fmt.Errorf("nil block")
	}

	seenSigHashes := make(map[string]struct{})
	seenSessions := make(map[string]struct{})
	seenCommitments := make(map[string]struct{})

	for i, tx := range block.Body.TxsList {
		if tx == nil {
			return fmt.Errorf("transaction %d is nil", i)
		}
		if tx.IsSystemTransaction() {
			continue
		}

		sigHashKey := string(tx.SignatureHash)
		if _, exists := seenSigHashes[sigHashKey]; exists {
			return fmt.Errorf("duplicate signature hash in block for transaction %s", tx.ID)
		}
		seenSigHashes[sigHashKey] = struct{}{}

		sessionKey := string(transactionAuthTimestamp(tx)) + string(transactionAuthNonce(tx))
		if _, exists := seenSessions[sessionKey]; exists {
			return fmt.Errorf("duplicate timestamp/nonce in block for transaction %s", tx.ID)
		}
		seenSessions[sessionKey] = struct{}{}

		commitmentKey := string(tx.Commitment)
		if _, exists := seenCommitments[commitmentKey]; exists {
			return fmt.Errorf("duplicate commitment in block for transaction %s", tx.ID)
		}
		seenCommitments[commitmentKey] = struct{}{}

		if err := bc.validateTransactionAuth(tx, storeEvidence); err != nil {
			return err
		}
	}

	return nil
}

// SignTransaction fills a transaction with the full SPHINCS auth bundle required
// for mempool admission, P2P gossip, and block validation.
func (bc *Blockchain) SignTransaction(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.IsSystemTransaction() {
		return nil
	}
	if bc.sphincsManager == nil {
		return fmt.Errorf("STHINCS manager is not configured")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize transaction signing key pair: %w", err)
	}

	bundle, err := bc.sphincsManager.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction auth bundle: %w", err)
	}

	tx.Signature = bundle.Signature
	tx.SignatureHash = bundle.SignatureHash
	tx.PublicKey = bundle.PublicKey
	tx.AuthTimestamp = bundle.Timestamp
	tx.AuthNonce = bundle.Nonce
	tx.MerkleRootHash = bundle.MerkleRootHash
	tx.Commitment = bundle.Commitment
	tx.Proof = bundle.Proof

	return nil
}

// RebuildCanonicalReplayEvidence replays compact authentication evidence from
// the current canonical chain into the configured SPHINCS evidence database.
// Call this after chain sync or fork choice selects a new canonical head.
func (bc *Blockchain) RebuildCanonicalReplayEvidence() error {
	if bc.sphincsManager == nil {
		return fmt.Errorf("STHINCS manager is not configured")
	}

	bc.lock.RLock()
	chain := append([]*types.Block(nil), bc.chain...)
	bc.lock.RUnlock()

	for _, block := range chain {
		if block == nil {
			continue
		}
		for _, tx := range block.Body.TxsList {
			if tx == nil || tx.IsSystemTransaction() {
				continue
			}
			if err := bc.sphincsManager.VerifyTransactionAuthStateless(
				[]byte(tx.ID),
				transactionAuthTimestamp(tx),
				transactionAuthNonce(tx),
				tx.Signature,
				tx.PublicKey,
				tx.SignatureHash,
				tx.MerkleRootHash,
				tx.Commitment,
				tx.Proof,
			); err != nil {
				return fmt.Errorf("transaction %s stateless auth failed during replay-index rebuild: %w", tx.ID, err)
			}
			if err := bc.sphincsManager.StoreSignatureHash(tx.Signature); err != nil {
				return fmt.Errorf("failed to rebuild signature hash evidence for tx %s: %w", tx.ID, err)
			}
			if err := bc.sphincsManager.StoreTimestampNonce(transactionAuthTimestamp(tx), transactionAuthNonce(tx)); err != nil {
				return fmt.Errorf("failed to rebuild timestamp/nonce evidence for tx %s: %w", tx.ID, err)
			}
			if err := bc.sphincsManager.StoreTransactionReceipt(tx.Commitment, tx.MerkleRootHash, tx.Proof); err != nil {
				return fmt.Errorf("failed to rebuild receipt evidence for tx %s: %w", tx.ID, err)
			}
		}
	}

	return nil
}
