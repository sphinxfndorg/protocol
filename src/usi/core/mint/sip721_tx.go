// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/mint/sip721_tx.go
//
// SIP-721 collection mint broadcasting for the mint package.
//
// This extends the automatic mint flow (MintAndAnchor) with an Ethereum-close
// collection mint while keeping the receipt-anchor model intact:
//
//  1. BroadcastSIP721CollectionMint executes the collection contract's mint
//     method on-chain (sendrawtransaction with ToContract/CallData). The
//     contract (contracts/callSIP721) is executed by EVERY node during block
//     commit, which is what makes ownerOf/approve/transfer_from and the
//     tokenId counter consensus-enforced instead of wallet-enforced.
//  2. The tokenId it allocates comes STRAIGHT from contract storage
//     (sip721:info.next_token_id), never guessed locally — this is the
//     Ethereum tokenId counter semantic.
//  3. The same SIP-721 binding (token_id/token_uri/contract) is then folded
//     into the AnchorTag ReturnData so the receipt commitment and the
//     on-chain token pointer verify as one atomic unit.
package mint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// Nonces is the process-wide nonce reservation table for every broadcast in
// this flow. It is exported because the GUI wallet broadcasts from the same
// process: one table means a SIP-721 collection mint, its receipt anchor, and
// any GUI transaction in between all see each other's uncommitted claims,
// instead of the GUI mirroring a second map into this package. The semantics
// (getnonce outside the lock, never below the committed nonce, release only
// when nothing later has claimed) live in abi.NonceReserver.
var Nonces = abi.NewNonceReserver()

// MintWaitOpts opts a broadcast into waiting for on-chain confirmation. The
// zero value is off, so a caller that never sets it keeps the historical
// broadcast-and-poll behavior. Wait is opt-in because it trades latency for
// certainty: abi.WaitMined polls gettransactionreceipt until the tx is
// committed or rejected. Timeout must be set (or left to
// TokenIDConfirmTimeout) because an unknown txid is indistinguishable from a
// pending one on this node, so an unbounded wait would poll forever.
type MintWaitOpts struct {
	Wait         bool
	Timeout      time.Duration
	PollInterval time.Duration
}

// waitForMined blocks until txID is committed or rejected, or the wait window
// ends. A nil/disabled MintWaitOpts returns (nil, nil) without touching the
// node, which is the default-off path.
func waitForMined(nodeAddr, txID string, wait *MintWaitOpts) (*abi.TxReceipt, error) {
	if wait == nil || !wait.Wait {
		return nil, nil
	}
	timeout := wait.Timeout
	if timeout <= 0 {
		timeout = TokenIDConfirmTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return abi.WaitMined(ctx, callOpts(nodeAddr), txID, wait.PollInterval)
}

// mintWaitResult reports, for a wait that ended without confirmation, whether
// the node terminally rejected the tx (so it will never commit and its nonce
// reservation can be dropped) or whether it is still in flight (so the
// reservation must be kept — the tx still owns that nonce).
func mintWaitResult(txID string, receipt *abi.TxReceipt, err error) (terminal bool, message string) {
	if err == nil {
		return false, ""
	}
	if receipt != nil && strings.TrimSpace(receipt.InvalidReason) != "" {
		return true, fmt.Sprintf("tx %s was REJECTED by the node and will never commit: %s", txID, receipt.InvalidReason)
	}
	return false, fmt.Sprintf("tx %s is still in flight (unconfirmed) — do not re-broadcast it: %v", txID, err)
}

// BroadcastSIP721CollectionMint executes collection.mint(to, tokenURI, mintID)
// on-chain with no embedded terms (legacy zero-royalty, zero-fee mint). It is
// kept for API compatibility; new flows should use
// BroadcastSIP721CollectionMintWithTerms.
func BroadcastSIP721CollectionMint(nodeAddr, collection, from, keyFile, to, tokenURI, mintID string) (tokenID uint64, txID string, err error) {
	return BroadcastSIP721CollectionMintWithTerms(nodeAddr, collection, from, keyFile, to, tokenURI, mintID, 0, "", "")
}

// BroadcastSIP721CollectionMintWithTerms executes
// collection.mint(to, tokenURI, mintID, royalty_bps, usage_fee,
// royalty_recipient) on-chain, freezing the token's embedded economics
// (resale royalty + licensed-access fee + optional payout override) in
// contract storage. All-zero terms behave exactly like the legacy mint.
//
// It does not wait for confirmation; use
// BroadcastSIP721CollectionMintWithWait to opt into that.
func BroadcastSIP721CollectionMintWithTerms(nodeAddr, collection, from, keyFile, to, tokenURI, mintID string, royaltyBPS uint64, usageFeeNSPX, royaltyRecipient string) (tokenID uint64, txID string, err error) {
	return broadcastSIP721CollectionMintWithTerms(nodeAddr, collection, from, keyFile, to, tokenURI, mintID, royaltyBPS, usageFeeNSPX, royaltyRecipient, nil)
}

// BroadcastSIP721CollectionMintWithWait is
// BroadcastSIP721CollectionMintWithTerms plus opt-in on-chain confirmation: a
// non-nil enabled MintWaitOpts blocks until the mint transaction is committed
// (or rejected, or the wait window ends) before the tokenId is read back. A nil
// or disabled MintWaitOpts is exactly the existing behavior.
func BroadcastSIP721CollectionMintWithWait(nodeAddr, collection, from, keyFile, to, tokenURI, mintID string, royaltyBPS uint64, usageFeeNSPX, royaltyRecipient string, wait *MintWaitOpts) (tokenID uint64, txID string, err error) {
	return broadcastSIP721CollectionMintWithTerms(nodeAddr, collection, from, keyFile, to, tokenURI, mintID, royaltyBPS, usageFeeNSPX, royaltyRecipient, wait)
}

// broadcastSIP721CollectionMintWithTerms is the single collection-mint
// implementation behind the exported wrappers, taking the wait config so the
// default-off callers never pay for it.
func broadcastSIP721CollectionMintWithTerms(nodeAddr, collection, from, keyFile, to, tokenURI, mintID string, royaltyBPS uint64, usageFeeNSPX, royaltyRecipient string, wait *MintWaitOpts) (tokenID uint64, txID string, err error) {
	if strings.TrimSpace(nodeAddr) == "" {
		return 0, "", errors.New("node address required")
	}
	if strings.TrimSpace(collection) == "" {
		return 0, "", errors.New("collection contract address required")
	}
	if strings.TrimSpace(from) == "" {
		return 0, "", errors.New("sender address required")
	}
	if strings.TrimSpace(keyFile) == "" {
		return 0, "", errors.New("key file required")
	}
	if strings.TrimSpace(to) == "" {
		return 0, "", errors.New("token recipient required")
	}
	tokenURI = strings.TrimSpace(tokenURI)
	if tokenURI == "" {
		return 0, "", errors.New("token_uri required: mint aborts without a real IPFS tokenURI")
	}

	// chainID for EIP-155 replay protection — must match the node's network.
	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	// The sender is the raw hex address (formatted SPIF addresses are
	// normalized by callers like the CLI/GUI before reaching this path).
	rawFrom := strings.TrimSpace(from)

	// Fetch the sender's exact current nonce (the mempool enforces an EXACT
	// match — "invalid nonce: %d must equal %d"). Goes through the
	// process-local reservation so a receipt anchor broadcast immediately
	// afterwards consumes the NEXT nonce, not this same one.
	nonce, err := Nonces.Reserve(nodeRPC{}, nodeAddr, rawFrom)
	if err != nil {
		return 0, "", err
	}

	// Build -> sign -> encode -> broadcast in one call. The typed wrapper owns
	// the calldata packing; abi.Transact owns the rest. Terms ride along in the
	// mint args and are frozen in contract storage when the block executes the
	// call — the wallet cannot change them afterwards.
	txID, err = (abi.SIP721Contract{Address: collection}).Mint(
		transactOpts(nodeAddr, keyFile, chainID, nonce),
		rawFrom,
		to,
		abi.MintTerms{
			TokenURI:         tokenURI,
			MintID:           mintID,
			RoyaltyBPS:       royaltyBPS,
			UsageFeeNSPX:     usageFeeNSPX,
			RoyaltyRecipient: royaltyRecipient,
		},
	)
	if err != nil {
		Nonces.Release(nodeAddr, rawFrom, nonce)
		return 0, "", fmt.Errorf("sip721 mint: %w", err)
	}

	// Opt-in confirmation wait: with wait disabled this is a no-op and the
	// flow proceeds straight to the existing storage poll below.
	if receipt, waitErr := waitForMined(nodeAddr, txID, wait); waitErr != nil {
		terminal, message := mintWaitResult(txID, receipt, waitErr)
		if terminal {
			// The node rejected the tx: it will never commit, so its nonce
			// reservation is free to be reused.
			Nonces.Release(nodeAddr, rawFrom, nonce)
		}
		return 0, txID, fmt.Errorf("collection mint %s", message)
	}

	// The collection contract's mint only executes when the broadcast
	// transaction is included in a block, so the tokenId is not visible in
	// consensus storage immediately after sendrawtransaction. Poll
	// getcontractstorage for a bounded window instead of racing the block.
	tokenID, err = readSIP721TokenIDOfMintWithRetries(nodeAddr, collection, mintID, TokenIDConfirmTimeout)
	if err != nil {
		// Ask the node where the mint tx actually is before choosing the
		// advice to give: a tx the node REJECTED can never commit (its
		// mint_id was never consumed, so re-minting is safe and correct),
		// while an in-flight tx still owns its nonce and WILL commit (the
		// contract rejects duplicate mint_ids, so re-minting would only
		// produce a second, permanently-unconfirmable tx).
		// The mint tx either REJECTED (never commits — its reservation is
		// free and must be given back, or every retry permanently inflates
		// the local nonce past the chain's: that is the reported
		// "invalid nonce: 5 must equal 2" deploy failure) or is still in
		// flight (its nonce stays claimed — re-minting the same mint_id
		// would only produce a second, permanently-unconfirmable tx).
		state := txNodeStateString(nodeAddr, txID)
		if releaseRejectedNonce(nodeAddr, rawFrom, nonce, state) {
			return 0, txID, fmt.Errorf("collection mint tx %s was REJECTED by the node and will never commit (%s) — the mint did NOT happen; fix the cause and mint again (last poll error: %v)",
				txID, state, err)
		}
		// The mint tx IS in the mempool and will commit even though we abort
		// wallet-side. Surface the txID explicitly so nobody re-mints the same
		// content (contract storage rejects duplicate mint_ids) or believes
		// the mint never happened.
		return 0, txID, fmt.Errorf("collection mint tx %s accepted but tokenId not confirmed within %v (%s); that tx WILL still commit this mint (mint_id %s) — do not re-mint this mint_id: %w",
			txID, TokenIDConfirmTimeout, state, mintID, err)
	}
	return tokenID, txID, nil
}

// TokenIDConfirmTimeout is how long BroadcastSIP721CollectionMint waits for the
// collection-mint transaction to be included in a block and its tokenId to
// become visible in contract storage.
const TokenIDConfirmTimeout = 60 * time.Second

// releaseRejectedNonce gives the process-local reservation for nonce back when
// nodeState proves the transaction terminally rejected (the "node rejected it:
// …" marker txNodeStateString produces from gettransactionreceipt's
// invalid_reason). A rejected transaction never consumes its nonce on chain,
// but Nonces.Reserve has already advanced the account past it — without this
// release every retry permanently pushes the next reservation higher than the
// chain's nonce, which the mempool's exact-match rule reports on the NEXT
// unrelated broadcast as "invalid nonce: N must equal M" (wallet ahead of
// chain, e.g. "5 must equal 2"). Returns false for every other state (still
// in flight, committed, unaskable) so an in-flight tx keeps owning its nonce.
func releaseRejectedNonce(nodeAddr, sender string, nonce uint64, nodeState string) bool {
	if !strings.Contains(nodeState, "node rejected it") {
		return false
	}
	Nonces.Release(nodeAddr, sender, nonce)
	return true
}

// txNodeStateString asks the node where a broadcast transaction currently is,
// as a short human-readable diagnostic string:
//
//	"committed at height N"                 — the tx is in a block
//	"node rejected it: <reason>"            — terminally invalid, will never commit
//	"uncommitted (broadcast=a validating=b pending=c invalid=d total=e)" — in flight
//	""                                      — the node could not be asked (RPC error)
//
// It is used to turn blind polling timeouts (tokenId visibility, collection
// readability) into precise failures: a rejected tx means the operation never
// happened and is safe to retry, while an in-flight tx still owns its nonce
// and its on-chain effects and must NOT be retried.
func txNodeStateString(nodeAddr, txID string) string {
	raw, err := rpc.CallRPC(nodeAddr, "gettransactionreceipt", []interface{}{txID}, 30)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var result struct {
		Confirmed     bool           `json:"confirmed"`
		Height        uint64         `json:"height"`
		Pool          map[string]int `json:"pool"`
		InvalidReason string         `json:"invalid_reason"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return ""
	}
	if strings.TrimSpace(result.InvalidReason) != "" {
		return "node rejected it: " + strings.TrimSpace(result.InvalidReason)
	}
	if result.Confirmed {
		return fmt.Sprintf("committed at height %d", result.Height)
	}
	if len(result.Pool) > 0 {
		return fmt.Sprintf("uncommitted (broadcast=%d validating=%d pending=%d invalid=%d total=%d)",
			result.Pool["broadcast"], result.Pool["validating"], result.Pool["pending"],
			result.Pool["invalid"], result.Pool["total"])
	}
	return "uncommitted (no pool state reported)"
}

// readSIP721TokenIDOfMintWithRetries polls contract storage until the tokenId
// bound to mintID is committed (reverse index sip721:mint:<mintID>), or the
// timeout elapses. The contract's mint runs at block commit, so a tiny wait
// is expected; this just bounds it instead of racing.
func readSIP721TokenIDOfMintWithRetries(nodeAddr, collection, mintID string, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for attempt := 0; attempt < 120; attempt++ {
		if tokenID, err := readSIP721TokenIDOfMint(nodeAddr, collection, mintID); err == nil {
			return tokenID, nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(1 * time.Second)
	}
	return 0, fmt.Errorf("tokenId not visible after %v (last error: %w)", timeout, lastErr)
}

// readSIP721TokenIDOfMint returns tokenId for a mintID via the on-chain
// reverse index (sip721:mint:<mintID>) through getcontractstorage.
func readSIP721TokenIDOfMint(nodeAddr, collection, mintID string) (uint64, error) {
	reader := NewContractStorageReader(nodeAddr)
	return reader.TokenIDOfMint(collection, mintID)
}

// broadcastReceiptAnchor commits the receipt's AnchorTag (which now carries
// the SIP-721 token_id/token_uri/contract binding) as a self-send ReturnData
// transaction. It is used after a collection mint so the anchor uses the
// NEXT account nonce — the mempool enforces an exact match and the collection
// call already consumed the current one.
// broadcastReceiptAnchorWithWait is broadcastReceiptAnchor plus opt-in
// on-chain confirmation. A nil/disabled MintWaitOpts is exactly
// broadcastReceiptAnchor. A rejected anchor releases its nonce reservation (the
// tx can never commit); an anchor still in flight keeps it, because it still
// owns that nonce.
func broadcastReceiptAnchorWithWait(nodeAddr, from, keyFile string, anchorData []byte, wait *MintWaitOpts) (txID string, err error) {
	rawFrom := strings.TrimSpace(from)
	txID, nonce, err := broadcastReceiptAnchorWithNonce(nodeAddr, from, keyFile, anchorData)
	if err != nil || txID == "" {
		return txID, err
	}
	receipt, waitErr := waitForMined(nodeAddr, txID, wait)
	if waitErr == nil {
		return txID, nil
	}
	terminal, message := mintWaitResult(txID, receipt, waitErr)
	if terminal {
		Nonces.Release(nodeAddr, rawFrom, nonce)
	}
	return txID, fmt.Errorf("receipt anchor %s", message)
}

func broadcastReceiptAnchor(nodeAddr, from, keyFile string, anchorData []byte) (txID string, err error) {
	txID, _, err = broadcastReceiptAnchorWithNonce(nodeAddr, from, keyFile, anchorData)
	return txID, err
}

// broadcastReceiptAnchorWithNonce broadcasts the anchor and also reports the
// nonce it reserved, so a caller that learns the anchor can never commit can
// release that reservation.
func broadcastReceiptAnchorWithNonce(nodeAddr, from, keyFile string, anchorData []byte) (txID string, nonce uint64, err error) {
	if strings.TrimSpace(nodeAddr) == "" {
		return "", 0, errors.New("node address required")
	}
	if strings.TrimSpace(from) == "" {
		return "", 0, errors.New("sender address required")
	}
	if strings.TrimSpace(keyFile) == "" {
		return "", 0, errors.New("key file required")
	}
	rawFrom := strings.TrimSpace(from)

	// chainID for EIP-155 replay protection — must match the node's network.
	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	// Fetch the account's exact current nonce (the mempool enforces an EXACT
	// match). Goes through the process-local reservation: the collection mint
	// consumed the previous nonce, but its block has not committed yet, so a
	// raw getnonce here would return the SAME value and collide — the
	// reservation advances past the collection mint's claim instead.
	nonce, err = Nonces.Reserve(nodeRPC{}, nodeAddr, rawFrom)
	if err != nil {
		return "", 0, err
	}

	mintPolicy := policy.GetDefaultPolicyParams()

	// The receipt anchor is a self-send that exists only to carry the AnchorTag
	// in ReturnData, but its Amount is NOT a free constant: it records the
	// deterministic, policy-priced mint fee (CalculateMintDataFee.TotalFee — the
	// same target QuoteMintDataGas sizes the gas price against) so the committed
	// anchor carries the same value on-chain that the wallet quoted. It is never
	// hardcoded; we fall back to 1 nSPX only when the fee quote is unavailable.
	mintFeeQuote := mintPolicy.CalculateMintDataFee(uint64(len(anchorData)), uint64(len(anchorData)), mintPolicy.MintBaseHashes, mintPolicy.MintPinningMonths)
	mintFeeNSPX := big.NewInt(1)
	if mintFeeQuote != nil && mintFeeQuote.TotalFee != nil && mintFeeQuote.TotalFee.Sign() > 0 {
		mintFeeNSPX = mintFeeQuote.TotalFee
	}

	gasQuote := mintPolicy.QuoteMintDataGas(uint64(len(anchorData)), uint64(len(anchorData)), mintPolicy.MintBaseHashes, mintPolicy.MintPinningMonths)

	anchorTx := &types.Transaction{
		ID:         "",
		ChainID:    chainID,
		Sender:     rawFrom,
		Receiver:   rawFrom, // self-send: this tx exists only to carry data
		Amount:     mintFeeNSPX,
		GasLimit:   gasQuote.GasLimit,
		GasPrice:   gasQuote.GasPrice,
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		Signature:  []byte{},
		ReturnData: anchorData,
	}
	anchorTx.ID = anchorTx.Hash()

	tx, err := abi.Transact(transactOpts(nodeAddr, keyFile, chainID, nonce), anchorTx)
	if err != nil {
		Nonces.Release(nodeAddr, rawFrom, nonce)
		return "", 0, fmt.Errorf("broadcast receipt anchor: %w", err)
	}
	return tx, nonce, nil
}

// signTransactionLocallyInMint lives in transact.go alongside the abi.Signer
// implementation that uses it.
