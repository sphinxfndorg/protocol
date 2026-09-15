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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	"github.com/sphinxfndorg/protocol/src/core"
	kbackend "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sbackend "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// mintPendingNonceMu / mintPendingNonce guard the CLI's process-local nonce
// reservations, keyed by "nodeAddr|sender" since the CLI is not tied to one
// logged-in session. The CLI does not share process state with the GUI
// wallet, so this is a separate copy of the same scheme gui/rpc.go uses —
// the critical property here is that BOTH broadcasts of the MintAndAnchor
// flow (the collection mint and its receipt anchor) go through this one
// reservation, so the anchor consumes the NEXT nonce instead of re-reading
// the same committed on-chain nonce before the collection mint's block has
// committed and colliding in the mempool's accountNonceIndex.
var (
	mintPendingNonceMu sync.Mutex
	mintPendingNonce   = map[string]uint64{} // "nodeAddr|sender" -> next unclaimed nonce
)

// mintNonceKey builds the reservation-map key for a (node, sender) pair.
func mintNonceKey(nodeAddr, sender string) string {
	return nodeAddr + "|" + strings.TrimSpace(sender)
}

// reserveNextNonce mirrors gui/rpc.go's getCurrentNonce pending-nonce cache:
// a SIP-721 collection mint immediately followed by its receipt anchor
// (broadcastReceiptAnchor) would otherwise both read the same committed
// on-chain nonce from getnonce and collide, since the collection mint's
// block has not committed yet when the anchor is built.
func reserveNextNonce(nodeAddr, rawSender string) (uint64, error) {
	nonceData, err := rpc.CallRPC(nodeAddr, "getnonce", []interface{}{rawSender}, 60)
	if err != nil {
		return 0, fmt.Errorf("failed to get account nonce: %w", err)
	}
	var chainNonce uint64
	if err := json.Unmarshal(nonceData, &chainNonce); err != nil {
		return 0, fmt.Errorf("parse nonce response: %w", err)
	}

	key := mintNonceKey(nodeAddr, rawSender)
	mintPendingNonceMu.Lock()
	defer mintPendingNonceMu.Unlock()
	next := chainNonce
	if reserved, ok := mintPendingNonce[key]; ok && reserved > next {
		next = reserved
	}
	mintPendingNonce[key] = next + 1
	return next, nil
}

// releaseNextNonce rolls back a reservation made by reserveNextNonce when the
// transaction that was going to consume it was never actually broadcast.
// Only rewinds when nothing has claimed a later nonce since.
func releaseNextNonce(nodeAddr, rawSender string, nonce uint64) {
	key := mintNonceKey(nodeAddr, rawSender)
	mintPendingNonceMu.Lock()
	defer mintPendingNonceMu.Unlock()
	if mintPendingNonce[key] == nonce+1 {
		mintPendingNonce[key] = nonce
	}
}

// PeekReservedNonce reports the next unclaimed nonce this process reserved via
// reserveNextNonce for (nodeAddr, sender), if any. Exported so the GUI wallet
// (which keeps its own pending-nonce cache in gui/rpc.go but shares this
// process when the mint worker runs there) can take the maximum of both
// reservations instead of re-reading the same committed on-chain nonce.
func PeekReservedNonce(nodeAddr, sender string) (uint64, bool) {
	key := mintNonceKey(nodeAddr, sender)
	mintPendingNonceMu.Lock()
	defer mintPendingNonceMu.Unlock()
	next, ok := mintPendingNonce[key]
	return next, ok
}

// AdvanceReservation ensures the reservation for (nodeAddr, sender) is at
// least next. Called by the GUI wallet after it claims a nonce through its
// own cache so a later reserveNextNonce in this package sees it — covering
// the reverse order (GUI broadcast first, collection mint second) that
// reserveNextNonce alone cannot see, since this package cannot import the
// GUI (gui already imports mint).
func AdvanceReservation(nodeAddr, sender string, next uint64) {
	key := mintNonceKey(nodeAddr, sender)
	mintPendingNonceMu.Lock()
	defer mintPendingNonceMu.Unlock()
	if next > mintPendingNonce[key] {
		mintPendingNonce[key] = next
	}
}

// ReleaseReservation rolls back a GUI-side reservation previously pushed via
// AdvanceReservation. Only rewinds when nothing has claimed a later nonce
// since, mirroring releaseNextNonce.
func ReleaseReservation(nodeAddr, sender string, nonce uint64) {
	releaseNextNonce(nodeAddr, sender, nonce)
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
func BroadcastSIP721CollectionMintWithTerms(nodeAddr, collection, from, keyFile, to, tokenURI, mintID string, royaltyBPS uint64, usageFeeNSPX, royaltyRecipient string) (tokenID uint64, txID string, err error) {
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
	nonce, err := reserveNextNonce(nodeAddr, rawFrom)
	if err != nil {
		return 0, "", err
	}

	// Build the unsigned SIP-721 call (policy-quoted) via the canonical ABI.
	// Terms ride along in the mint args and are frozen in contract storage when
	// the block executes the call — the wallet cannot change them afterwards.
	mintArgs := map[string]string{
		"to":        to,
		"token_uri": tokenURI,
		"mint_id":   mintID,
	}
	if royaltyBPS > 0 {
		mintArgs["royalty_bps"] = strconv.FormatUint(royaltyBPS, 10)
	}
	usageFeeNSPX = strings.TrimSpace(usageFeeNSPX)
	if usageFeeNSPX != "" {
		mintArgs["usage_fee"] = usageFeeNSPX
	}
	royaltyRecipient = strings.TrimSpace(royaltyRecipient)
	if royaltyRecipient != "" {
		mintArgs["royalty_recipient"] = royaltyRecipient
	}
	tx, err := abi.NewSIP721CallTx(abi.TxOptions{
		ChainID: chainID,
		Sender:  rawFrom,
		Nonce:   nonce,
	}, collection, "mint", mintArgs)
	if err != nil {
		releaseNextNonce(nodeAddr, rawFrom, nonce)
		return 0, "", fmt.Errorf("build sip721 mint call: %w", err)
	}

	txID, err = signAndBroadcastMintTx(nodeAddr, tx, keyFile)
	if err != nil {
		releaseNextNonce(nodeAddr, rawFrom, nonce)
		return 0, "", err
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
		state := txNodeStateString(nodeAddr, txID)
		if strings.Contains(state, "node rejected it") {
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
func broadcastReceiptAnchor(nodeAddr, from, keyFile string, anchorData []byte) (txID string, err error) {
	if strings.TrimSpace(nodeAddr) == "" {
		return "", errors.New("node address required")
	}
	if strings.TrimSpace(from) == "" {
		return "", errors.New("sender address required")
	}
	if strings.TrimSpace(keyFile) == "" {
		return "", errors.New("key file required")
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
	nonce, err := reserveNextNonce(nodeAddr, rawFrom)
	if err != nil {
		return "", err
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

	tx := &types.Transaction{
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
	tx.ID = tx.Hash()

	txID, err = signAndBroadcastMintTx(nodeAddr, tx, keyFile)
	if err != nil {
		releaseNextNonce(nodeAddr, rawFrom, nonce)
		return "", fmt.Errorf("broadcast receipt anchor: %w", err)
	}
	return txID, nil
}

// signAndBroadcastMintTx signs the contract-call transaction with the local
// SPHINCS+ key and broadcasts it through sendrawtransaction. The transaction
// is a normal consensus call: the node executes collection.mint during block
// commit and rejects it if the caller is not the collection owner.
func signAndBroadcastMintTx(nodeAddr string, tx *types.Transaction, keyFile string) (string, error) {
	if tx == nil {
		return "", errors.New("nil transaction")
	}
	// Load the local key and sign the canonical transaction auth bundle.
	kp, skBytes, err := keys.LoadKeyFromDisk(keyFile)
	if err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()
	tx.ID = tx.Hash()
	if err := signTransactionLocallyInMint(tx, skBytes, kp.PublicKey); err != nil {
		return "", fmt.Errorf("sign sip721 mint call: %w", err)
	}

	// Marshal and broadcast.
	txData, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("marshal sip721 mint tx: %w", err)
	}
	resultData, err := rpc.CallRPC(nodeAddr, "sendrawtransaction", []interface{}{hex.EncodeToString(txData)}, 120)
	if err != nil {
		return "", fmt.Errorf("broadcast sip721 mint: %w", err)
	}
	var result struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil || result.TxID == "" {
		return "", errors.New("sip721 mint broadcast: no txid in response")
	}
	return result.TxID, nil
}

// signTransactionLocallyInMint signs a transaction using the node's canonical
// SPHINCS+ transaction authentication path (STHINCSManager.SignTransactionAuth),
// the same call cli/utils/client.go, core.SignTransaction and the USI wallet
// use. It is kept in this package so MintAndAnchor's collection step carries
// no dependency on the GUI.
func signTransactionLocallyInMint(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	km, err := kbackend.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize key pair: %w", err)
	}

	sphincsParams := km.GetSPHINCSParameters()
	if sphincsParams == nil || sphincsParams.Params == nil {
		return fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	signingMgr := sbackend.NewSTHINCSManager(nil, km, sphincsParams)
	bundle, err := signingMgr.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
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
