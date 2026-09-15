// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/rpc.go
package gui

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/storage"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
)

// NewWalletClient creates a new wallet RPC client.
//
// nodeAddr MUST be the node's dedicated wallet/JSON-RPC address — the
// nodeConfig.WSPort slot (see port.go's baseWSPort, default
// 127.0.0.1:8700), NOT the P2P gossip TCP address (baseTCPPort/32307) and
// NOT the HTTP/Gin address.
//
//   - The P2P gossip port (bind.StartNode's SECTION 11 listener) is served
//     by bind.handleIncomingConn, which speaks the unencrypted P2P wire
//     protocol (key_exchange, peer_exchange, checkpoint, get_blocks,
//     consensus messages) and has no "jsonrpc" case at all.
//   - The HTTP server (go/src/http) is a plain REST API
//     (/transaction, /blockcount, ...) with no JSON-RPC bridge.
//   - bind.StartNode's SECTION 11a starts a transport.TCPServer bound to
//     nodeConfig.WSPort specifically for this: transport.TCPServer.
//     handleConnection (tcp.go) is the only listener that performs the
//     handshake and forwards Type:"jsonrpc" requests into
//     rpc.Server.HandleRequest, and rpc.CallRPC (client.go) is written to
//     speak exactly its protocol (handshake + Type:"jsonrpc" + encrypted
//     framing).
func NewWalletClient(nodeAddr string) *WalletClient {
	if nodeAddr == "" {
		// Fallback to environment variable, then default
		if envAddr := os.Getenv("SPHINX_RPC_ADDR"); envAddr != "" {
			nodeAddr = envAddr
		} else {
			// Default to the dedicated wallet/JSON-RPC port (WSPort slot,
			// baseWSPort=8700), not the P2P gossip port (32307) and not the
			// HTTP port (8545/8645) — neither of those has a jsonrpc
			// handler, so pointing here previously guaranteed every wallet
			// RPC call would fail or be silently misrouted.
			nodeAddr = "127.0.0.1:8700"
		}
	}
	return &WalletClient{
		nodeAddr: nodeAddr,
	}
}

// normaliseAddress converts a SPIF formatted address to raw hex.
func normaliseAddress(addr string) (string, error) {
	if addr == "" {
		return "", errors.New("empty address")
	}
	raw, err := common.NormalizeSPIFAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %w", err)
	}
	return raw, nil
}

// sameIdentity reports whether two address forms denote the same identity.
//
// Contract storage and chain records hold the canonical raw UPPERCASE hex form
// (ownerOf / seller / licensee / token creator / tx sender), while the session
// carries the display form ("SPIF F6F6 F6F6 …"). A plain == therefore never
// matches across the two, which would stop a minter from ever listing their own
// token (and silently mis-label transaction direction). Both sides are
// collapsed through common.NormalizeSPIFAddress, which accepts prefixed, spaced,
// and raw hex forms alike; when either side is not a parseable address (empty,
// or a system address such as "genesis") it falls back to a trimmed,
// case-insensitive comparison so callers still get sane behaviour.
func sameIdentity(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	rawA, errA := common.NormalizeSPIFAddress(a)
	rawB, errB := common.NormalizeSPIFAddress(b)
	if errA == nil && errB == nil {
		return rawA == rawB
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// GetBalance fetches balance for an address
func (c *WalletClient) GetBalance(address string) (*BalanceResponse, error) {
	if address == "" {
		address = sessionFingerprint
	}
	if address == "" {
		return nil, errors.New("no address provided")
	}

	// Normalise to raw hex
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return nil, err
	}

	log.Printf("[WalletRPC] GetBalance: fetching for %s", rawAddress[:16]+"...")

	params := []interface{}{rawAddress}
	resultData, err := rpc.CallRPC(c.nodeAddr, "getbalance", params, 60)
	if err != nil {
		log.Printf("[WalletRPC] RPC call failed: %v", err)
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty response from RPC")
	}

	var resp BalanceResponse
	if err := json.Unmarshal(resultData, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &resp, nil
}

// ────────────────────────────────────────────────────────────────────────
// ANCHOR CONFIRMATION PROVENANCE
// ────────────────────────────────────────────────────────────────────────

// TxConfirmation records where a transaction was committed on-chain.
type TxConfirmation struct {
	Height uint64 // block height that included the transaction
	Hash   string // hex hash of the confirming block
}

// TxRejectedError reports that the node TERMINALLY rejected a transaction.
type TxRejectedError struct {
	TxID   string
	Reason string
}

func (e *TxRejectedError) Error() string {
	return fmt.Sprintf("transaction %s was rejected by the node and can never confirm: %s", e.TxID, e.Reason)
}

// confirmedBlockInfo adapts a TxConfirmation to the sign package's
// RefreshOnChainProvenance confirmedBlock interface (GetHeight/GetHash).
type confirmedBlockInfo struct {
	height uint64
	hash   string
}

func (c *confirmedBlockInfo) GetHeight() uint64 { return c.height }
func (c *confirmedBlockInfo) GetHash() string   { return c.hash }

// GetTxConfirmation asks the node where a transaction was committed. Returns
// (nil, nil) while the tx is still pending/uncommitted so callers can simply
// poll; an error means the RPC itself failed.
func (c *WalletClient) GetTxConfirmation(txID string) (*TxConfirmation, error) {
	if strings.TrimSpace(txID) == "" {
		return nil, errors.New("empty txid")
	}
	resultData, err := rpc.CallRPC(c.nodeAddr, "gettransactionreceipt", []interface{}{txID}, 30)
	if err != nil {
		return nil, fmt.Errorf("gettransactionreceipt rpc: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty gettransactionreceipt response")
	}
	var result struct {
		Confirmed     bool           `json:"confirmed"`
		Height        uint64         `json:"height"`
		BlockHash     string         `json:"blockhash"`
		Pool          map[string]int `json:"pool"`
		InvalidReason string         `json:"invalid_reason"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return nil, fmt.Errorf("parse gettransactionreceipt: %w", err)
	}
	if len(result.Pool) > 0 {
		log.Printf("[WalletRPC] GetTxConfirmation: txid=%s pool(broadcast=%d validating=%d pending=%d invalid=%d total=%d)",
			txID,
			result.Pool["broadcast"], result.Pool["validating"], result.Pool["pending"],
			result.Pool["invalid"], result.Pool["total"])
	}
	if strings.TrimSpace(result.InvalidReason) != "" {
		log.Printf("[WalletRPC] GetTxConfirmation: txid=%s INVALID — reason: %s", txID, result.InvalidReason)
		return nil, &TxRejectedError{TxID: txID, Reason: strings.TrimSpace(result.InvalidReason)}
	}
	if !result.Confirmed {
		return nil, nil
	}
	return &TxConfirmation{Height: result.Height, Hash: result.BlockHash}, nil
}

// WaitForTxConfirmation polls the node until the transaction is committed to a
// block or the timeout elapses.
func (c *WalletClient) WaitForTxConfirmation(txID string, timeout time.Duration) (*TxConfirmation, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		conf, err := c.GetTxConfirmation(txID)
		if err == nil && conf != nil {
			log.Printf("[WalletRPC] WaitForTxConfirmation: txid=%s confirmed at height=%d hash=%s", txID, conf.Height, conf.Hash)
			return conf, nil
		}
		if err != nil {
			var rejected *TxRejectedError
			if errors.As(err, &rejected) {
				log.Printf("[WalletRPC] WaitForTxConfirmation: txid=%s REJECTED — %v", txID, rejected)
				return nil, rejected
			}
			log.Printf("[WalletRPC] WaitForTxConfirmation: poll txid=%s: %v", txID, err)
		}
		if time.Now().After(deadline) {
			log.Printf("[WalletRPC] WaitForTxConfirmation: txid=%s still unconfirmed after %s", txID, timeout)
			return nil, nil
		}
		<-ticker.C
	}
}

// ────────────────────────────────────────────────────────────────────────
// LIGHTWEIGHT (HEADER-ONLY) SYNC PATH
// ────────────────────────────────────────────────────────────────────────

// GetChainTipHeader fetches ONLY the chain-tip block header from the node.
func (c *WalletClient) GetChainTipHeader() (*types.BlockHeader, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "getblockheader", []interface{}{"latest"}, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty response from RPC")
	}
	var hdr types.BlockHeader
	if err := json.Unmarshal(resultData, &hdr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &hdr, nil
}

// GetBlockHeader fetches ONLY the header of the block at `height` (0 = genesis).
func (c *WalletClient) GetBlockHeader(height uint64) (*types.BlockHeader, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "getblockheader", []interface{}{height}, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, errors.New("empty response from RPC")
	}
	var hdr types.BlockHeader
	if err := json.Unmarshal(resultData, &hdr); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &hdr, nil
}

// GetHeaders downloads a batch of block headers — headers only, never block
// bodies.
func (c *WalletClient) GetHeaders(start uint64, count int) ([]types.BlockHeader, error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "getheaders", []interface{}{start, count}, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return []types.BlockHeader{}, nil
	}
	var hdrs []types.BlockHeader
	if err := json.Unmarshal(resultData, &hdrs); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return hdrs, nil
}

// pendingNonceMu / pendingNonce guard against a wallet-process-local nonce
// race.
var (
	pendingNonceMu sync.Mutex
	pendingNonce   = map[string]uint64{} // raw sender address -> next unclaimed nonce
)

// getCurrentNonce gets the next nonce to use for `address` from the node.
func (c *WalletClient) getCurrentNonce(address string) (uint64, error) {
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return 0, err
	}
	resultData, err := rpc.CallRPC(c.nodeAddr, "getnonce", []interface{}{rawAddress}, 60)
	if err != nil {
		return 0, err
	}
	var chainNonce uint64
	if err := json.Unmarshal(resultData, &chainNonce); err != nil {
		return 0, err
	}

	pendingNonceMu.Lock()
	next := chainNonce
	if reserved, ok := pendingNonce[rawAddress]; ok && reserved > next {
		next = reserved
	}
	// ★ FIX: also account for reservations made by the mint package
	// (BroadcastSIP721CollectionMintWithTerms / broadcastReceiptAnchor use
	// their own reserveNextNonce cache in sip721_tx.go). Without this check,
	// a mint-package broadcast that already claimed a nonce — but whose tx
	// hasn't committed yet — is invisible to this cache: a GUI action right
	// after it (e.g. Deploy New Collection) re-reads the same on-chain
	// nonce and collides with the mempool's pending-aware
	// accountNonceIndex, producing "invalid nonce: N must equal N+1".
	// mint.PeekReservedNonce exists precisely to close this gap but was
	// never actually called anywhere until now.
	if mintReserved, ok := mint.PeekReservedNonce(c.nodeAddr, rawAddress); ok && mintReserved > next {
		next = mintReserved
	}
	pendingNonce[rawAddress] = next + 1
	pendingNonceMu.Unlock()

	// Mirror this claim into the mint package's reservation so a SIP-721
	// collection mint that follows this broadcast never re-reads the same
	// committed on-chain nonce.
	mint.AdvanceReservation(c.nodeAddr, rawAddress, next+1)

	return next, nil
}

// releasePendingNonce rolls back a reservation made by getCurrentNonce when
// the transaction that was going to consume it was never actually broadcast.
func (c *WalletClient) releasePendingNonce(address string, nonce uint64) {
	mint.ReleaseReservation(c.nodeAddr, address, nonce)

	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return
	}
	pendingNonceMu.Lock()
	defer pendingNonceMu.Unlock()
	if pendingNonce[rawAddress] == nonce+1 {
		pendingNonce[rawAddress] = nonce
	}
}

// advanceMintReservation pushes a GUI-side claim into the mint package's
// reservation.
func (c *WalletClient) advanceMintReservation(address string, next uint64) {
	mint.AdvanceReservation(c.nodeAddr, address, next)
}

// SendTransaction sends funds to a recipient
func (c *WalletClient) SendTransaction(toAddress string, amount *big.Int, memo string) (string, error) {
	if sessionPassphrase == "" {
		return "", errors.New("not logged in")
	}
	if toAddress == "" {
		return "", errors.New("recipient required")
	}
	if amount == nil || amount.Sign() <= 0 {
		return "", errors.New("invalid amount")
	}

	rawTo, err := normaliseAddress(toAddress)
	if err != nil {
		return "", fmt.Errorf("invalid recipient address: %w", err)
	}

	rawSender, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return "", fmt.Errorf("invalid sender address: %w", err)
	}

	log.Printf("[WalletRPC] SendTransaction: sending %s to %s",
		amount.String(), rawTo[:16]+"...")

	kp, skBytes, err := keys.LoadKeyFromDisk(sessionPassphrase)
	if err != nil {
		return "", fmt.Errorf("failed to load key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()

	var nonce uint64
	if cachedNonce, err := c.getCurrentNonce(sessionFingerprint); err == nil {
		nonce = cachedNonce
		log.Printf("[WalletRPC] Using RPC nonce: %d", nonce)
	} else {
		return "", fmt.Errorf("failed to get account nonce from node: %w", err)
	}

	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	gasQuote := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(len(memo)))

	tx := &types.Transaction{
		ID:         "",
		ChainID:    chainID,
		Sender:     rawSender,
		Receiver:   rawTo,
		Amount:     amount,
		GasLimit:   gasQuote.GasLimit,
		GasPrice:   gasQuote.GasPrice,
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		Signature:  []byte{},
		ReturnData: []byte(memo),
	}
	tx.ID = tx.Hash()

	if err := signTransactionLocally(tx, skBytes, kp.PublicKey); err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	txData, err := json.Marshal(tx)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("failed to marshal transaction: %w", err)
	}
	rawTx := hex.EncodeToString(txData)

	resultData, err := rpc.CallRPC(c.nodeAddr, "sendrawtransaction", []interface{}{rawTx}, 120)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("RPC error: %w", err)
	}

	if len(resultData) == 0 || string(resultData) == "null" {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", errors.New("empty response")
	}

	var result struct {
		TxID   string `json:"txid"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Error != "" {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("tx rejected: %s", result.Error)
	}

	if strings.TrimSpace(result.TxID) == "" {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", errors.New("node returned empty txid — transaction may have been rejected")
	}

	return result.TxID, nil
}

// ────────────────────────────────────────────────────────────────────────
// SIP-721 MARKETPLACE + LICENSING
// ────────────────────────────────────────────────────────────────────────

// SIP721Listing mirrors contracts.SIP721Listing for GUI display.
type SIP721Listing struct {
	Seller string
	Price  *big.Int // nSPX
}

// SIP721Terms mirrors contracts.SIP721TokenTerms for GUI display.
type SIP721Terms struct {
	Creator          string
	RoyaltyBPS       uint64
	RoyaltyRecipient string
	UsageFeeNSPX     *big.Int // nil = no licensing
	CurrentLicensee  string   // "" = unlicensed
}

// parsePositiveDecimalNSPX validates GUI-entered nSPX input: positive decimal
// integer.
func parsePositiveDecimalNSPX(raw string) (*big.Int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("amount required (positive decimal nSPX)")
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() <= 0 {
		return nil, fmt.Errorf("invalid amount %q (positive decimal nSPX required)", raw)
	}
	return v, nil
}

// parseSPXToNSPX converts GUI-entered SPX decimal (e.g. "0.05") to integer
// nSPX.
func parseSPXToNSPX(raw string) (*big.Int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("amount required (SPX)")
	}
	f, ok := new(big.Float).SetPrec(256).SetString(s)
	if !ok || f.Sign() <= 0 {
		return nil, fmt.Errorf("invalid amount %q (positive SPX required)", raw)
	}
	mult := new(big.Float).SetPrec(256).SetInt(big.NewInt(1e18))
	v, _ := new(big.Float).SetPrec(256).Mul(f, mult).Int(nil)
	if v == nil || v.Sign() <= 0 {
		return nil, fmt.Errorf("amount %q is too small to represent in nSPX", raw)
	}
	return v, nil
}

// formatTokenID validates a GUI-entered token id: positive decimal integer.
func formatTokenID(raw string) (string, error) {
	v := ""
	for _, r := range raw {
		if r == ' ' || r == '\t' || r == '\n' {
			continue
		}
		v += string(r)
	}
	if v == "" {
		return "", errors.New("missing token_id")
	}
	var n uint64
	for _, r := range v {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("invalid token_id: %s", raw)
		}
		n = n*10 + uint64(r-'0')
	}
	if n == 0 {
		return "", fmt.Errorf("invalid token_id: %s", raw)
	}
	return v, nil
}

// decodeStorageHex unwraps a getcontractstorage JSON response (hex string).
func decodeStorageHex(raw []byte) []byte {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var hexStr string
	if jerr := json.Unmarshal(raw, &hexStr); jerr == nil {
		decoded, derr := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
		if derr != nil || len(decoded) == 0 {
			return nil
		}
		return decoded
	}
	payload := []byte(strings.Trim(string(raw), "\""))
	if len(payload) == 0 {
		return nil
	}
	return payload
}

// GetSIP721Listing reads a token's listing via getcontractstorage.
func (c *WalletClient) GetSIP721Listing(collection, tokenID string) (*SIP721Listing, error) {
	tokenID, err := formatTokenID(tokenID)
	if err != nil {
		return nil, err
	}
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return nil, errors.New("collection contract address required")
	}
	raw, err := rpc.CallRPC(c.nodeAddr, "getcontractstorage",
		[]interface{}{collection, "sip721:token:" + tokenID + ":listing"}, 60)
	if err != nil {
		return nil, fmt.Errorf("getcontractstorage: %w", err)
	}
	payload := decodeStorageHex(raw)
	if len(payload) == 0 {
		return nil, nil
	}
	var listing struct {
		Seller string `json:"seller"`
		Price  string `json:"price_nspx"`
	}
	if uerr := json.Unmarshal(payload, &listing); uerr != nil {
		return nil, nil
	}
	if listing.Seller == "" || listing.Price == "" {
		return nil, nil
	}
	price, ok := new(big.Int).SetString(listing.Price, 10)
	if !ok || price.Sign() <= 0 {
		return nil, nil
	}
	return &SIP721Listing{Seller: listing.Seller, Price: price}, nil
}

// signTransactionLocally signs a transaction using the node's canonical
// SPHINCS+ transaction authentication path.
func signTransactionLocally(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
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
		return fmt.Errorf("failed to deserialize key pair: %w", err)
	}

	sphincsParams := km.GetSPHINCSParameters()
	if sphincsParams == nil || sphincsParams.Params == nil {
		return fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	signingMgr := sign.NewSTHINCSManager(nil, km, sphincsParams)
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

// GetTransactionHistory fetches recent transactions
func (c *WalletClient) GetTransactionHistory(address string, limit int) ([]TransactionResponse, error) {
	if address == "" {
		address = sessionFingerprint
	}
	if address == "" {
		return nil, errors.New("no address provided")
	}
	if limit <= 0 {
		limit = 20
	}

	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return nil, err
	}

	log.Printf("[WalletRPC] GetTransactionHistory: fetching for %s", rawAddress[:16]+"...")

	params := []interface{}{rawAddress, limit}
	resultData, err := rpc.CallRPC(c.nodeAddr, "gettransactionhistory", params, 60)
	if err != nil {
		return nil, fmt.Errorf("RPC call failed: %w", err)
	}

	if len(resultData) == 0 || string(resultData) == "null" {
		return []TransactionResponse{}, nil
	}

	return parseTransactionHistory(resultData)
}

// historyWireTx is the tolerant wire form of one transaction in the node's
// gettransactionhistory result.
//
// ★ FIX: this used to be types.Transaction, whose Amount/Fee are *big.Int.
// A plain *big.Int only accepts plain decimal text, so a node (or an older
// wallet build whose rpc.CallRPC round-tripped numbers through float64) that
// renders a large nSPX amount in exponent notation — "amount": 1e+25 — made
// the whole history decode fail with:
//
//	parse response: math/big: cannot unmarshal "1e+25" into a *big.Int
//
// Every numeric field is therefore typed BigInt, which accepts plain decimal
// integers, quoted values, and scientific notation alike (see types.go), so a
// history response is never rejected because of how a number was rendered.
type historyWireTx struct {
	TxID       string `json:"txid"` // some callers/nodes label the hash "txid"
	ID         string `json:"id"`   // the node's Transaction marshals it as "id"
	Sender     string `json:"sender"`
	Receiver   string `json:"receiver"`
	Amount     BigInt `json:"amount"`
	Fee        BigInt `json:"fee"`
	Timestamp  BigInt `json:"timestamp"` // unix seconds, tolerant of float rendering
	Status     string `json:"status"`
	ReturnData []byte `json:"return_data"` // OP_RETURN memo (base64 on the wire)
}

// parseTransactionHistory converts the raw gettransactionhistory result into
// the wallet's TransactionResponse values. Kept free of network and session
// state so the wire format is directly testable.
func parseTransactionHistory(resultData []byte) ([]TransactionResponse, error) {
	if len(resultData) == 0 || string(resultData) == "null" {
		return []TransactionResponse{}, nil
	}

	var rawTxs []historyWireTx
	if err := json.Unmarshal(resultData, &rawTxs); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	txs := make([]TransactionResponse, 0, len(rawTxs))
	for _, tx := range rawTxs {
		id := tx.TxID
		if id == "" {
			id = tx.ID
		}
		status := tx.Status
		if status == "" {
			status = "confirmed"
		}
		resp := TransactionResponse{
			TxID:       id,
			Sender:     tx.Sender,
			Receiver:   tx.Receiver,
			Amount:     tx.Amount,
			Fee:        tx.Fee,
			ReturnData: tx.ReturnData,
			Status:     status,
		}
		// A missing/zero timestamp means "unknown" and stays the zero time so
		// the wallet screen's IsZero() check hides it, rather than rendering
		// the 1970 epoch as if it were real.
		if tx.Timestamp.Int != nil && tx.Timestamp.Int.Sign() != 0 {
			resp.Timestamp = time.Unix(tx.Timestamp.Int.Int64(), 0)
		}
		txs = append(txs, resp)
	}

	return txs, nil
}

// newSIP721CallTx is the GUI-local equivalent of abi.NewSIP721CallTx.
func newSIP721CallTx(chainID uint64, sender string, nonce uint64, collection, method string, args map[string]string) (*types.Transaction, error) {
	if sender == "" || collection == "" {
		return nil, errors.New("sender and contract address are required")
	}
	method = strings.ToLower(strings.TrimSpace(method))
	switch method {
	case "mint", "transfer_from", "approve", "owner_of", "token_uri", "token_id_of_mint",
		"purchase_license", "revoke_license", "terms_of", "list", "buy", "cancel", "listing_of", "info":
	default:
		return nil, fmt.Errorf("unsupported sip721 method: %s", method)
	}
	if args == nil {
		args = map[string]string{}
	}
	callData, err := json.Marshal(map[string]interface{}{"method": method, "args": args})
	if err != nil {
		return nil, fmt.Errorf("encode sip721 call: %w", err)
	}
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contractQuote := p.QuoteContractGas(false, 0, uint64(len(callData)), 0)
	return &types.Transaction{
		ChainID:    chainID,
		Sender:     sender,
		Amount:     big.NewInt(0),
		Nonce:      nonce,
		ToContract: collection,
		CallData:   callData,
		GasLimit:   new(big.Int).Add(base.GasLimit, contractQuote.GasLimit),
		GasPrice:   new(big.Int).Set(base.GasPrice),
	}, nil
}

// GetSIP721Terms reads a token's frozen terms + current licensee.
func (c *WalletClient) GetSIP721Terms(collection, tokenID string) (*SIP721Terms, error) {
	tokenID, err := formatTokenID(tokenID)
	if err != nil {
		return nil, err
	}
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return nil, errors.New("collection contract address required")
	}
	raw, err := rpc.CallRPC(c.nodeAddr, "getcontractstorage",
		[]interface{}{collection, "sip721:token:" + tokenID + ":terms"}, 60)
	if err != nil {
		return nil, fmt.Errorf("getcontractstorage: %w", err)
	}
	payload := decodeStorageHex(raw)
	if len(payload) == 0 {
		return nil, fmt.Errorf("token %s has no embedded terms", tokenID)
	}
	var terms struct {
		Creator          string `json:"creator"`
		RoyaltyBPS       uint64 `json:"royalty_bps"`
		RoyaltyRecipient string `json:"royalty_recipient"`
		UsageFeeNSPX     string `json:"usage_fee_nspx"`
	}
	if uerr := json.Unmarshal(payload, &terms); uerr != nil {
		return nil, fmt.Errorf("token %s has no embedded terms", tokenID)
	}
	out := &SIP721Terms{
		Creator:          terms.Creator,
		RoyaltyBPS:       terms.RoyaltyBPS,
		RoyaltyRecipient: terms.RoyaltyRecipient,
	}
	if out.RoyaltyRecipient == "" {
		out.RoyaltyRecipient = out.Creator
	}
	if strings.TrimSpace(terms.UsageFeeNSPX) != "" {
		if fee, ok := new(big.Int).SetString(strings.TrimSpace(terms.UsageFeeNSPX), 10); ok && fee.Sign() > 0 {
			out.UsageFeeNSPX = fee
		}
	}
	if lraw, lerr := rpc.CallRPC(c.nodeAddr, "getcontractstorage",
		[]interface{}{collection, "sip721:token:" + tokenID + ":licensee"}, 60); lerr == nil {
		if lpayload := decodeStorageHex(lraw); lpayload != nil {
			out.CurrentLicensee = string(lpayload)
		}
	}
	return out, nil
}

// GetSIP721Owner reads ownerOf[tokenId] via getcontractstorage.
func (c *WalletClient) GetSIP721Owner(collection, tokenID string) (string, error) {
	tokenID, err := formatTokenID(tokenID)
	if err != nil {
		return "", err
	}
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return "", errors.New("collection contract address required")
	}
	raw, err := rpc.CallRPC(c.nodeAddr, "getcontractstorage",
		[]interface{}{collection, "sip721:token:" + tokenID + ":owner"}, 60)
	if err != nil {
		return "", fmt.Errorf("getcontractstorage: %w", err)
	}
	payload := decodeStorageHex(raw)
	if len(payload) == 0 {
		return "", fmt.Errorf("token %s does not exist", tokenID)
	}
	return string(payload), nil
}

// CallSIP721 builds, signs, and broadcasts a SIP-721 contract call.
//
// ★ FIX: this path already claims a nonce via getCurrentNonce and injects it
// into the tx (newSIP721CallTx takes the nonce as a parameter), and releases
// on every failure path. No change needed here beyond what is already present
// — included verbatim so the file is complete.
func (c *WalletClient) CallSIP721(collection, method string, args map[string]string, amountNSPX *big.Int) (string, error) {
	if sessionPassphrase == "" {
		return "", errors.New("not logged in")
	}
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return "", errors.New("collection contract address required")
	}
	rawSender, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return "", fmt.Errorf("invalid sender address: %w", err)
	}
	nonce, err := c.getCurrentNonce(sessionFingerprint)
	if err != nil {
		return "", fmt.Errorf("failed to get account nonce from node: %w", err)
	}
	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}
	unsignedTx, err := newSIP721CallTx(chainID, rawSender, nonce, collection, method, args)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", err
	}
	if amountNSPX != nil && amountNSPX.Sign() > 0 {
		unsignedTx.Amount = new(big.Int).Set(amountNSPX)
	}
	unsignedTx.Timestamp = time.Now().Unix()
	unsignedTx.ID = unsignedTx.Hash()

	kp, skBytes, err := keys.LoadKeyFromDisk(sessionPassphrase)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("failed to load key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
			_ = i
		}
	}()
	if err := signTransactionLocally(unsignedTx, skBytes, kp.PublicKey); err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("failed to sign contract call: %w", err)
	}
	txData, err := json.Marshal(unsignedTx)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("failed to marshal contract call: %w", err)
	}
	resultData, err := rpc.CallRPC(c.nodeAddr, "sendrawtransaction", []interface{}{hex.EncodeToString(txData)}, 120)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("RPC error: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", errors.New("empty response")
	}
	var result struct {
		TxID   string `json:"txid"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("parse response: %w", err)
	}
	if result.Error != "" {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", fmt.Errorf("tx rejected: %s", result.Error)
	}
	if strings.TrimSpace(result.TxID) == "" {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", errors.New("node returned empty txid — transaction may have been rejected")
	}
	return result.TxID, nil
}

// ───────────────────────────────────────────────────────────────────────
// COLLECTION LIFECYCLE
// ────────────────────────────────────────────────────────────────────────

// SIP721CollectionInfo mirrors contracts.SIP721Info for GUI display.
type SIP721CollectionInfo struct {
	Address     string
	Name        string
	Symbol      string
	Owner       string
	NextTokenID uint64
}

// SIP721TokenSummary is one discoverable minted-data token.
type SIP721TokenSummary struct {
	Collection string
	TokenID    uint64
	Owner      string

	TokenURI    string
	Name        string
	Description string
	Subject     string
	Creator     string

	Listed    bool
	Seller    string
	PriceNSPX *big.Int

	HasTerms       bool
	RoyaltyBPS     uint64
	LicenseFeeNSPX *big.Int
	Licensee       string
}

// Buyable reports whether `buyer` can buy this token right now.
func (s SIP721TokenSummary) Buyable(buyer string) bool {
	return s.Listed && s.Seller != "" && !sameIdentity(s.Seller, buyer) &&
		s.PriceNSPX != nil && s.PriceNSPX.Sign() > 0
}

// Rentable reports whether `licensee` can license this token right now.
func (s SIP721TokenSummary) Rentable(licensee string) bool {
	return s.HasTerms && s.LicenseFeeNSPX != nil && s.LicenseFeeNSPX.Sign() > 0 &&
		!sameIdentity(s.Licensee, licensee)
}

// Label renders a one-line summary for list widgets.
func (s SIP721TokenSummary) Label() string {
	name := strings.TrimSpace(s.Name)
	if name == "" {
		if s.Subject != "" {
			name = s.Subject
		} else {
			name = "Token"
		}
	}
	parts := []string{fmt.Sprintf("%s  #%d", name, s.TokenID)}
	if s.Listed && s.PriceNSPX != nil {
		parts = append(parts, "sale "+formatNSPXAmount(s.PriceNSPX)+" SPX")
	}
	if s.HasTerms && s.LicenseFeeNSPX != nil {
		parts = append(parts, "rent "+formatNSPXAmount(s.LicenseFeeNSPX)+" SPX")
	}
	if !s.Listed && s.LicenseFeeNSPX == nil {
		parts = append(parts, "not for sale")
	}
	return strings.Join(parts, " · ")
}

// GetSIP721CollectionInfo reads the collection's sip721:info record.
func (c *WalletClient) GetSIP721CollectionInfo(collection string) (*SIP721CollectionInfo, error) {
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return nil, errors.New("collection contract address required")
	}
	raw, err := rpc.CallRPC(c.nodeAddr, "getcontractstorage",
		[]interface{}{collection, "sip721:info"}, 60)
	if err != nil {
		return nil, fmt.Errorf("getcontractstorage: %w", err)
	}
	payload := decodeStorageHex(raw)
	if len(payload) == 0 {
		return nil, fmt.Errorf("%s is not a SIP-721 collection", collection)
	}
	var info struct {
		Name        string `json:"name"`
		Symbol      string `json:"symbol"`
		Owner       string `json:"owner"`
		NextTokenID uint64 `json:"next_token_id"`
	}
	if uerr := json.Unmarshal(payload, &info); uerr != nil {
		return nil, fmt.Errorf("%s is not a SIP-721 collection", collection)
	}
	return &SIP721CollectionInfo{
		Address:     collection,
		Name:        info.Name,
		Symbol:      info.Symbol,
		Owner:       info.Owner,
		NextTokenID: info.NextTokenID,
	}, nil
}

// sip721DeploySpec mirrors contracts.DeploySpec's wire form.
type sip721DeploySpec struct {
	Runtime  string `json:"runtime"`
	Standard string `json:"standard"`
	Name     string `json:"name,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	Owner    string `json:"owner,omitempty"`
}

// sip721DeployGasLimit returns the policy gas limit for broadcasting a
// deployment whose deploy-code is codeBytes long.
func sip721DeployGasLimit(codeBytes uint64) *big.Int {
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contract := p.QuoteContractGas(true, codeBytes, 0, 0)
	return new(big.Int).Add(base.GasLimit, contract.GasLimit)
}

// DeploySIP721Collection deploys an empty SIP-721 collection owned by the
// logged-in identity and waits until its sip721:info record is readable.
//
// ★ FIX: the deploy now claims its nonce via getCurrentNonce (the wallet's
// pending-aware reservation cache) BEFORE asking the node to build the tx,
// passes it to deploycontract, and — crucially — FORCES it onto the tx the
// node returns. The node's deploycontract handler reads the raw state DB
// nonce, which does not account for our own in-flight broadcasts; using it
// verbatim collides with the mempool's pending-aware accountNonceIndex and
// is rejected with "invalid nonce: N must equal N+1". The wallet's
// reservation is authoritative for this process. Every failure path between
// the reservation and a successful broadcast releases it via
// releasePendingNonce so a skipped nonce does not strand the account.
func (c *WalletClient) DeploySIP721Collection(name, symbol string) (string, string, error) {
	if sessionPassphrase == "" {
		return "", "", errors.New("not logged in")
	}
	name = strings.TrimSpace(name)
	symbol = strings.ToUpper(strings.TrimSpace(symbol))
	if name == "" {
		return "", "", errors.New("collection name required")
	}
	if symbol == "" {
		return "", "", errors.New("collection symbol required")
	}
	rawOwner, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return "", "", fmt.Errorf("invalid sender address: %w", err)
	}

	codeJSON, err := json.Marshal(sip721DeploySpec{
		Runtime:  "native",
		Standard: "sip721",
		Name:     name,
		Symbol:   symbol,
		Owner:    rawOwner,
	})
	if err != nil {
		return "", "", fmt.Errorf("encode deploy spec: %w", err)
	}

	deployGasLimit := sip721DeployGasLimit(uint64(len(codeJSON)))

	// ★ FIX: claim the wallet's next nonce BEFORE asking the node to build
	// the deploy tx. The node's deploycontract handler reads the raw state
	// DB nonce, which does not account for our own in-flight broadcasts (and
	// now lags the mempool's pending-aware getnonce). Passing it explicitly
	// and forcing it onto the returned tx keeps the deploy's slot consistent
	// with every other broadcast this wallet makes.
	deployNonce, nerr := c.getCurrentNonce(sessionFingerprint)
	if nerr != nil {
		return "", "", fmt.Errorf("failed to get account nonce from node: %w", nerr)
	}

	// Object-shaped params (deploycontract unmarshals into a struct, not a
	// positional array) — CallRPC passes this through verbatim.
	resultData, err := rpc.CallRPC(c.nodeAddr, "deploycontract", map[string]interface{}{
		"from":     rawOwner,
		"code":     hex.EncodeToString(codeJSON),
		"gasLimit": deployGasLimit.Uint64(),
		"gasPrice": policy.GetDefaultPolicyParams().MinimumGasPrice.String(),
		"nonce":    deployNonce,
	}, 60)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("deploycontract rpc: %w", err)
	}
	var out struct {
		Tx              string `json:"tx"`
		ContractAddress string `json:"contractAddress"`
		Error           string `json:"error"`
	}
	if err := json.Unmarshal(resultData, &out); err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("parse deploycontract: %w", err)
	}
	if out.Error != "" {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("deploy rejected: %s", out.Error)
	}
	if strings.TrimSpace(out.Tx) == "" || strings.TrimSpace(out.ContractAddress) == "" {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", errors.New("deploycontract returned no transaction")
	}

	collection := strings.TrimSpace(out.ContractAddress)
	if !common.ValidateSPIFAddress(collection) {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("node returned an invalid contract address %q (not a valid SPIF address)", collection)
	}
	// ★ FIX: collapse whatever rendering the node returned into the single
	// canonical form. Current nodes send the grouped "SPIF XXXX XXXX …" form,
	// but stale nodes may still send the legacy "SPIF"+40-lowercase-hex form.
	// The wallet carries this address for the lifetime of the collection — it
	// becomes the mint tx's ToContract and the key for getcontractstorage reads
	// — so normalising here keeps every downstream lookup byte-for-byte aligned
	// with the node's on-disk contract key instead of depending on the node to
	// accept a differently-rendered address.
	if raw, cerr := common.NormalizeSPIFAddress(collection); cerr == nil {
		if canonical, ferr := common.FormatSPIFAddress(raw); ferr == nil {
			if canonical != collection {
				log.Printf("[WalletRPC] DeploySIP721Collection: normalised node-returned contract address %q to canonical SPIF form %q", collection, canonical)
			}
			collection = canonical
		}
	}

	txBytes, err := hex.DecodeString(strings.TrimPrefix(out.Tx, "0x"))
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("decode deploy tx: %w", err)
	}
	var tx types.Transaction
	if err := json.Unmarshal(txBytes, &tx); err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("parse deploy tx: %w", err)
	}
	// ★ FIX: force the wallet-reserved nonce. The node's deploycontract
	// handler derives the nonce from state (which does not know about our
	// own in-flight broadcasts); using it verbatim collides with the
	// mempool's pending-aware accountNonceIndex and gets rejected with
	// "invalid nonce: N must equal N+1". The wallet's reservation is
	// authoritative for this process.
	tx.Nonce = deployNonce
	tx.Timestamp = time.Now().Unix()

	kp, skBytes, err := keys.LoadKeyFromDisk(sessionPassphrase)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("failed to load key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()
	if err := signTransactionLocally(&tx, skBytes, kp.PublicKey); err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("failed to sign deploy tx: %w", err)
	}
	signedJSON, err := json.Marshal(&tx)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("failed to marshal deploy tx: %w", err)
	}
	sendData, err := rpc.CallRPC(c.nodeAddr, "sendrawtransaction",
		[]interface{}{hex.EncodeToString(signedJSON)}, 120)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("RPC error: %w", err)
	}
	var sent struct {
		TxID  string `json:"txid"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(sendData, &sent); err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("parse response: %w", err)
	}
	if sent.Error != "" {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("deploy tx rejected: %s", sent.Error)
	}
	if strings.TrimSpace(sent.TxID) == "" {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", errors.New("node returned empty txid — deploy may have been rejected")
	}

	// The collection only exists once the deploy tx is committed; wait for its
	// info record so a follow-up mint cannot race the block. While waiting,
	// also ask the node where the deploy tx actually is
	// (gettransactionreceipt), so a failure is reported with its EXACT cause
	// instead of a blind 90-second "not readable yet" timeout.
	deadline := time.Now().Add(90 * time.Second)
	var lastPool string
	var committedHeight uint64
	var committed bool
	for {
		if info, ierr := c.GetSIP721CollectionInfo(collection); ierr == nil && info.Owner != "" {
			return collection, sent.TxID, nil
		}

		if conf, poolStr, invalidReason, derr := c.getTxNodeState(sent.TxID); derr == nil {
			if invalidReason != "" {
				return "", sent.TxID, fmt.Errorf(
					"deploy tx %s was REJECTED by the node and can never confirm: %s",
					sent.TxID, invalidReason)
			}
			if conf != nil {
				committed = true
				committedHeight = conf.Height
			} else if poolStr != "" {
				lastPool = poolStr
				log.Printf("[WalletRPC] DeploySIP721Collection: deploy tx %s uncommitted (%s)", sent.TxID, poolStr)
			}
		}

		if time.Now().After(deadline) {
			if committed {
				return collection, sent.TxID, fmt.Errorf(
					"deploy tx %s committed at height %d but collection %s is still not readable — the contract runtime did not record sip721:info; check the node's block-execution logs",
					sent.TxID, committedHeight, collection)
			}
			return collection, sent.TxID, fmt.Errorf(
				"deploy tx %s was accepted but did not commit within 90s (last mempool state: %s) — if the node is producing blocks check its logs for the validation reason, otherwise confirm block production is running (solo mode mines a block every 10s)",
				sent.TxID, lastPool)
		}
		time.Sleep(2 * time.Second)
	}
}

// getTxNodeState asks the node where a broadcast transaction currently is.
func (c *WalletClient) getTxNodeState(txID string) (conf *TxConfirmation, poolState, invalidReason string, err error) {
	resultData, err := rpc.CallRPC(c.nodeAddr, "gettransactionreceipt", []interface{}{txID}, 30)
	if err != nil {
		return nil, "", "", fmt.Errorf("gettransactionreceipt rpc: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return nil, "", "", errors.New("empty gettransactionreceipt response")
	}
	var result struct {
		Confirmed     bool           `json:"confirmed"`
		Height        uint64         `json:"height"`
		BlockHash     string         `json:"blockhash"`
		Pool          map[string]int `json:"pool"`
		InvalidReason string         `json:"invalid_reason"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return nil, "", "", fmt.Errorf("parse gettransactionreceipt: %w", err)
	}
	if len(result.Pool) > 0 {
		poolState = fmt.Sprintf("broadcast=%d validating=%d pending=%d invalid=%d total=%d",
			result.Pool["broadcast"], result.Pool["validating"], result.Pool["pending"],
			result.Pool["invalid"], result.Pool["total"])
	}
	if strings.TrimSpace(result.InvalidReason) != "" {
		return nil, poolState, strings.TrimSpace(result.InvalidReason), nil
	}
	if result.Confirmed {
		return &TxConfirmation{Height: result.Height, Hash: result.BlockHash}, poolState, "", nil
	}
	return nil, poolState, "", nil
}

// readSIP721TokenURI reads tokenURI[tokenId] (the on-chain ipfs:// pointer).
func (c *WalletClient) readSIP721TokenURI(collection, tokenID string) string {
	raw, err := rpc.CallRPC(c.nodeAddr, "getcontractstorage",
		[]interface{}{collection, "sip721:token:" + tokenID + ":uri"}, 60)
	if err != nil {
		return ""
	}
	return string(decodeStorageHex(raw))
}

// SearchSIP721Tokens discovers the minted data inside a collection.
func (c *WalletClient) SearchSIP721Tokens(collection, query string, limit int) ([]SIP721TokenSummary, error) {
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return nil, errors.New("collection contract address required")
	}
	if limit <= 0 {
		limit = 50
	}
	const maxScanTokens = 200

	info, err := c.GetSIP721CollectionInfo(collection)
	if err != nil {
		return nil, err
	}
	if info.NextTokenID <= 1 {
		return []SIP721TokenSummary{}, nil
	}

	head := info.NextTokenID - 1
	floor := uint64(1)
	if head > maxScanTokens {
		floor = head - maxScanTokens + 1
	}

	needle := strings.ToLower(strings.TrimSpace(query))
	ipfsClient := storage.NewClient(storage.DefaultConfig())
	metadataDeadline := time.Now().Add(8 * time.Second)

	results := make([]SIP721TokenSummary, 0, limit)
	for tokenID := head; tokenID >= floor && tokenID >= 1; tokenID-- {
		tid := fmt.Sprintf("%d", tokenID)
		owner, oerr := c.GetSIP721Owner(collection, tid)
		if oerr != nil || owner == "" {
			continue
		}
		summary := SIP721TokenSummary{
			Collection: collection,
			TokenID:    tokenID,
			Owner:      owner,
			TokenURI:   c.readSIP721TokenURI(collection, tid),
		}

		if listing, lerr := c.GetSIP721Listing(collection, tid); lerr == nil && listing != nil {
			summary.Listed, summary.Seller, summary.PriceNSPX = true, listing.Seller, listing.Price
		}
		if terms, terr := c.GetSIP721Terms(collection, tid); terr == nil && terms != nil {
			summary.HasTerms = true
			summary.Creator = terms.Creator
			summary.RoyaltyBPS = terms.RoyaltyBPS
			summary.Licensee = terms.CurrentLicensee
			if terms.UsageFeeNSPX != nil {
				summary.LicenseFeeNSPX = terms.UsageFeeNSPX
			}
		}

		if summary.TokenURI != "" && time.Now().Before(metadataDeadline) {
			cid := strings.TrimPrefix(strings.TrimSpace(summary.TokenURI), "ipfs://")
			if cid != "" {
				if data, jerr := ipfsClient.GetBytesFromIPFS(cid); jerr == nil {
					var md mint.NFTMetadata
					if jerr := json.Unmarshal(data, &md); jerr == nil {
						summary.Name = md.Name
						summary.Description = md.Description
						summary.Subject = md.Subject
						if summary.Creator == "" {
							summary.Creator = md.MinterPublicKey
						}
					}
				}
			}
		}
		if summary.Subject == "" {
			summary.Subject = info.Symbol
		}

		if needle != "" && !summary.matches(needle) {
			continue
		}
		results = append(results, summary)
		if len(results) >= limit {
			break
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		rank := func(s SIP721TokenSummary) int {
			switch {
			case s.Listed:
				return 0
			case s.LicenseFeeNSPX != nil:
				return 1
			default:
				return 2
			}
		}
		ri, rj := rank(results[i]), rank(results[j])
		if ri != rj {
			return ri < rj
		}
		return results[i].TokenID > results[j].TokenID
	})
	return results, nil
}

// matches reports whether a lowercased needle occurs in any searchable field.
func (s SIP721TokenSummary) matches(needle string) bool {
	haystacks := []string{
		s.Name, s.Description, s.Subject, s.Creator, s.TokenURI,
		fmt.Sprintf("%d", s.TokenID),
	}
	for _, h := range haystacks {
		if h != "" && strings.Contains(strings.ToLower(h), needle) {
			return true
		}
	}
	return false
}
