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
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/storage"
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

// guiRPC adapts the wallet's rpc.CallRPC to abi.RPCClient, so the shared
// abi.Transact path can reach the node without abi importing src/rpc.
type guiRPC struct{}

func (guiRPC) CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	return rpc.CallRPC(nodeAddr, method, params, ttlSeconds)
}

// chainIDFor returns the network's EIP-155 chain id, falling back to the
// Sphinx mainnet id when the chain header is unavailable.
func chainIDFor() uint64 {
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		return chainHdr.ChainID
	}
	return 7331
}

// transactOpts builds the shared abi.TransactOpts for one wallet broadcast. The
// signer is mint.KeyFileSigner — the same abi.Signer the mint flow uses, so
// there is one signing implementation — and a nil nonce means abi.Transact
// claims it from the shared reservation (mint.Nonces) and gives it back if the
// broadcast fails.
func (c *WalletClient) transactOpts(chainID uint64, nonce *uint64) *abi.TransactOpts {
	return &abi.TransactOpts{
		Client:   guiRPC{},
		Signer:   mint.KeyFileSigner{KeyFile: sessionPassphrase},
		NodeAddr: c.nodeAddr,
		ChainID:  chainID,
		Nonce:    nonce,
		Reserver: mint.Nonces,
	}
}

// getCurrentNonce gets the next nonce to use for `address` by claiming it from
// the shared process-wide reservation (abi.NonceReserver). One table is what
// keeps a wallet action, a collection mint, and its receipt anchor — all in
// this process — from claiming the same committed nonce before the first block
// commits.
func (c *WalletClient) getCurrentNonce(address string) (uint64, error) {
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return 0, err
	}
	return mint.Nonces.Reserve(guiRPC{}, c.nodeAddr, rawAddress)
}

// releasePendingNonce rolls a reservation back when the transaction that was
// going to consume it was never broadcast. The address is normalised first so
// the release targets the same key the claim did. Only rewinds when nothing
// later has claimed the nonce.
func (c *WalletClient) releasePendingNonce(address string, nonce uint64) {
	rawAddress, err := normaliseAddress(address)
	if err != nil {
		return
	}
	mint.Nonces.Release(c.nodeAddr, rawAddress, nonce)
}

// TransferPriority is the user-visible send speed tier. Each tier maps to a
// multiplier on the policy minimum gas price: the mempool's calculatePriority
// awards ~1 point per 1 gSPX (capped at +100), so 1/2/5 gSPX sit in the cheap,
// clearly-differentiated part of that curve rather than bunching near the cap.
//
// Copy is deliberately modest ("faster under congestion", never "fastest"): a
// static multiplier cannot outbid a congested mempool it never observes, and
// priority only matters under congestion in the first place.
type TransferPriority int

const (
	PriorityStandard TransferPriority = iota // 1x minimum — cheapest
	PriorityMedium                           // 2x — balanced
	PriorityHigh                             // 5x — faster under congestion
	PriorityCustom                           // user multiplier (>= 1x, see ValidateCustomMultiplier)
)

// GasPriceMultiplier returns the gas-price multiplier for a preset tier.
// Custom has no fixed multiplier — use ValidateCustomMultiplier instead.
func (p TransferPriority) GasPriceMultiplier() uint64 {
	switch p {
	case PriorityMedium:
		return 2
	case PriorityHigh:
		return 5
	default:
		return 1
	}
}

// Label returns the user-facing tier name (no overpromising: "faster under
// congestion", never "fastest" — a static multiplier cannot guarantee the top
// of a mempool it never observes).
func (p TransferPriority) Label() string {
	switch p {
	case PriorityMedium:
		return "Medium (2x)"
	case PriorityHigh:
		return "High (5x — faster under congestion)"
	case PriorityCustom:
		return "Custom"
	default:
		return "Standard (1x)"
	}
}

// transferPriorityOptions is the ordered option list for the Send screen's
// priority selector.
var transferPriorityOptions = []string{
	PriorityStandard.Label(),
	PriorityMedium.Label(),
	PriorityHigh.Label(),
	PriorityCustom.Label(),
}

// priorityFromLabel maps a selector label back to its TransferPriority.
// Unknown labels fall back to Standard so a stale selection can never
// produce an unpriced transaction.
func priorityFromLabel(label string) TransferPriority {
	switch label {
	case PriorityMedium.Label():
		return PriorityMedium
	case PriorityHigh.Label():
		return PriorityHigh
	case PriorityCustom.Label():
		return PriorityCustom
	default:
		return PriorityStandard
	}
}

// ValidateCustomMultiplier checks a user-supplied gas-price multiplier.
// Below 1x the node would reject the tx (gas price < MinimumGasPrice), so it
// is an error; above 100x is almost certainly a fat-finger, so it is allowed
// but flagged with a warning the caller surfaces.
func ValidateCustomMultiplier(mult uint64) (warn bool, err error) {
	if mult < 1 {
		return false, fmt.Errorf("custom multiplier must be at least 1x (the node rejects anything below the minimum gas price)")
	}
	if mult > 100 {
		return true, nil
	}
	return false, nil
}

// QuoteTransferGas quotes a plain SPX transfer at the given priority tier:
// the deterministic gas limit for the memo footprint, times the tier's gas
// price. Custom uses the caller-validated multiplier (see
// ValidateCustomMultiplier); every other tier uses its fixed multiplier.
func QuoteTransferGas(memoLen int, priority TransferPriority, customMult uint64) *policy.GasQuote {
	memoBytes := 0
	if memoLen > 0 {
		memoBytes = memoLen
	}
	base := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(memoBytes))

	mult := priority.GasPriceMultiplier()
	if priority == PriorityCustom {
		mult = customMult
	}
	if mult < 1 {
		mult = 1
	}
	gasPrice := new(big.Int).Mul(base.GasPrice, new(big.Int).SetUint64(mult))
	return &policy.GasQuote{
		GasLimit: new(big.Int).Set(base.GasLimit),
		GasPrice: gasPrice,
		GasFee:   new(big.Int).Mul(base.GasLimit, gasPrice),
	}
}

// priorityTierLabel renders the short tier tag shown in the Transfer Status
// dialog (e.g. "High (5x)"). Custom shows its actual multiplier so the
// recorded tier always matches what was paid.
func priorityTierLabel(priority TransferPriority, customMult uint64) string {
	if priority == PriorityCustom {
		return fmt.Sprintf("Custom (%dx)", customMult)
	}
	return priority.Label()
}

// SendTransactionResult holds the result of a transaction send, including gas fee info.
type SendTransactionResult struct {
	TxID     string
	GasLimit *big.Int
	GasPrice *big.Int
	GasFee   *big.Int
	// Nonce is the account nonce this send reserved from the wallet's shared
	// reservation table. The caller needs it because the node validates the
	// nonce ASYNCHRONOUSLY: sendrawtransaction returns a txid first, and only
	// later does the pool move a bad transaction into its invalid pool. The
	// reservation must then be released by hand — see
	// transferStatusDialogWorker — or the account's next reservation starts
	// past the chain's nonce and every later send from this wallet is rejected
	// the same way.
	Nonce uint64
}

// SendTransactionWithPriority sends funds to a recipient at the given gas
// price and returns the transaction ID along with gas fee details. A nil
// gasPrice falls back to the policy minimum (Standard tier); callers must
// never pass a price below it — the node rejects such transactions at
// admission, so validate first (see ValidateCustomMultiplier).
func (c *WalletClient) SendTransactionWithPriority(toAddress string, amount *big.Int, memo string, gasPrice *big.Int) (*SendTransactionResult, error) {
	if sessionPassphrase == "" {
		return nil, errors.New("not logged in")
	}
	if toAddress == "" {
		return nil, errors.New("recipient required")
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("invalid amount")
	}

	rawTo, err := normaliseAddress(toAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient address: %w", err)
	}

	rawSender, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %w", err)
	}

	log.Printf("[WalletRPC] SendTransaction: sending %s to %s",
		amount.String(), rawTo[:16]+"...")

	gasQuote := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(len(memo)))
	if gasPrice != nil && gasPrice.Sign() > 0 {
		minPrice := policy.GetDefaultPolicyParams().MinimumGasPrice
		if gasPrice.Cmp(minPrice) < 0 {
			return nil, fmt.Errorf("gas price %s below node minimum %s — raise the priority tier", gasPrice.String(), minPrice.String())
		}
		gasQuote = &policy.GasQuote{
			GasLimit: new(big.Int).Set(gasQuote.GasLimit),
			GasPrice: new(big.Int).Set(gasPrice),
			GasFee:   new(big.Int).Mul(gasQuote.GasLimit, gasPrice),
		}
	}

	tx := &types.Transaction{
		ChainID:    chainIDFor(),
		Sender:     rawSender,
		Receiver:   rawTo,
		Amount:     amount,
		GasLimit:   gasQuote.GasLimit,
		GasPrice:   gasQuote.GasPrice,
		Timestamp:  time.Now().Unix(),
		ReturnData: []byte(memo),
	}

	// ★ FIX: claim the nonce HERE rather than letting abi.Transact claim it
	// internally (the old `transactOpts(..., nil)`).
	//
	// The node checks gas and fee synchronously (ValidateTransactionPolicy) but
	// validates the NONCE — along with balance, signature and replay protection
	// — only asynchronously, inside the mempool's performValidation, which runs
	// after sendrawtransaction has already returned a txid. So a rejected send
	// comes back as a terminal rejection on the confirmation poll, not as a
	// broadcast error, and abi.Transact's own release (which fires only when
	// the broadcast itself fails) never runs for it.
	//
	// Letting that stand was not a lost-transaction bug, it was a permanent
	// one: the shared reservation claims max(chain nonce, local reservation),
	// so a slot leaked by an async rejection pushed every LATER send from this
	// account past the nonce the chain expects. Each new send was then rejected
	// the same way, the pool never held anything, and every surface downstream
	// — the explorer's mempool above all — read "0 pending" for as long as the
	// user kept retrying. Reserving here and returning the nonce is what lets
	// transferStatusDialogWorker release it when the rejection arrives.
	nonce, nerr := c.getCurrentNonce(sessionFingerprint)
	if nerr != nil {
		return nil, fmt.Errorf("failed to get account nonce from node: %w", nerr)
	}
	tx.Nonce = nonce

	// abi.Transact derives the ID (which commits to the nonce), signs, encodes
	// and broadcasts with the explicit nonce above. It will NOT release a nonce
	// the caller supplied, so a failed broadcast is released here instead —
	// the same contract AnchorMintReceipt follows.
	txid, err := abi.Transact(c.transactOpts(chainIDFor(), &nonce), tx)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return nil, fmt.Errorf("send transaction: %w", err)
	}

	return &SendTransactionResult{
		TxID:     txid,
		GasLimit: gasQuote.GasLimit,
		GasPrice: gasQuote.GasPrice,
		GasFee:   gasQuote.GasFee,
		Nonce:    nonce,
	}, nil
}

// SendTransaction sends funds to a recipient at the policy minimum gas price
// (Standard tier) and returns the transaction ID along with gas fee details.
// Kept so existing callers keep compiling; new code should prefer
// SendTransactionWithPriority.
func (c *WalletClient) SendTransaction(toAddress string, amount *big.Int, memo string) (*SendTransactionResult, error) {
	return c.SendTransactionWithPriority(toAddress, amount, memo, nil)
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

// CallSIP721 signs and broadcasts a SIP-721 contract call.
//
// The two escrow-carrying marketplace methods (buy, purchase_license) dispatch
// to the typed abi.SIP721Contract methods, which put amountNSPX on the
// transaction as its exact value — the contract's runtime rejects any other
// value. Every other method runs through the typed dispatcher with no value.
// Nonce reservation, signing, encoding and broadcast belong to abi.Transact.
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

	method = strings.ToLower(strings.TrimSpace(method))
	contract := abi.SIP721Contract{Address: collection}
	opts := c.transactOpts(chainIDFor(), nil)

	switch method {
	case "buy", "purchase_license":
		if amountNSPX == nil {
			return "", fmt.Errorf("%s requires the exact escrow amount (nSPX)", method)
		}
		tokenID, err := strconv.ParseUint(strings.TrimSpace(args["token_id"]), 10, 64)
		if err != nil {
			return "", fmt.Errorf("%s: invalid token_id %q", method, args["token_id"])
		}
		if method == "buy" {
			return contract.Buy(opts, rawSender, tokenID, amountNSPX.String())
		}
		return contract.PurchaseLicense(opts, rawSender, tokenID, args["licensee"], amountNSPX.String())
	default:
		return contract.Transact(opts, rawSender, method, args)
	}
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

	// abi owns the deploy encoding and quote, so the spec bytes and gas limit
	// the node builds from are exactly the ones the ABI would sign.
	deployTx, err := abi.NewSIP721DeployTx(abi.TxOptions{ChainID: chainIDFor(), Sender: rawOwner},
		contracts.DeploySpec{Name: name, Symbol: symbol, Owner: rawOwner})
	if err != nil {
		return "", "", fmt.Errorf("build deploy transaction: %w", err)
	}

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
		"code":     hex.EncodeToString(deployTx.Code),
		"gasLimit": deployTx.GasLimit.Uint64(),
		"gasPrice": deployTx.GasPrice.String(),
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

	// Sign, encode and broadcast through the shared path. The nonce is passed
	// explicitly so the deploy keeps the slot deploycontract was told about.
	deployTxID, err := abi.Transact(c.transactOpts(chainIDFor(), &deployNonce), &tx)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, deployNonce)
		return "", "", fmt.Errorf("send deploy tx: %w", err)
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
			return collection, deployTxID, nil
		}

		if conf, poolStr, invalidReason, derr := c.getTxNodeState(deployTxID); derr == nil {
			if invalidReason != "" {
				// The deploy can never commit: give its reserved nonce back,
				// or the account's next reservation starts one higher than
				// the chain's and the FOLLOWING broadcast is rejected with
				// "invalid nonce: N must equal M" (wallet ahead of chain —
				// the reported "5 must equal 2" after earlier failed
				// transactions leaked their reservations).
				c.releasePendingNonce(sessionFingerprint, deployNonce)
				return "", deployTxID, fmt.Errorf(
					"deploy tx %s was REJECTED by the node and can never confirm: %s",
					deployTxID, invalidReason)
			}
			if conf != nil {
				committed = true
				committedHeight = conf.Height
			} else if poolStr != "" {
				lastPool = poolStr
				log.Printf("[WalletRPC] DeploySIP721Collection: deploy tx %s uncommitted (%s)", deployTxID, poolStr)
			}
		}

		if time.Now().After(deadline) {
			if committed {
				return collection, deployTxID, fmt.Errorf(
					"deploy tx %s committed at height %d but collection %s is still not readable — the contract runtime did not record sip721:info; check the node's block-execution logs",
					deployTxID, committedHeight, collection)
			}
			return collection, deployTxID, fmt.Errorf(
				"deploy tx %s was accepted but did not commit within 90s (last mempool state: %s) — if the node is producing blocks check its logs for the validation reason, otherwise confirm block production is running (solo mode mines a block every 10s)",
				deployTxID, lastPool)
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
