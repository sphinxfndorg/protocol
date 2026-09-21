// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// assembleUnsignedTx is the single canonical constructor for every unsigned
// contract transaction the ABI emits. Before this helper, all seven builders
// (SIP-20 deploy/call, WASM deploy/call/function-call, SVM deploy, the
// deploy-from-hex path) repeated the same types.Transaction literal — seven
// copies that could drift apart, with one consensus-relevant omission: none
// of them could ever set Receiver, Amount, or ReturnData.
//
// amount is the escrow the caller escorts to the contract, not a native
// transfer: exactly two methods carry value — the SIP-721 marketplace's buy
// and purchase_license — because contracts.callSIP721 requires the transaction
// to carry the posted price/fee exactly (a mismatch, including carrying
// nothing, is rejected at consensus) and escrows it at the contract before
// paying out the seller and creator. Both set it explicitly through
// SIP721Contract.Buy/.PurchaseLicense; every other builder passes nil, which
// assembles as 0. Receiver stays empty, and ReturnData is owned by the
// mint-anchor flow (src/core/mint_anchor.go, node-verified via
// src/core.ValidateTransactionPolicy). All builders delegate here so a
// consensus-relevant field can only ever be added in exactly one place.
func assembleUnsignedTx(options TxOptions, code, callData []byte, contractAddress string, gasLimit, gasPrice, amount *big.Int) *types.Transaction {
	value := new(big.Int)
	if amount != nil {
		value.Set(amount)
	}
	return &types.Transaction{
		ChainID:    options.ChainID,
		Sender:     options.Sender,
		Amount:     value,
		Nonce:      options.Nonce,
		Timestamp:  timestamp(options),
		Code:       append([]byte(nil), code...),
		ToContract: contractAddress,
		CallData:   append([]byte(nil), callData...),
		GasLimit:   gasLimit,
		GasPrice:   gasPrice,
	}
}

// EncodeRawTransaction produces the canonical hex(JSON(transaction)) wire
// payload accepted by the node's sendrawtransaction RPC method.
//
// It lives in the ABI package rather than src/bind because it completes the
// client story — build (the ABI builders above) → encode (here) → broadcast —
// while keeping the dependency footprint leaf-sized: src/bind pulls the full
// node runtime (43+ packages: consensus, network, p2p, dht, transport, zap),
// the ABI pulls 11. SDKs, wallets, and the CLI encode contract payloads
// through this function so they emit byte-identical payloads. Code and call
// data remain binary fields and use Go JSON's byte-slice encoding internally.
func EncodeRawTransaction(tx *types.Transaction) (string, error) {
	if tx == nil {
		return "", fmt.Errorf("nil transaction")
	}
	data, err := json.Marshal(tx)
	if err != nil {
		return "", fmt.Errorf("marshal raw transaction: %w", err)
	}
	return hex.EncodeToString(data), nil
}

// DecodeRawTransaction reverses EncodeRawTransaction: it turns the canonical
// hex(JSON(transaction)) payload back into a transaction, so a caller holding a
// raw payload (its own broadcast, or one fetched from the node) can inspect it
// before or after submission. A leading 0x is accepted because that is how
// explorers and RPC responses render the same bytes.
func DecodeRawTransaction(raw string) (*types.Transaction, error) {
	payload := strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if payload == "" {
		return nil, fmt.Errorf("empty raw transaction")
	}
	data, err := hex.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode raw transaction hex: %w", err)
	}
	var tx types.Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("decode raw transaction: %w", err)
	}
	return &tx, nil
}

// RPCClient is the minimal node transport Transact needs. It matches
// rpc.CallRPC's signature so a wallet or SDK can inject its own transport,
// while abi stays free of the node's rpc package (importing it would put the
// node runtime back into every client's dependency graph — the whole reason
// the ABI lives outside src/bind).
type RPCClient interface {
	CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error)
}

// Signer attaches the canonical SPHINCS+ transaction auth bundle. It is
// supplied by the wallet layer for the same reason: abi holds no key material
// and imports no signing backend.
type Signer interface {
	SignTransaction(tx *types.Transaction) error
}

// TransactOpts mirrors go-ethereum's bind.TransactOpts: the per-session state
// a typed contract call needs (transport, signer, chain id, nonce) gathered in
// one struct instead of threaded through every call site as loose arguments.
type TransactOpts struct {
	Client   RPCClient
	Signer   Signer
	NodeAddr string
	ChainID  uint64
	// Timeout is the RPC timeout in seconds; zero uses DefaultTransactTTL.
	Timeout uint16
	// Nonce is the account nonce to sign with. nil resolves the account's live
	// nonce from the node; a pointer is used because 0 is a valid nonce for an
	// account that has never sent a transaction. Wallets that reserve nonces
	// locally set this, so a second broadcast in the same flow signs the next
	// nonce instead of re-reading the committed one and colliding in the
	// mempool.
	Nonce *uint64
	// Reserver, when set, supplies the nonce by claiming the next one from a
	// shared process-local reservation, for callers that broadcast more than
	// one transaction from the same account before the first commits. Only
	// consulted when Nonce is nil.
	Reserver *NonceReserver
	// Amount is the escrow this call escorts to the contract. Only the SIP-721
	// marketplace's two value-carrying methods (buy, purchase_license) set it,
	// because contracts.callSIP721 requires the transaction to carry the posted
	// price/fee exactly; nil means 0 for every other method. Per-call rather
	// than a field on TxOptions, so no builder is forced to consider value.
	Amount *big.Int
}

// callOpts bridges the write-side options to the read path (read-only calls,
// receipts, WaitMined). It exists so both paths share one RPCClient and
// NodeAddr instead of a deploy flow constructing a second client.
func (o *TransactOpts) callOpts() *CallOpts {
	if o == nil {
		return &CallOpts{}
	}
	return &CallOpts{Client: o.Client, NodeAddr: o.NodeAddr, Timeout: o.Timeout}
}

// DefaultTransactTTL is the sendrawtransaction timeout in seconds used when
// TransactOpts.Timeout is unset.
const DefaultTransactTTL uint16 = 120

func (o *TransactOpts) ttl() uint16 {
	if o == nil || o.Timeout == 0 {
		return DefaultTransactTTL
	}
	return o.Timeout
}

func (o *TransactOpts) validate() error {
	if o == nil {
		return errors.New("nil transact options")
	}
	if o.Signer == nil {
		return errors.New("transact options: signer is required")
	}
	if o.Client == nil {
		return errors.New("transact options: client is required")
	}
	if strings.TrimSpace(o.NodeAddr) == "" {
		return errors.New("transact options: node address is required")
	}
	return nil
}

// nonceFor returns the nonce to sign sender's transaction with and whether
// that nonce was claimed from a Reserver — the caller must give a claimed
// nonce back if the broadcast never happens. The account's live nonce is read
// from the node only when TransactOpts.Nonce is nil.
func (o *TransactOpts) nonceFor(sender string) (uint64, bool, error) {
	if o.Nonce != nil {
		return *o.Nonce, false, nil
	}
	if err := o.validate(); err != nil {
		return 0, false, err
	}
	// A Reserver claims the next nonce this process reserved for (node,
	// sender). A wallet that broadcasts twice before the first commits needs
	// that reservation; a bare getnonce would hand both broadcasts the same
	// committed nonce.
	if o.Reserver != nil {
		nonce, err := o.Reserver.Reserve(o.Client, o.NodeAddr, sender)
		return nonce, err == nil, err
	}
	raw, err := o.Client.CallRPC(o.NodeAddr, "getnonce", []interface{}{sender}, o.ttl())
	if err != nil {
		return 0, false, fmt.Errorf("getnonce: %w", err)
	}
	var nonce uint64
	if err := json.Unmarshal(raw, &nonce); err != nil {
		return 0, false, fmt.Errorf("parse nonce response: %w", err)
	}
	return nonce, false, nil
}

// Transact signs tx and broadcasts it as sendrawtransaction, returning the
// node's txid. It is the single sign -> encode -> broadcast path shared by
// every typed contract method and by raw transaction flows (such as the mint
// receipt anchor), replacing the per-caller copies of that sequence.
func Transact(opts *TransactOpts, tx *types.Transaction) (txid string, err error) {
	if tx == nil {
		return "", errors.New("nil transaction")
	}
	if err = opts.validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(tx.Sender) == "" {
		return "", errors.New("transaction sender is required")
	}
	// The nonce is part of both the transaction ID and the signed SPHINCS+
	// auth bundle, so it must be applied before the ID is derived.
	nonce, reserved, err := opts.nonceFor(tx.Sender)
	if err != nil {
		return "", err
	}
	// A nonce this call reserved is this call's to give back: leaving it
	// claimed after a failed broadcast would make the account skip that nonce,
	// which the exact-match mempool rule turns into a stall. Release only
	// rewinds while nothing later has claimed the nonce.
	if reserved {
		defer func() {
			if err != nil {
				opts.Reserver.Release(opts.NodeAddr, tx.Sender, nonce)
			}
		}()
	}
	if tx.Nonce != nonce {
		tx.Nonce = nonce
		tx.ID = ""
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}
	if err := opts.Signer.SignTransaction(tx); err != nil {
		return "", fmt.Errorf("sign transaction: %w", err)
	}
	raw, err := EncodeRawTransaction(tx)
	if err != nil {
		return "", err
	}
	resp, err := opts.Client.CallRPC(opts.NodeAddr, "sendrawtransaction", []interface{}{raw}, opts.ttl())
	if err != nil {
		return "", fmt.Errorf("sendrawtransaction: %w", err)
	}
	if len(resp) == 0 || string(resp) == "null" {
		return "", errors.New("sendrawtransaction: empty response")
	}
	var result struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("parse sendrawtransaction response: %w", err)
	}
	if result.TxID == "" {
		return "", errors.New("sendrawtransaction: no txid in response")
	}
	return result.TxID, nil
}

// NewCallTx constructs an unsigned, policy-quoted call of method against a
// contract implementing schema. It is the shared constructor behind every
// typed call wrapper; callers that sign elsewhere can use it directly. It
// carries no escrow — the two value-carrying SIP-721 methods (buy,
// purchase_license) pass their amount to newCallTx.
func NewCallTx(schema Contract, options TxOptions, contractAddress, method string, args map[string]string) (*types.Transaction, error) {
	return newCallTx(schema, options, contractAddress, method, args, nil)
}

// newCallTx is NewCallTx with an explicit escrow amount; amount nil assembles
// as 0 (see assembleUnsignedTx).
func newCallTx(schema Contract, options TxOptions, contractAddress, method string, args map[string]string, amount *big.Int) (*types.Transaction, error) {
	if options.Sender == "" || contractAddress == "" {
		return nil, errors.New("sender and contract address are required")
	}
	callData, err := EncodeCall(schema, method, args)
	if err != nil {
		return nil, err
	}
	gasLimit, gasPrice := transactionQuote(false, nil, callData)
	return assembleUnsignedTx(options, nil, callData, contractAddress, gasLimit, gasPrice, amount), nil
}

// transactCall packs method/args against schema, quotes the call with opts'
// chain id and nonce, and runs it through Transact. Typed contract methods
// delegate here so the build -> sign -> encode -> broadcast sequence exists
// once, not once per standard.
func transactCall(opts *TransactOpts, schema Contract, address, from, method string, args map[string]string) (string, error) {
	if strings.TrimSpace(from) == "" {
		return "", errors.New("sender is required")
	}
	if err := opts.validate(); err != nil {
		return "", err
	}
	// Nonce is deliberately left unset: Transact resolves it from opts and
	// applies it before deriving the transaction ID. Amount carries the
	// caller's escrow for the value-carrying SIP-721 methods and is nil (0)
	// for every other method.
	tx, err := newCallTx(schema, TxOptions{ChainID: opts.ChainID, Sender: from}, address, method, args, opts.Amount)
	if err != nil {
		return "", err
	}
	return Transact(opts, tx)
}
