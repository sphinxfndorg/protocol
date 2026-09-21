// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// CallOpts mirrors go-ethereum's bind.CallOpts: the per-session state a
// read-only contract query needs.
type CallOpts struct {
	Client   RPCClient
	NodeAddr string
	// Timeout is the RPC timeout in seconds; zero uses DefaultTransactTTL.
	Timeout uint16
	// From is informational for most reads; the node's storage query is not
	// sender-gated. Methods that default an argument to the caller (SIP-20
	// balance_of) use it.
	From string
	// BlockHeight carries the caller's intended height for parity with geth's
	// CallOpts.BlockNumber. getcontractstorage always reads committed state, so
	// this is not a filter.
	BlockHeight *uint64
	// Pending mirrors geth's pending-state read. The node keeps no pending view
	// of contract storage, so a pending read still returns committed state.
	Pending bool
	// Context bounds the call. A deadline earlier than Timeout clamps the RPC
	// TTL to it.
	Context context.Context
}

func (o *CallOpts) ttl() uint16 {
	if o == nil || o.Timeout == 0 {
		return DefaultTransactTTL
	}
	return o.Timeout
}

func (o *CallOpts) ctx() context.Context {
	if o == nil || o.Context == nil {
		return context.Background()
	}
	return o.Context
}

func (o *CallOpts) validate() error {
	if o == nil {
		return errors.New("nil call options")
	}
	if o.Client == nil {
		return errors.New("call options: client is required")
	}
	if strings.TrimSpace(o.NodeAddr) == "" {
		return errors.New("call options: node address is required")
	}
	return nil
}

// Call invokes a read-only node RPC method and returns its raw result. It is
// the read counterpart to Transact and deliberately adds no RPC method: the
// node's query surface is getcontractstorage (raw slot) and getcontract (meta),
// both already registered in src/rpc/json.go — callcontract is not a query, it
// builds an unsigned transaction for the caller to sign.
func Call(opts *CallOpts, method string, params []interface{}) (json.RawMessage, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(method) == "" {
		return nil, errors.New("rpc method is required")
	}
	ttl := opts.ttl()
	ctx := opts.ctx()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		seconds := uint16(remaining / time.Second)
		if seconds == 0 {
			seconds = 1
		}
		if seconds < ttl {
			ttl = seconds
		}
	}
	return opts.Client.CallRPC(opts.NodeAddr, method, params, ttl)
}

// ContractRegistered reports whether the node's contract registry holds a
// contract at address. Today the node answers "nothing here" with an error
// (core.Blockchain.GetContract fails when no meta is stored), so an error means
// not-registered; an empty/null payload is treated the same way defensively, in
// case a transport renders the miss as a null body instead of an error.
func ContractRegistered(opts *CallOpts, address string) (bool, error) {
	if err := opts.validate(); err != nil {
		return false, err
	}
	address = strings.TrimSpace(address)
	if address == "" {
		return false, errors.New("contract address is required")
	}
	raw, err := Call(opts, "getcontract", []interface{}{address})
	if err != nil {
		return false, err
	}
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return false, nil
	}
	return true, nil
}

// remoteStore backs contract reads with the node's committed state. Writes are
// no-ops and unreachable: callContract refuses any method not marked ReadOnly in
// the ABI schema.
type remoteStore struct {
	opts *CallOpts
}

func (s *remoteStore) ContractExists(string) bool { return true }

func (s *remoteStore) SetContractCode(string, []byte)            {}
func (s *remoteStore) SetContractMeta(string, []byte)            {}
func (s *remoteStore) SetContractStorage(string, string, []byte) {}

func (s *remoteStore) GetContractStorage(address, key string) ([]byte, error) {
	raw, err := Call(s.opts, "getcontractstorage", []interface{}{address, key})
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("contract %s key %q not found", address, key)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("decode storage value: %w", err)
	}
	value, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode storage hex: %w", err)
	}
	return value, nil
}

func (s *remoteStore) GetContractMeta(address string) ([]byte, error) {
	raw, err := Call(s.opts, "getcontract", []interface{}{address})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Meta *contracts.ContractMeta `json:"meta"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode contract response: %w", err)
	}
	if payload.Meta == nil {
		return nil, fmt.Errorf("contract %s not found", address)
	}
	return json.Marshal(payload.Meta)
}

func (s *remoteStore) GetContractCode(address string) ([]byte, error) {
	raw, err := Call(s.opts, "getcontract", []interface{}{address})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode contract response: %w", err)
	}
	return hex.DecodeString(strings.TrimPrefix(payload.Code, "0x"))
}

// callContract runs a read-only method through the node's canonical contract
// logic (contracts.Call) over committed storage, so owner/approval/terms rules
// are the node's, not a re-implementation.
func callContract(opts *CallOpts, schema Contract, address, method string, args map[string]string) (map[string]string, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(address) == "" {
		return nil, errors.New("contract address is required")
	}
	if !schema.IsReadOnly(method) {
		return nil, fmt.Errorf("ABI method %q is not read-only on %s — use Transact", method, schema.Name)
	}
	callData, err := EncodeCall(schema, method, args)
	if err != nil {
		return nil, err
	}
	result, err := contracts.Call(&remoteStore{opts: opts}, &types.Transaction{
		Sender:     opts.From,
		ToContract: address,
		Amount:     big.NewInt(0),
		CallData:   callData,
	})
	if err != nil {
		return nil, err
	}
	return result.Return, nil
}

// resultKey reads a required field of a read-only node result. A missing field
// means the node answered a shape this binding does not know, which is a
// protocol-level defect worth surfacing rather than silently zeroing.
func resultKey(result map[string]string, method, key string) (string, error) {
	value, ok := result[key]
	if !ok {
		return "", fmt.Errorf("%s: node response missing %q", method, key)
	}
	return value, nil
}

// resultUint64 is resultKey for the decimal-string numbers the node returns
// (token_id, royalty_bps).
func resultUint64(result map[string]string, method, key string) (uint64, error) {
	raw, err := resultKey(result, method, key)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid %s %q in node response", method, key, raw)
	}
	return value, nil
}

// resultDecimal is resultKey for arbitrary-magnitude amounts, which the node
// sends as decimal strings (balance, total_supply).
func resultDecimal(result map[string]string, method, key string) (*big.Int, error) {
	raw, err := resultKey(result, method, key)
	if err != nil {
		return nil, err
	}
	value, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
	if !ok {
		return nil, fmt.Errorf("%s: invalid %s %q in node response", method, key, raw)
	}
	return value, nil
}
