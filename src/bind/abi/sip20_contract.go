// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"math/big"
	"strings"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// SIP20Contract is the typed binding for a deployed SIP-20 token, following
// the same shape as SIP721Contract.
type SIP20Contract struct {
	Address string
}

// Transact runs any SIP-20 method (transfer, ...) through the shared Transact
// path.
func (c SIP20Contract) Transact(opts *TransactOpts, from, method string, args map[string]string) (string, error) {
	return transactCall(opts, SIP20ABI, c.Address, from, method, args)
}

// Mint executes mint(to, amount) and returns the broadcast txid. Every node
// rejects it unless from is the token owner (contracts.callSIP20 enforces the
// owner check at consensus, not wallet-side).
func (c SIP20Contract) Mint(opts *TransactOpts, from, to, amount string) (string, error) {
	return c.Transact(opts, from, "mint", map[string]string{
		"to":     strings.TrimSpace(to),
		"amount": strings.TrimSpace(amount),
	})
}

// MintTx builds the unsigned mint transaction without broadcasting it, for
// callers that manage their own signing and submission.
func (c SIP20Contract) MintTx(options TxOptions, to, amount string) (*types.Transaction, error) {
	return NewSIP20CallTx(options, c.Address, "mint", map[string]string{
		"to":     strings.TrimSpace(to),
		"amount": strings.TrimSpace(amount),
	})
}

// ── Typed writes ─────────────────────────────────────────────────────────

// Transfer executes transfer(to, amount) and returns the broadcast txid; the
// node rejects it unless from holds the balance (or, for a collection-owned
// token, is the owner).
func (c SIP20Contract) Transfer(opts *TransactOpts, from, to, amount string) (string, error) {
	return c.Transact(opts, from, "transfer", map[string]string{
		"to":     strings.TrimSpace(to),
		"amount": strings.TrimSpace(amount),
	})
}

// TransferTx builds the unsigned transfer transaction without broadcasting it,
// for callers that manage their own signing and submission.
func (c SIP20Contract) TransferTx(options TxOptions, to, amount string) (*types.Transaction, error) {
	return NewSIP20CallTx(options, c.Address, "transfer", map[string]string{
		"to":     strings.TrimSpace(to),
		"amount": strings.TrimSpace(amount),
	})
}

// BalanceOf returns the token balance of owner through the node's own
// read-only balance_of (an empty owner means the node answers for the caller).
// The balance travels as a decimal string so arbitrary magnitudes survive, and
// a malformed one is an error rather than a silent zero.
func (c SIP20Contract) BalanceOf(opts *CallOpts, owner string) (*big.Int, error) {
	result, err := callContract(opts, SIP20ABI, c.Address, "balance_of", map[string]string{
		"owner": strings.TrimSpace(owner),
	})
	if err != nil {
		return nil, err
	}
	return resultDecimal(result, "balance_of", "balance")
}

// SIP20Info is the read-side view of a deployed token (contracts.callSIP20
// "info"): identity, the frozen decimals, the mint authority, and the live
// supply. TotalSupply is a *big.Int because the node sends it as a decimal
// string — token supplies are not bounded by int64.
type SIP20Info struct {
	Name        string
	Symbol      string
	Decimals    uint64
	Owner       string
	TotalSupply *big.Int
}

// Info returns the token's metadata and live total supply.
func (c SIP20Contract) Info(opts *CallOpts) (SIP20Info, error) {
	result, err := callContract(opts, SIP20ABI, c.Address, "info", nil)
	if err != nil {
		return SIP20Info{}, err
	}
	info := SIP20Info{}
	if info.Name, err = resultKey(result, "info", "name"); err != nil {
		return SIP20Info{}, err
	}
	if info.Symbol, err = resultKey(result, "info", "symbol"); err != nil {
		return SIP20Info{}, err
	}
	if info.Decimals, err = resultUint64(result, "info", "decimals"); err != nil {
		return SIP20Info{}, err
	}
	if info.Owner, err = resultKey(result, "info", "owner"); err != nil {
		return SIP20Info{}, err
	}
	if info.TotalSupply, err = resultDecimal(result, "info", "total_supply"); err != nil {
		return SIP20Info{}, err
	}
	return info, nil
}
