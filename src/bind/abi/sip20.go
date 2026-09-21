// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/contracts"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

type TxOptions struct {
	ChainID uint64
	Sender  string
	Nonce   uint64
	// Timestamp is consensus data; zero uses the current time for client-side
	// construction only. Nodes never read local time during execution.
	Timestamp int64
}

func transactionQuote(deploy bool, code, callData []byte) (*big.Int, *big.Int) {
	p := policy.GetDefaultPolicyParams()
	base := p.QuoteTransactionGas(0)
	contract := p.QuoteContractGas(deploy, uint64(len(code)), uint64(len(callData)), 0)
	return new(big.Int).Add(base.GasLimit, contract.GasLimit), new(big.Int).Set(base.GasPrice)
}

func timestamp(options TxOptions) int64 {
	if options.Timestamp != 0 {
		return options.Timestamp
	}
	return time.Now().Unix()
}

// NewSIP20DeployTx constructs an unsigned, policy-quoted token deployment.
// Callers sign it with their normal wallet/signing flow before broadcasting.
func NewSIP20DeployTx(options TxOptions, spec contracts.DeploySpec) (*types.Transaction, error) {
	if options.Sender == "" {
		return nil, errors.New("sender is required")
	}
	spec.Runtime, spec.Standard = contracts.RuntimeNative, contracts.StandardSIP20
	code, err := contracts.BuildDeployCode(&spec)
	if err != nil {
		return nil, err
	}
	gasLimit, gasPrice := transactionQuote(true, code, nil)
	return assembleUnsignedTx(options, code, nil, "", gasLimit, gasPrice, nil), nil
}

// NewSIP20CallTx constructs an unsigned, policy-quoted SIP-20 call.
func NewSIP20CallTx(options TxOptions, contractAddress, method string, args map[string]string) (*types.Transaction, error) {
	return NewCallTx(SIP20ABI, options, contractAddress, method, args)
}

// NewSIP721DeployTx constructs an unsigned, policy-quoted SIP-721 collection
// deployment. Callers sign it with their normal wallet/signing flow.
func NewSIP721DeployTx(options TxOptions, spec contracts.DeploySpec) (*types.Transaction, error) {
	if options.Sender == "" {
		return nil, errors.New("sender is required")
	}
	spec.Runtime, spec.Standard = contracts.RuntimeNative, contracts.StandardSIP721
	code, err := contracts.BuildDeployCode(&spec)
	if err != nil {
		return nil, err
	}
	gasLimit, gasPrice := transactionQuote(true, code, nil)
	return assembleUnsignedTx(options, code, nil, "", gasLimit, gasPrice, nil), nil
}

// NewSIP721CallTx constructs an unsigned, policy-quoted SIP-721 call
// (mint/transfer_from/approve/owner_of/token_uri, the marketplace
// list/buy/cancel/listing_of, and the licensing
// purchase_license/revoke_license/terms_of). The call executes inside
// core.executeContractTransaction, so ownerOf/approval rules are enforced by
// every node at consensus, not just by the wallet.
func NewSIP721CallTx(options TxOptions, contractAddress, method string, args map[string]string) (*types.Transaction, error) {
	return NewCallTx(SIP721ABI, options, contractAddress, method, args)
}

// ── Deploy ────────────────────────────────────────────────────────────────
// The Deploy* functions complete the deploy story the New*DeployTx builders
// start: build (here) → sign → broadcast (Transact) → bound handle. The handle's
// address is not guessed — it is contracts.ContractAddress(sender, nonce, code)
// over the nonce Transact actually applied, which is exactly what the node
// derives at commit (contracts.Deploy), so the two agree by construction.

func deployTx(opts *TransactOpts, build func(TxOptions) (*types.Transaction, error), from string) (*types.Transaction, string, error) {
	from = strings.TrimSpace(from)
	if from == "" {
		return nil, "", errors.New("sender is required")
	}
	if err := opts.validate(); err != nil {
		return nil, "", err
	}
	// Nonce is deliberately left unset: Transact resolves it from opts and
	// applies it before deriving the transaction ID — and the derived contract
	// address depends on that final nonce.
	tx, err := build(TxOptions{ChainID: opts.ChainID, Sender: from})
	if err != nil {
		return nil, "", err
	}
	txid, err := Transact(opts, tx)
	if err != nil {
		return nil, "", err
	}
	return tx, txid, nil
}

// DeploySIP721 signs and broadcasts a SIP-721 collection deployment and returns
// a handle bound to the address the transaction derives. That address is
// PREDICTED, not confirmed: it is contracts.ContractAddress(sender, nonce, code)
// over the nonce Transact actually signed — the same function and inputs the
// node registers the contract with (contracts.Deploy calls it with the same
// tx fields), so the two agree by construction — but the deploy has not
// committed when this returns. Use DeploySIP721AndWait to have the node's
// contract registry confirm the address as well.
func DeploySIP721(opts *TransactOpts, from string, spec contracts.DeploySpec) (*SIP721Contract, string, error) {
	tx, txid, err := deployTx(opts, func(options TxOptions) (*types.Transaction, error) {
		return NewSIP721DeployTx(options, spec)
	}, from)
	if err != nil {
		return nil, "", err
	}
	return &SIP721Contract{Address: contracts.ContractAddress(tx.Sender, tx.Nonce, tx.Code)}, txid, nil
}

// DeploySIP20 signs and broadcasts a SIP-20 deployment and returns a handle
// bound to the address the transaction derives — PREDICTED, not confirmed, for
// the same reason and with the same guarantees as DeploySIP721.
func DeploySIP20(opts *TransactOpts, from string, spec contracts.DeploySpec) (*SIP20Contract, string, error) {
	tx, txid, err := deployTx(opts, func(options TxOptions) (*types.Transaction, error) {
		return NewSIP20DeployTx(options, spec)
	}, from)
	if err != nil {
		return nil, "", err
	}
	return &SIP20Contract{Address: contracts.ContractAddress(tx.Sender, tx.Nonce, tx.Code)}, txid, nil
}

// DeploySIP721AndWait is DeploySIP721 plus on-chain confirmation: it returns the
// handle only once the node reports the deploy committed AND the node's contract
// registry answers for the derived address (see confirmDeployed — a confirmed
// transaction can still have failed). A rejected deploy is an error carrying the
// node's reason, and ctx must carry its own deadline — see WaitMined.
func DeploySIP721AndWait(ctx context.Context, opts *TransactOpts, from string, spec contracts.DeploySpec, pollInterval time.Duration) (*SIP721Contract, *TxReceipt, error) {
	contract, txid, err := DeploySIP721(opts, from, spec)
	if err != nil {
		return nil, nil, err
	}
	receipt, err := WaitMined(ctx, opts.callOpts(), txid, pollInterval)
	if err != nil {
		return nil, receipt, err
	}
	if err := confirmDeployed(opts, contract.Address, txid, receipt); err != nil {
		return nil, receipt, err
	}
	return contract, receipt, nil
}

// DeploySIP20AndWait is DeploySIP20 plus on-chain confirmation, with the same
// contract as DeploySIP721AndWait.
func DeploySIP20AndWait(ctx context.Context, opts *TransactOpts, from string, spec contracts.DeploySpec, pollInterval time.Duration) (*SIP20Contract, *TxReceipt, error) {
	contract, txid, err := DeploySIP20(opts, from, spec)
	if err != nil {
		return nil, nil, err
	}
	receipt, err := WaitMined(ctx, opts.callOpts(), txid, pollInterval)
	if err != nil {
		return nil, receipt, err
	}
	if err := confirmDeployed(opts, contract.Address, txid, receipt); err != nil {
		return nil, receipt, err
	}
	return contract, receipt, nil
}

// confirmDeployed proves the derived address through the node's registry. A
// confirmed receipt only proves the transaction was included, not that a
// contract exists where the derivation says it should — so the address stays a
// prediction until getcontract answers for it. The receipt is returned by the
// caller either way, so a caller can see the deploy was included but rejected.
func confirmDeployed(opts *TransactOpts, address, txid string, receipt *TxReceipt) error {
	registered, err := ContractRegistered(opts.callOpts(), address)
	if err != nil {
		return fmt.Errorf("deploy tx %s confirmed at height %d but no contract is registered at predicted address %s (derivation mismatch or failed deploy): %w",
			txid, receipt.Height, address, err)
	}
	if !registered {
		return fmt.Errorf("deploy tx %s confirmed at height %d but no contract is registered at predicted address %s (derivation mismatch or failed deploy)",
			txid, receipt.Height, address)
	}
	return nil
}
