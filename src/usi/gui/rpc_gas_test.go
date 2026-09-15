// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/rpc_gas_test.go
package gui

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/policy"
)

// TestSIP721DeployGasLimitIncludesBaseTransactionGas guards the regression that
// made "Deploy New Collection" fail on-chain with:
//
//	deploy failed: RPC error: RPC error (-3262): gas limit below policy
//	minimum: offered 107050, required 128050
//
// core.Blockchain.RequiredTransactionGas charges the BASE TRANSACTION GAS on
// top of the contract-deploy quote, so a client that quotes only
// QuoteContractGas is always short by BaseTransactionGas (21,000) and the node
// rejects the broadcast at admission.
func TestSIP721DeployGasLimitIncludesBaseTransactionGas(t *testing.T) {
	p := policy.GetDefaultPolicyParams()

	// 141 bytes is the deploy-spec size from the failing report:
	// 100000 + 141*50 = 107050 (offered), + 21000 = 128050 (required).
	const codeBytes = 141
	got := sip721DeployGasLimit(codeBytes)

	base := p.QuoteTransactionGas(0)
	contractOnly := p.QuoteContractGas(true, codeBytes, 0, 0)

	// The contract-only quote is exactly what used to be sent; the quoted
	// limit must now be strictly above it.
	if contractOnly.GasLimit.Cmp(got) >= 0 {
		t.Fatalf("deploy gas limit must exceed the contract-only quote: contract=%s got=%s",
			contractOnly.GasLimit, got)
	}

	// It must be precisely the node's required sum.
	want := new(big.Int).Add(base.GasLimit, contractOnly.GasLimit)
	if got.Cmp(want) != 0 {
		t.Fatalf("deploy gas limit mismatch: got %s want %s (base %s + contract %s)",
			got, want, base.GasLimit, contractOnly.GasLimit)
	}

	// Explicit numeric expectation straight from the policy schedule, so a
	// silent change to any of the three parameters is caught here:
	// BaseTransactionGas + ContractDeployGas + codeBytes*ContractCodeGasByte.
	explicit := new(big.Int).SetUint64(p.BaseTransactionGas + p.ContractDeployGas)
	explicit.Add(explicit, new(big.Int).Mul(
		new(big.Int).SetUint64(codeBytes),
		new(big.Int).SetUint64(p.ContractCodeGasByte),
	))
	if got.Cmp(explicit) != 0 {
		t.Fatalf("deploy gas limit does not match the policy schedule: got %s want %s", got, explicit)
	}

	// The exact numbers from the bug report.
	if got.Uint64() != 128050 {
		t.Fatalf("expected 128050 gas for a %d-byte deploy spec, got %s", codeBytes, got)
	}

	// The gas price offered alongside it must meet the node's floor.
	if p.MinimumGasPrice == nil || p.MinimumGasPrice.Sign() <= 0 {
		t.Fatal("policy MinimumGasPrice must be positive")
	}
}

// TestSameIdentityMatchesStorageAndDisplayForms covers the marketplace's
// owner/seller/licensee comparisons: contract storage returns canonical raw
// UPPERCASE hex while the session holds the "SPIF XXXX XXXX …" display form, so
// a plain == never matched and a minter could never list their own token.
func TestSameIdentityMatchesStorageAndDisplayForms(t *testing.T) {
	const raw = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"

	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"raw vs display prefix", raw, "SPIF " + raw, true},
		{"display vs raw", "SPIF " + raw, raw, true},
		{"grouped display", "SPIF AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD EEFF 0011 2233 4455 6677 8899", raw, true},
		{"lowercase raw", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", raw, true},
		{"different identities", raw, "BBBBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899", false},
		{"empty storage value", "", raw, false},
		{"empty session", raw, "", false},
		{"both empty", "", "", false},
		{"non-address exact match", "genesis", "GENESIS", true},
		{"non-address mismatch", "genesis", "treasury", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameIdentity(tc.a, tc.b); got != tc.want {
				t.Fatalf("sameIdentity(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestSIP721CallTxGasIncludesBaseTransactionGas guards the same two-component
// contract on the contract-call path: newSIP721CallTx must offer base
// transaction gas + contract-call gas, exactly like abi.transactionQuote and
// core.Blockchain.RequiredTransactionGas. This is the helper behind the
// collection mint/list/buy/license call.
func TestSIP721CallTxGasIncludesBaseTransactionGas(t *testing.T) {
	p := policy.GetDefaultPolicyParams()

	const sender = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
	const collection = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF"

	tx, err := newSIP721CallTx(7331, sender, 0, collection, "buy", map[string]string{"token_id": "1"})
	if err != nil {
		t.Fatalf("newSIP721CallTx: %v", err)
	}

	base := p.QuoteTransactionGas(0)
	if tx.GasLimit.Cmp(base.GasLimit) <= 0 {
		t.Fatalf("call gas limit must exceed base transaction gas: got %s base %s", tx.GasLimit, base.GasLimit)
	}

	want := new(big.Int).Add(base.GasLimit,
		p.QuoteContractGas(false, 0, uint64(len(tx.CallData)), 0).GasLimit)
	if tx.GasLimit.Cmp(want) != 0 {
		t.Fatalf("call gas limit mismatch: got %s want %s", tx.GasLimit, want)
	}
	if tx.GasPrice == nil || tx.GasPrice.Cmp(p.MinimumGasPrice) != 0 {
		t.Fatalf("call gas price must be the policy minimum: got %v want %s", tx.GasPrice, p.MinimumGasPrice)
	}
}
