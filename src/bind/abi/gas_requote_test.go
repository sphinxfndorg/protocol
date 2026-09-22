// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// svmTestCode builds a valid SVM1 program (magic + arithmetic/store/load
// ending in a terminal instruction). AnalyzeSVM counts every instruction, so
// the operation count it returns is exactly what the node's gas floor charges
// at 10 gas each.
func svmTestCode(t *testing.T) ([]byte, uint64) {
	t.Helper()
	push := func(v uint64) []byte {
		b := make([]byte, 9)
		b[0] = contracts.SVMPush8
		binary.BigEndian.PutUint64(b[1:], v)
		return b
	}
	code := append([]byte{}, contracts.SVM1Magic...)
	code = append(code, push(1)...)
	code = append(code, push(2)...)
	code = append(code, contracts.SVMAdd)
	code = append(code, contracts.SVMStore)
	code = append(code, push(1)...)
	code = append(code, contracts.SVMLoad)
	code = append(code, contracts.SVMReturn)
	operations, err := contracts.AnalyzeSVM(code)
	if err != nil {
		t.Fatalf("AnalyzeSVM: %v", err)
	}
	return code, operations
}

// TestTransactRaisesCallGasToTheStoredCodeFloor locks in the fix for the
// reported mint rejection:
//
//	contract gas validation failed: gas limit 60925 below required 68475
//
// A call built from calldata alone offers base + ContractCallGas +
// calldata×25, but the mempool's verifyContractGas loads the STORED contract
// code and adds len(code)×ContractCodeGasByte + operations×SVMGasPerOperation
// before accepting. Transact must therefore re-quote against the code
// getcontract returns — raising the limit to exactly the node's floor (never
// lowering it) BEFORE the transaction ID is derived, since the ID commits to
// GasLimit.
func TestTransactRaisesCallGasToTheStoredCodeFloor(t *testing.T) {
	storedCode, operations := svmTestCode(t)
	client := &stubClient{
		nonce:        4,
		txid:         "tx-call-gas",
		standard:     SIP721,
		contractCode: storedCode,
	}
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Reserver: NewNonceReserver()}

	const collection = "SPIF 1111 2222 3333 4444 5555 6666 7777 8888 9999 AAAA BBBB CCCC DDDD EEEE FFFF 0000"
	tx, err := NewSIP721CallTx(TxOptions{ChainID: 7331, Sender: stubDeployFrom}, collection, "mint", map[string]string{
		"to":          stubDeployFrom,
		"token_uri":   "ipfs://bafy-metadata",
		"mint_id":     "mint-gas-test",
		"royalty_bps": "0",
	})
	if err != nil {
		t.Fatalf("NewSIP721CallTx: %v", err)
	}

	// The built (calldata-only) quote is exactly what used to be broadcast —
	// and exactly what the node rejects: it lacks the stored code's bytes and
	// operation count.
	p := policy.GetDefaultPolicyParams()
	builtFloor := new(big.Int).Add(
		p.QuoteTransactionGas(0).GasLimit,
		p.QuoteContractGas(false, 0, uint64(len(tx.CallData)), 0).GasLimit,
	)
	if tx.GasLimit.Cmp(builtFloor) != 0 {
		t.Fatalf("precondition: built call quote = %s, want the calldata-only floor %s", tx.GasLimit, builtFloor)
	}

	if _, err := Transact(opts, tx); err != nil {
		t.Fatalf("Transact: %v", err)
	}

	// The code read must actually happen before the broadcast (getnonce comes
	// first because this opts claims its nonce from the Reserver).
	if len(client.calls) < 3 ||
		client.calls[0].method != "getnonce" ||
		client.calls[1].method != "getcontract" ||
		client.calls[len(client.calls)-1].method != "sendrawtransaction" {
		t.Fatalf("calls = %#v, want getnonce, getcontract, …, sendrawtransaction", client.methods())
	}

	broadcast := client.broadcast(t)

	// The node's exact floor: base + ContractCallGas + storedCode×50 +
	// calldata×25 + operations×10 (mempool verifyContractGas's SVM branch).
	wantContract := p.QuoteContractGas(false, uint64(len(storedCode)), uint64(len(broadcast.CallData)), operations)
	want := new(big.Int).Add(p.QuoteTransactionGas(uint64(len(broadcast.ReturnData))).GasLimit, wantContract.GasLimit)
	if broadcast.GasLimit == nil || broadcast.GasLimit.Cmp(want) != 0 {
		t.Fatalf("broadcast gas limit = %v, want the node's floor %s (stored %d bytes + %d ops)",
			broadcast.GasLimit, want, len(storedCode), operations)
	}
	// The regression, stated directly: the calldata-only quote that produced
	// "gas limit 60925 below required 68475" must no longer be what is signed.
	if broadcast.GasLimit.Cmp(builtFloor) <= 0 {
		t.Fatalf("gas limit %s must EXCEED the calldata-only quote %s — the node charges stored code bytes too",
			broadcast.GasLimit, builtFloor)
	}
	if broadcast.ID == "" {
		t.Fatal("transaction ID missing from broadcast")
	}
}
// TestTransactKeepsTheBuiltQuoteWhenCodeIsUnreadable pins the fallback: a
// getcontract miss (unknown address, older node without the code field, or a
// transport error) must leave the calldata-only quote untouched rather than
// fail the broadcast — the failure mode then stays exactly what it was (the
// node's own gas error), never worse.
func TestTransactKeepsTheBuiltQuoteWhenCodeIsUnreadable(t *testing.T) {
	// standard set but contractCode empty: getcontract answers with code:"".
	client := &stubClient{nonce: 1, txid: "tx-no-code", standard: SIP721}
	nonce := uint64(1)
	opts := &TransactOpts{Client: client, Signer: &stubSigner{}, NodeAddr: stubNodeAddr, ChainID: 7331, Nonce: &nonce}

	tx, err := NewSIP721CallTx(TxOptions{ChainID: 7331, Sender: stubDeployFrom},
		"SPIF 1111 2222 3333 4444 5555 6666 7777 8888 9999 AAAA BBBB CCCC DDDD EEEE FFFF 0000",
		"list", map[string]string{"token_id": "1", "price": "1000"})
	if err != nil {
		t.Fatalf("NewSIP721CallTx: %v", err)
	}
	want := new(big.Int).Set(tx.GasLimit)

	if _, err := Transact(opts, tx); err != nil {
		t.Fatalf("Transact with unreadable code must still broadcast: %v", err)
	}
	broadcast := client.broadcast(t)
	if broadcast.GasLimit.Cmp(want) != 0 {
		t.Fatalf("gas limit = %s, want the unchanged built quote %s", broadcast.GasLimit, want)
	}
}

// TestRequiredContractGasMirrorsTheNodeFormula checks the pure quote helper
// against the policy schedule directly, for the code classes the mempool's
// verifyContractGas distinguishes (SVM, native/default) plus the refusal path.
func TestRequiredContractGasMirrorsTheNodeFormula(t *testing.T) {
	p := policy.GetDefaultPolicyParams()
	callData := []byte("0123456789") // 10 bytes → 10×25 = 250 gas

	// Default (native) code: no SVM magic, not WASM — base + CallGas +
	// code×50 + calldata×25, operations term absent (the mempool's default
	// branch passes 0 because neither analyzer ran).
	native := []byte("native sip-721 spec bytes....")
	got, ok := requiredContractGas(native, callData, nil, false)
	if !ok {
		t.Fatal("requiredContractGas(native) must be quotable")
	}
	want := new(big.Int).Add(p.QuoteTransactionGas(0).GasLimit,
		p.QuoteContractGas(false, uint64(len(native)), uint64(len(callData)), 0).GasLimit)
	if got.Cmp(want) != 0 {
		t.Fatalf("native quote = %s, want %s", got, want)
	}

	// SVM code: operations from AnalyzeSVM are charged at SVMGasPerOperation.
	svmCode, operations := svmTestCode(t)
	got, ok = requiredContractGas(svmCode, callData, nil, false)
	if !ok {
		t.Fatal("requiredContractGas(svm) must be quotable")
	}
	want = new(big.Int).Add(p.QuoteTransactionGas(0).GasLimit,
		p.QuoteContractGas(false, uint64(len(svmCode)), uint64(len(callData)), operations).GasLimit)
	if got.Cmp(want) != 0 {
		t.Fatalf("svm quote = %s, want %s (ops=%d)", got, want, operations)
	}

	// Unanalyzable SVM-looking code must be refused (ok=false), never
	// misquoted: the caller then keeps its built quote. 0x06 sits in the gap
	// between SVMDiv (0x05) and SVMStore (0x10) — unassigned, and crucially
	// NOT 0xFF (that is SVMReturn, a valid terminal instruction).
	brokenSVM := append([]byte{}, contracts.SVM1Magic...)
	brokenSVM = append(brokenSVM, 0x06)
	if _, ok := requiredContractGas(brokenSVM, callData, nil, false); ok {
		t.Fatal("invalid SVM code must not produce a quote")
	}

	// ReturnData rides on the base quote (100 gas/byte), matching the node's
	// QuoteTransactionGas(len(tx.ReturnData)) term.
	got, ok = requiredContractGas(native, callData, []byte("rrrr"), false)
	if !ok {
		t.Fatal("requiredContractGas with ReturnData must be quotable")
	}
	want = new(big.Int).Add(p.QuoteTransactionGas(4).GasLimit,
		p.QuoteContractGas(false, uint64(len(native)), uint64(len(callData)), 0).GasLimit)
	if got.Cmp(want) != 0 {
		t.Fatalf("return-data quote = %s, want %s", got, want)
	}
}

