// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/contracts"
)

func TestSIP20BuildersUseCanonicalABI(t *testing.T) {
	opts := TxOptions{ChainID: 1, Sender: "owner", Nonce: 7, Timestamp: 100}
	deploy, err := NewSIP20DeployTx(opts, contracts.DeploySpec{Name: "Token", Symbol: "TOK", InitialSupply: "100"})
	if err != nil || len(deploy.Code) == 0 || deploy.ToContract != "" {
		t.Fatalf("deploy=%#v err=%v", deploy, err)
	}
	call, err := NewSIP20CallTx(opts, common.SPIFPrefix+"123", "transfer", map[string]string{"to": "alice", "amount": "5"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCall(SIP20ABI, call.CallData)
	if err != nil || decoded.Method != "transfer" || decoded.Args["amount"] != "5" {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
}

func TestBinaryArtifactRoundTrip(t *testing.T) {
	code := append([]byte{}, contracts.SVM1Magic...)
	code = append(code, contracts.SVMStop)
	artifact, err := NewBinaryArtifact("svm1", code)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeArtifactCode(artifact)
	if err != nil || string(decoded) != string(code) {
		t.Fatalf("decoded=%x err=%v", decoded, err)
	}
}

func TestWASMDeployRejectsNonBinaryInput(t *testing.T) {
	if _, err := NewWASMDeployTx(TxOptions{Sender: "owner", Timestamp: 100}, []byte("not wasm")); err == nil {
		t.Fatal("expected invalid WASM to be rejected")
	}
}

func TestSVMDeploymentQuoteIncludesOperationCost(t *testing.T) {
	code := append([]byte{}, contracts.SVM1Magic...)
	code = append(code, contracts.SVMStop)
	tx, err := NewSVMDeployTx(TxOptions{Sender: "owner", Timestamp: 100}, code)
	if err != nil || tx.GasLimit.Sign() <= 0 {
		t.Fatalf("tx=%#v err=%v", tx, err)
	}
}

func TestSIP20ABIRejectsMissingRequiredArgument(t *testing.T) {
	if _, err := EncodeCall(SIP20ABI, "transfer", map[string]string{"to": "alice"}); err == nil {
		t.Fatal("expected missing amount to fail")
	}
}

func TestWASMBuildersCopyAndQuoteBytecode(t *testing.T) {
	opts := TxOptions{Sender: "owner", Nonce: 1, Timestamp: 100}
	wasm := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	deploy, err := NewWASMDeployTx(opts, wasm)
	if err != nil || len(deploy.Code) != len(wasm) || deploy.GasLimit.Sign() <= 0 {
		t.Fatalf("deploy=%#v err=%v", deploy, err)
	}
	call, err := NewWASMCallTx(opts, common.SPIFPrefix+"123", []byte{1, 2})
	if err != nil || call.ToContract != common.SPIFPrefix+"123" || len(call.CallData) != 2 {
		t.Fatalf("call=%#v err=%v", call, err)
	}
}
