// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/policy"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
)

const (
	stableAdmin = "stable-admin"
	stableA     = "stable-alice"
	stableB     = "stable-bob"
	stableEve   = "stable-eve"
)

func deployStableForTest(t *testing.T, store Store, owner string) string {
	t.Helper()
	spec := &DeploySpec{Standard: StandardSIP20, Name: "Sphinx USD", Symbol: "SUSD", Owner: owner}
	code, err := BuildDeployCode(spec)
	if err != nil {
		t.Fatalf("BuildDeployCode: %v", err)
	}
	addr := ContractAddress("stable-deployer", 7, code)
	store.SetContractCode(addr, code)
	meta := `{"address":"` + addr + `","creator":"stable-deployer","runtime":"native","standard":"sip20","created_at":1}`
	store.SetContractMeta(addr, []byte(meta))
	if err := initSIP20(store, addr, "stable-deployer", spec); err != nil {
		t.Fatalf("initSIP20: %v", err)
	}
	return addr
}

func stableStore() *memoryStore { return &memoryStore{values: map[string][]byte{}} }

func callStable(t *testing.T, store Store, addr, caller, method string, args map[string]string) (*ExecutionResult, error) {
	t.Helper()
	return callSIP20(store, addr, caller, &CallSpec{Method: method, Args: args})
}

func balanceOf(t *testing.T, store Store, addr, owner string) *big.Int {
	t.Helper()
	r, err := callStable(t, store, addr, owner, "balance_of", map[string]string{"owner": owner})
	if err != nil {
		t.Fatalf("balance_of(%s): %v", owner, err)
	}
	v, ok := new(big.Int).SetString(r.Return["balance"], 10)
	if !ok {
		t.Fatalf("balance_of(%s): bad value %q", owner, r.Return["balance"])
	}
	return v
}

func totalSupplyOf(t *testing.T, store Store, addr string) *big.Int {
	t.Helper()
	r, err := callStable(t, store, addr, stableAdmin, "info", nil)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	v, ok := new(big.Int).SetString(r.Return["total_supply"], 10)
	if !ok {
		t.Fatalf("info: bad total_supply %q", r.Return["total_supply"])
	}
	return v
}

func assertSupplyInvariant(t *testing.T, store Store, addr string, holders []string) {
	t.Helper()
	sum := big.NewInt(0)
	for _, h := range holders {
		sum.Add(sum, balanceOf(t, store, addr, h))
	}
	if got := totalSupplyOf(t, store, addr); got.Cmp(sum) != 0 {
		t.Fatalf("supply invariant broken: total_supply=%s sum(balances)=%s", got.String(), sum.String())
	}
}

func TestStablecoinDeploy(t *testing.T) {
	store := stableStore()
	spec := &DeploySpec{Standard: StandardSIP20, Name: "Sphinx USD", Symbol: "SUSD", Owner: stableAdmin}
	code, err := BuildDeployCode(spec)
	if err != nil {
		t.Fatalf("BuildDeployCode: %v", err)
	}
	tx := &txtypes.Transaction{Sender: "stable-deployer", Nonce: 7, Code: code}
	res, err := Deploy(store, tx)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	want := ContractAddress("stable-deployer", 7, code)
	if res.ContractAddress != want {
		t.Fatalf("contract address mismatch: got %q want %q", res.ContractAddress, want)
	}
	if res.Status != "deployed" {
		t.Fatalf("deploy status: got %q want deployed", res.Status)
	}
}

func TestStablecoinMintTransferBurn(t *testing.T) {
	store := stableStore()
	addr := deployStableForTest(t, store, stableAdmin)
	holders := []string{stableAdmin, stableA, stableB, stableEve}

	if got := totalSupplyOf(t, store, addr); got.Sign() != 0 {
		t.Fatalf("initial total_supply: got %s want 0", got.String())
	}

	if _, err := callStable(t, store, addr, stableAdmin, "mint", map[string]string{"to": stableA, "amount": "1000"}); err != nil {
		t.Fatalf("admin mint: %v", err)
	}
	if got := balanceOf(t, store, addr, stableA); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("balance_of(A) after mint: got %s want 1000", got.String())
	}
	if got := totalSupplyOf(t, store, addr); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("total_supply after mint: got %s want 1000", got.String())
	}

	before := totalSupplyOf(t, store, addr)
	if _, err := callStable(t, store, addr, stableEve, "mint", map[string]string{"to": stableEve, "amount": "500"}); err == nil {
		t.Fatal("unauthorized mint must be rejected")
	}
	if got := totalSupplyOf(t, store, addr); got.Cmp(before) != 0 {
		t.Fatalf("total_supply changed after rejected mint: got %s want %s", got.String(), before.String())
	}
	if got := balanceOf(t, store, addr, stableEve); got.Sign() != 0 {
		t.Fatalf("eve balance after rejected mint: got %s want 0", got.String())
	}

	if _, err := callStable(t, store, addr, stableA, "transfer", map[string]string{"to": stableB, "amount": "300"}); err != nil {
		t.Fatalf("transfer A->B: %v", err)
	}
	if got := balanceOf(t, store, addr, stableA); got.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("balance_of(A) after transfer: got %s want 700", got.String())
	}
	if got := balanceOf(t, store, addr, stableB); got.Cmp(big.NewInt(300)) != 0 {
		t.Fatalf("balance_of(B) after transfer: got %s want 300", got.String())
	}
	if got := totalSupplyOf(t, store, addr); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("total_supply after transfer: got %s want 1000", got.String())
	}

	balA := balanceOf(t, store, addr, stableA)
	balB := balanceOf(t, store, addr, stableB)
	if _, err := callStable(t, store, addr, stableA, "transfer", map[string]string{"to": stableB, "amount": "9999"}); err == nil {
		t.Fatal("overdraft transfer must be rejected")
	}
	if got := balanceOf(t, store, addr, stableA); got.Cmp(balA) != 0 {
		t.Fatalf("balance_of(A) changed after rejected transfer: got %s want %s", got.String(), balA.String())
	}
	if got := balanceOf(t, store, addr, stableB); got.Cmp(balB) != 0 {
		t.Fatalf("balance_of(B) changed after rejected transfer: got %s want %s", got.String(), balB.String())
	}

	if _, err := callStable(t, store, addr, stableAdmin, "burn", map[string]string{"from": stableA, "amount": "200"}); err != nil {
		t.Fatalf("admin burn: %v", err)
	}
	if got := balanceOf(t, store, addr, stableA); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("balance_of(A) after admin burn: got %s want 500", got.String())
	}
	if got := totalSupplyOf(t, store, addr); got.Cmp(big.NewInt(800)) != 0 {
		t.Fatalf("total_supply after admin burn: got %s want 800", got.String())
	}

	if _, err := callStable(t, store, addr, stableEve, "burn", map[string]string{"from": stableA, "amount": "10"}); err == nil {
		t.Fatal("unauthorized admin burn must be rejected")
	}
	if got := balanceOf(t, store, addr, stableA); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("balance_of(A) changed after rejected burn: got %s want 500", got.String())
	}

	if _, err := callStable(t, store, addr, stableB, "burn_self", map[string]string{"amount": "100"}); err != nil {
		t.Fatalf("self-burn: %v", err)
	}
	if got := balanceOf(t, store, addr, stableB); got.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("balance_of(B) after self-burn: got %s want 200", got.String())
	}
	if got := totalSupplyOf(t, store, addr); got.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("total_supply after self-burn: got %s want 700", got.String())
	}

	if _, err := callStable(t, store, addr, stableB, "burn_self", map[string]string{"amount": "9999"}); err == nil {
		t.Fatal("self-burn overdraft must be rejected")
	}
	if got := balanceOf(t, store, addr, stableB); got.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("balance_of(B) changed after rejected self-burn: got %s want 200", got.String())
	}

	assertSupplyInvariant(t, store, addr, holders)
}
func TestStablecoinSupplyInvariantSequence(t *testing.T) {
	store := stableStore()
	addr := deployStableForTest(t, store, stableAdmin)
	holders := []string{stableAdmin, stableA, stableB}
	assertSupplyInvariant(t, store, addr, holders)
	if _, err := callStable(t, store, addr, stableAdmin, "mint", map[string]string{"to": stableA, "amount": "5000"}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	assertSupplyInvariant(t, store, addr, holders)
	if _, err := callStable(t, store, addr, stableA, "transfer", map[string]string{"to": stableB, "amount": "2000"}); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	assertSupplyInvariant(t, store, addr, holders)
	if _, err := callStable(t, store, addr, stableAdmin, "burn", map[string]string{"from": stableB, "amount": "500"}); err != nil {
		t.Fatalf("burn: %v", err)
	}
	assertSupplyInvariant(t, store, addr, holders)
	if _, err := callStable(t, store, addr, stableA, "burn_self", map[string]string{"amount": "250"}); err != nil {
		t.Fatalf("burn_self: %v", err)
	}
	assertSupplyInvariant(t, store, addr, holders)
	if got := totalSupplyOf(t, store, addr); got.Cmp(big.NewInt(4250)) != 0 {
		t.Fatalf("final total_supply: got %s want 4250", got.String())
	}
	if got := balanceOf(t, store, addr, stableA); got.Cmp(big.NewInt(2750)) != 0 {
		t.Fatalf("final balance A: got %s want 2750", got.String())
	}
	if got := balanceOf(t, store, addr, stableB); got.Cmp(big.NewInt(1500)) != 0 {
		t.Fatalf("final balance B: got %s want 1500", got.String())
	}
}

func TestStablecoinGasQuotes(t *testing.T) {
	p := policy.GetDefaultPolicyParams()
	callData, _ := BuildCallData(&CallSpec{Method: "transfer", Args: map[string]string{"to": stableB, "amount": "1"}})
	code, _ := BuildDeployCode(&DeploySpec{Standard: StandardSIP20, Name: "Sphinx USD", Symbol: "SUSD", Owner: stableAdmin})
	deployQ := p.QuoteContractGas(true, uint64(len(code)), 0, 0)
	if deployQ.GasLimit.Cmp(big.NewInt(int64(p.ContractDeployGas))) < 0 {
		t.Fatalf("deploy quote below base: %s", deployQ.GasLimit.String())
	}
	callQ := p.QuoteContractGas(false, 0, uint64(len(callData)), 0)
	want := new(big.Int).SetUint64(p.ContractCallGas)
	want.Add(want, new(big.Int).Mul(big.NewInt(int64(len(callData))), new(big.Int).SetUint64(p.ContractCallDataByte)))
	if callQ.GasLimit.Cmp(want) != 0 {
		t.Fatalf("call quote mismatch: got %s want %s", callQ.GasLimit.String(), want.String())
	}
	q := p.QuoteTransactionGas(0)
	if q.GasLimit.Cmp(big.NewInt(int64(p.BaseTransactionGas))) != 0 {
		t.Fatalf("base tx quote mismatch: got %s want %d", q.GasLimit.String(), p.BaseTransactionGas)
	}
}

