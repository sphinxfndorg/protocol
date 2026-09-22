// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"math/big"
	"testing"
)

// TestABIValues tests the ABI type system
func TestABIValues(t *testing.T) {
	tests := []struct {
		name    string
		value   *ABIValue
		extract interface{}
		wantErr bool
	}{
		{
			name:    "uint64",
			value:   NewABIValueUint64(42),
			extract: uint64(42),
		},
		{
			name:    "int64",
			value:   NewABIValueInt64(-42),
			extract: int64(-42),
		},
		{
			name:    "bool_true",
			value:   NewABIValueBool(true),
			extract: true,
		},
		{
			name:    "address",
			value:   NewABIValueAddress("SPIF 1234 5678"),
			extract: "SPIF 1234 5678",
		},
		{
			name:    "string",
			value:   NewABIValueString("hello world"),
			extract: "hello world",
		},
		{
			name:    "amount",
			value:   NewABIValueAmount(big.NewInt(1000000)),
			extract: "1000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateABIValue(tt.value); err != nil {
				t.Fatalf("validation failed: %v", err)
			}

			var got interface{}
			var err error
			switch tt.extract.(type) {
			case uint64:
				got, err = tt.value.AsUint64()
			case int64:
				got, err = tt.value.AsInt64()
			case bool:
				got, err = tt.value.AsBool()
			case string:
				switch tt.value.Type {
				case ABITypeAddress:
					got, err = tt.value.AsAddress()
				case ABITypeString:
					got, err = tt.value.AsString()
				case ABITypeAmount:
					amt, _ := tt.value.AsAmount()
					got = amt.String()
				}
			}

			if (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, want error %v", err, tt.wantErr)
			}

			if got != tt.extract {
				t.Fatalf("got %v, want %v", got, tt.extract)
			}
		})
	}
}

// TestABIArrays tests the array type
func TestABIArrays(t *testing.T) {
	items := []ABIValue{
		*NewABIValueUint64(1),
		*NewABIValueUint64(2),
		*NewABIValueUint64(3),
	}

	arr := NewABIValueArray(items)

	if arr.Type != ABITypeArray {
		t.Fatalf("type mismatch: got %s, want %s", arr.Type, ABITypeArray)
	}

	extracted, err := arr.AsArray()
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if len(extracted) != 3 {
		t.Fatalf("length mismatch: got %d, want 3", len(extracted))
	}
}

func TestStablecoinABIAndRichCalls(t *testing.T) {
	if err := ValidateContractABI(&StablecoinABI); err != nil {
		t.Fatalf("stablecoin ABI validation failed: %v", err)
	}

	mintCall := NewStablecoinMintCall("alice", big.NewInt(1000))
	if mintCall.Method != "mint" {
		t.Fatalf("mint method mismatch: got %s", mintCall.Method)
	}
	if len(mintCall.Args) != 2 {
		t.Fatalf("mint arg count mismatch: got %d", len(mintCall.Args))
	}
	if mintCall.Args[0].Type != ABITypeAddress || mintCall.Args[1].Type != ABITypeAmount {
		t.Fatalf("mint args wrong: %#v", mintCall.Args)
	}

	payload, err := BuildRichCallData(NewStablecoinTransferCall("bob", big.NewInt(250)))
	if err != nil {
		t.Fatalf("transfer call encoding failed: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("encoded transfer payload was empty")
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if decoded["method"] != "transfer" {
		t.Fatalf("method mismatch in JSON: %#v", decoded)
	}
}

func TestValidateContractABIDuplicateMethodRejects(t *testing.T) {
	badABI := ContractABI{Version: 1, Methods: []ABIMethod{
		{Name: "transfer", Parameters: []ABIParameter{{Name: "to", Type: ABITypeAddress}}},
		{Name: "TRANSFER", Parameters: []ABIParameter{{Name: "from", Type: ABITypeAddress}}},
	}}
	if err := ValidateContractABI(&badABI); err == nil {
		t.Fatal("expected duplicate method validation to fail")
	}
}

func TestContractTemplateScaffold(t *testing.T) {
	helper := &ContractTemplateHelper{}
	for _, lang := range []string{"rust", "cpp", "go", "assemblyscript", "native"} {
		manifest, err := helper.GenerateScaffold(lang, "stablecoin", "stablecoin_contract")
		if err != nil {
			t.Fatalf("GenerateScaffold(%s) failed: %v", lang, err)
		}
		if manifest == nil || manifest.Template == "" {
			t.Fatalf("template for %s was empty", lang)
		}
		if manifest.ABI == nil || manifest.ABI.Version == 0 {
			t.Fatalf("ABI for %s was empty", lang)
		}
		if manifest.ContractName == "" {
			t.Fatalf("contract name was empty for %s", lang)
		}
	}

	if _, err := helper.GenerateScaffold("unknown", "stablecoin", "x"); err == nil {
		t.Fatal("expected unsupported language to fail")
	}
}

func TestSecurityHardening(t *testing.T) {
	policy := DefaultSecurityPolicy()
	auditor := NewSecurityAuditor(policy)
	meta := &ContractMeta{Runtime: "bogus-runtime", RuntimeVersion: 99}
	result := auditor.AuditDeployment("contract-a", meta, nil)
	if result == nil || result.Passed {
		t.Fatal("deployment audit should fail for invalid runtime metadata")
	}

	missingMeta := auditor.AuditDeployment("contract-b", nil, nil)
	if missingMeta == nil || missingMeta.Passed {
		t.Fatal("nil metadata should fail deployment audit")
	}

	limiter := NewResourceLimiter(policy, 1_000)
	if err := limiter.ChargeGas(400); err != nil {
		t.Fatalf("charge gas failed: %v", err)
	}
	if err := limiter.EnterCall(); err != nil {
		t.Fatalf("enter call failed: %v", err)
	}
	if err := limiter.EnterCall(); err != nil {
		t.Fatalf("second enter call should be allowed within policy")
	}
	if limiter.callDepth != 2 {
		t.Fatalf("call depth mismatch: got %d want 2", limiter.callDepth)
	}
	if err := limiter.ExitCall(); err != nil {
		t.Fatalf("exit call failed: %v", err)
	}
	if err := limiter.ChargeMemory(1); err != nil {
		t.Fatalf("charge memory failed: %v", err)
	}

	validator := NewInputValidator()
	if err := validator.ValidateInput([]ABIValue{*NewABIValueString(string(make([]byte, 10_001)))}); err == nil {
		t.Fatal("oversized string should fail input validation")
	}

	checker := NewComplianceChecker(DefaultUpgradePolicy())
	oldMeta := &ContractMeta{Runtime: RuntimeWASM, RuntimeVersion: 1}
	newMeta := &ContractMeta{Runtime: RuntimeWASM, RuntimeVersion: 1}
	oldABI := &ContractABI{Version: 1, Methods: []ABIMethod{{Name: "transfer", Parameters: []ABIParameter{{Name: "to", Type: ABITypeAddress}}, Returns: []ABIParameter{{Name: "ok", Type: ABITypeBool}}}}}
	newABI := &ContractABI{Version: 2, Methods: []ABIMethod{{Name: "transfer", Parameters: []ABIParameter{{Name: "to", Type: ABITypeAddress}}, Returns: []ABIParameter{{Name: "ok", Type: ABITypeBool}}}}}
	if errs := checker.CheckUpgrade(oldMeta, newMeta, oldABI, newABI); len(errs) == 0 {
		t.Fatal("upgrade checker should reject missing version bump")
	}
}

func TestContractSimulatorDryRun(t *testing.T) {
	sim := NewContractSimulator()
	addr, err := sim.Deploy(&DeploySpec{
		Runtime:       RuntimeNative,
		Standard:      StandardSIP20,
		Name:          "TestUSD",
		Symbol:        "TUSD",
		Decimals:      18,
		InitialSupply: "1000",
	})
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	result, err := sim.Simulate(addr, NewStablecoinBalanceOfCall("test"))
	if err != nil {
		t.Fatalf("simulate failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("simulation failed: %v", result.Error)
	}
	if result.StorageBefore == nil || result.StorageAfter == nil {
		t.Fatal("storage snapshots should be recorded")
	}
	if got := result.StorageAfter["sip20:balance:test"]; got == "" {
		t.Fatalf("balance storage should be present: %#v", result.StorageAfter)
	}
}

// TestStorageValues tests typed storage values
func TestStorageValues(t *testing.T) {
	tests := []struct {
		name  string
		value *StorageValue
		check func(*StorageValue) bool
	}{
		{
			name:  "word",
			value: NewStorageValueWord(12345),
			check: func(sv *StorageValue) bool {
				v, err := sv.AsWord()
				return err == nil && v == 12345
			},
		},
		{
			name:  "int",
			value: NewStorageValueInt(-999),
			check: func(sv *StorageValue) bool {
				v, err := sv.AsInt()
				return err == nil && v == -999
			},
		},
		{
			name:  "string",
			value: NewStorageValueString("test data"),
			check: func(sv *StorageValue) bool {
				v, err := sv.AsString()
				return err == nil && v == "test data"
			},
		},
		{
			name:  "bytes",
			value: NewStorageValueBytes([]byte{1, 2, 3, 4}),
			check: func(sv *StorageValue) bool {
				v, err := sv.AsBytes()
				if err != nil {
					return false
				}
				if len(v) != 4 {
					return false
				}
				return v[0] == 1 && v[3] == 4
			},
		},
		{
			name:  "bool",
			value: NewStorageValueBool(true),
			check: func(sv *StorageValue) bool {
				v, err := sv.AsBool()
				return err == nil && v == true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization and deserialization
			serialized := tt.value.Bytes()
			parsed, err := ParseStorageValue(serialized)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			if !tt.check(parsed) {
				t.Fatalf("value check failed")
			}
		})
	}
}

// TestBoundedArray tests the bounded array container
func TestBoundedArray(t *testing.T) {
	store := NewMemoryStore()
	addr := "test-contract"
	store.SetContractCode(addr, []byte{1, 2, 3})

	ba := NewBoundedArray(store, addr, "items", 3)

	// Test push
	if err := ba.Push([]byte("first")); err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if err := ba.Push([]byte("second")); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	if ba.Len() != 2 {
		t.Fatalf("length mismatch: got %d, want 2", ba.Len())
	}

	// Test capacity limit
	ba.Push([]byte("third"))
	if err := ba.Push([]byte("fourth")); err == nil {
		t.Fatalf("expected capacity error")
	}

	// Test save and load
	if err := ba.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	ba2 := NewBoundedArray(store, addr, "items", 3)
	if err := ba2.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if ba2.Len() != 3 {
		t.Fatalf("loaded length mismatch: got %d, want 3", ba2.Len())
	}

	// Test get
	first, err := ba2.Get(0)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if string(first) != "first" {
		t.Fatalf("value mismatch: got %s, want 'first'", string(first))
	}

	// Test pop
	last, err := ba2.Pop()
	if err != nil {
		t.Fatalf("pop failed: %v", err)
	}
	if string(last) != "third" {
		t.Fatalf("pop value mismatch: got %s, want 'third'", string(last))
	}
	if ba2.Len() != 2 {
		t.Fatalf("post-pop length mismatch: got %d, want 2", ba2.Len())
	}
}

// TestBoundedMap tests the bounded map container
func TestBoundedMap(t *testing.T) {
	store := NewMemoryStore()
	addr := "test-contract"
	store.SetContractCode(addr, []byte{1, 2, 3})

	bm := NewBoundedMap(store, addr, "balances", 5)

	// Test set
	if err := bm.Set("alice", []byte("100")); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if err := bm.Set("bob", []byte("50")); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	// Test get
	alice, err := bm.Get("alice")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if string(alice) != "100" {
		t.Fatalf("value mismatch: got %s, want '100'", string(alice))
	}

	// Test keys
	keys := bm.Keys()
	if len(keys) != 2 {
		t.Fatalf("keys length mismatch: got %d, want 2", len(keys))
	}

	// Test size
	if bm.Size() != 2 {
		t.Fatalf("size mismatch: got %d, want 2", bm.Size())
	}

	// Test delete
	if err := bm.Delete("alice"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if bm.Size() != 1 {
		t.Fatalf("post-delete size mismatch: got %d, want 1", bm.Size())
	}

	// Test capacity limit
	for i := 0; i < 4; i++ {
		if err := bm.Set("key"+string(rune(i)), []byte("val")); err != nil {
			t.Fatalf("set failed at iteration %d: %v", i, err)
		}
	}

	if err := bm.Set("extra", []byte("val")); err == nil {
		t.Fatalf("expected capacity error")
	}

	// Test save and load
	if err := bm.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	bm2 := NewBoundedMap(store, addr, "balances", 5)
	if err := bm2.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if bm2.Size() != bm.Size() {
		t.Fatalf("loaded size mismatch: got %d, want %d", bm2.Size(), bm.Size())
	}
}

// TestCallContext tests call depth and reentrancy protection
func TestCallContext(t *testing.T) {
	ctx := NewCallContext(5, true)

	// Test depth tracking
	if ctx.Depth != 0 {
		t.Fatalf("initial depth mismatch: got %d, want 0", ctx.Depth)
	}

	if err := ctx.Push("contract1"); err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if ctx.Depth != 1 {
		t.Fatalf("post-push depth mismatch: got %d, want 1", ctx.Depth)
	}

	// Test reentrancy protection
	if err := ctx.Push("contract1"); err == nil {
		t.Fatalf("expected reentrancy error")
	}

	if err := ctx.Push("contract2"); err != nil {
		t.Fatalf("push of different contract failed: %v", err)
	}
	if ctx.Depth != 2 {
		t.Fatalf("depth after second push mismatch: got %d, want 2", ctx.Depth)
	}

	// Test depth limit
	for i := 2; i < 5; i++ {
		if err := ctx.Push("contract" + string(rune(i))); err != nil {
			t.Fatalf("push at depth %d failed: %v", i, err)
		}
	}

	// Should hit limit
	if err := ctx.Push("contract999"); err == nil {
		t.Fatalf("expected depth limit error")
	}

	// Test pop
	if err := ctx.Pop(); err != nil {
		t.Fatalf("pop failed: %v", err)
	}
	if ctx.Depth != 4 {
		t.Fatalf("post-pop depth mismatch: got %d, want 4", ctx.Depth)
	}
}

// TestRichCallData tests building typed call data
func TestRichCallData(t *testing.T) {
	args := []ABIValue{
		*NewABIValueAddress("SPIF 1234 5678"),
		*NewABIValueUint64(1000),
	}

	spec := &RichCallSpec{
		Method: "Transfer",
		Args:   args,
		Value:  big.NewInt(0),
	}

	callData, err := BuildRichCallData(spec)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed RichCallSpec
	if err := json.Unmarshal(callData, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Method != "transfer" {
		t.Fatalf("method mismatch: got %s, want 'transfer'", parsed.Method)
	}

	if len(parsed.Args) != 2 {
		t.Fatalf("args count mismatch: got %d, want 2", len(parsed.Args))
	}
}

// TestContractSimulator tests contract simulation environment
func TestContractSimulator(t *testing.T) {
	sim := NewContractSimulator()

	spec := &DeploySpec{
		Runtime:  RuntimeNative,
		Standard: StandardSIP20,
		Name:     "TestToken",
		Symbol:   "TEST",
		Decimals: 18,
	}

	addr, err := sim.Deploy(spec)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	if addr == "" {
		t.Fatalf("got empty contract address")
	}

	if !sim.store.ContractExists(addr) {
		t.Fatalf("deployed contract not found")
	}
}

// BenchmarkABIValue benchmarks ABI value creation and extraction
func BenchmarkABIValue(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		val := NewABIValueUint64(uint64(i))
		val.AsUint64()
	}
}

// BenchmarkStorageValue benchmarks storage value serialization
func BenchmarkStorageValue(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		sv := NewStorageValueWord(uint64(i))
		sv.Bytes()
		ParseStorageValue(sv.Bytes())
	}
}

// BenchmarkBoundedMap benchmarks map operations
func BenchmarkBoundedMap(b *testing.B) {
	store := NewMemoryStore()
	addr := "test"
	store.SetContractCode(addr, []byte{1})

	bm := NewBoundedMap(store, addr, "data", 1000)

	for i := 0; b.Loop(); i++ {
		key := "key" + string(rune(i%100))
		bm.Set(key, []byte("value"))
	}
}
