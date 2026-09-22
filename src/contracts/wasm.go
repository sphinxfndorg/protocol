// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const RuntimeWASM = "wasm1"

type wasmReadOnlyStore struct {
	Store
	values map[string][]byte
}

func newWASMReadOnlyStore(store Store) *wasmReadOnlyStore {
	return &wasmReadOnlyStore{Store: store, values: make(map[string][]byte)}
}

func (s *wasmReadOnlyStore) GetContractStorage(address, key string) ([]byte, error) {
	if value, ok := s.values[address+"\x00"+key]; ok {
		return append([]byte(nil), value...), nil
	}
	return s.Store.GetContractStorage(address, key)
}

func (s *wasmReadOnlyStore) SetContractStorage(address, key string, value []byte) {
	s.values[address+"\x00"+key] = append([]byte(nil), value...)
}

var wasmMagic = []byte{'\x00', 'a', 's', 'm', '\x01', '\x00', '\x00', '\x00'}

// IsWASM reports whether code is a WebAssembly 1.0 binary.
func IsWASM(code []byte) bool {
	if len(code) < len(wasmMagic) {
		return false
	}
	for i := range wasmMagic {
		if code[i] != wasmMagic[i] {
			return false
		}
	}
	return true
}

// ValidateWASM verifies the module can be compiled by the pinned WASM engine.
// There is intentionally no WASI host module, filesystem, sockets, clock, or
// random source. A contract must export a zero-argument `sphinx_main` entry.
func ValidateWASM(code []byte, maxCodeBytes uint64, memoryPages uint32) error {
	if !IsWASM(code) {
		return errors.New("invalid WASM magic/version")
	}
	if uint64(len(code)) > maxCodeBytes {
		return fmt.Errorf("WASM code exceeds policy maximum: %d > %d", len(code), maxCodeBytes)
	}
	if _, err := AnalyzeWASM(code); err != nil {
		return err
	}
	ctx := context.Background()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithMemoryLimitPages(memoryPages).WithDebugInfoEnabled(false))
	defer runtime.Close(ctx)
	compiled, err := runtime.CompileModule(ctx, code)
	if err != nil {
		return fmt.Errorf("compile WASM: %w", err)
	}
	defer compiled.Close(ctx)
	if len(compiled.ImportedMemories()) != 0 {
		return errors.New("WASM imported memory is not supported")
	}
	for _, definition := range compiled.ImportedFunctions() {
		module, name, imported := definition.Import()
		if !imported || module != "sphinx" || !allowedWASMImport(name, definition) {
			return fmt.Errorf("unsupported WASM import %q.%q", module, name)
		}
	}
	if _, ok := compiled.ExportedFunctions()["sphinx_main"]; !ok {
		return errors.New("WASM contract must export sphinx_main")
	}
	main := compiled.ExportedFunctions()["sphinx_main"]
	if len(main.ParamTypes()) != 0 || len(main.ResultTypes()) > 1 || (len(main.ResultTypes()) == 1 && main.ResultTypes()[0] != api.ValueTypeI64) {
		return errors.New("sphinx_main must have signature () -> () or () -> i64")
	}
	return nil
}

func allowedWASMImport(name string, definition api.FunctionDefinition) bool {
	params, results := definition.ParamTypes(), definition.ResultTypes()
	switch name {
	case "storage_get", "calldata_word":
		return len(params) == 1 && params[0] == api.ValueTypeI64 && len(results) == 1 && results[0] == api.ValueTypeI64
	case "storage_set":
		return len(params) == 2 && params[0] == api.ValueTypeI64 && params[1] == api.ValueTypeI64 && len(results) == 0
	case "caller", "transferred_value", "block_height":
		return len(params) == 0 && len(results) == 1 && results[0] == api.ValueTypeI64
	case "emit_event":
		return len(params) == 2 && params[0] == api.ValueTypeI64 && params[1] == api.ValueTypeI64 && len(results) == 0
	case "transfer":
		return len(params) == 3 && params[0] == api.ValueTypeI32 && params[1] == api.ValueTypeI32 && params[2] == api.ValueTypeI64 && len(results) == 1 && results[0] == api.ValueTypeI32
	default:
		return false
	}
}

// ExecuteWASM executes a WASM contract with the Sphinx host ABI. Storage is
// uint64-keyed and all values/call-data words are uint64, which keeps the ABI
// portable across Rust, C/C++, TinyGo and AssemblyScript targets.
func ExecuteWASM(store Store, address string, code, callData []byte, maxCodeBytes uint64, memoryPages uint32) (*ExecutionResult, error) {
	return ExecuteWASMWithContext(store, address, code, callData, maxCodeBytes, memoryPages, WASMContext{})
}

// ExecuteWASMReadOnly evaluates a WASM contract against an isolated storage
// overlay. Reads observe writes made earlier in the invocation, but no write
// reaches the supplied store and transfers are always rejected.
func ExecuteWASMReadOnly(store Store, address string, code, callData []byte, maxCodeBytes uint64, memoryPages uint32) (*ExecutionResult, error) {
	return ExecuteWASMReadOnlyWithContext(store, address, code, callData, maxCodeBytes, memoryPages, WASMContext{})
}

// ExecuteWASMReadOnlyWithContext is the contextual form of
// ExecuteWASMReadOnly. The Transfer callback in execution is deliberately
// ignored, so read-only callers cannot move balances.
func ExecuteWASMReadOnlyWithContext(store Store, address string, code, callData []byte, maxCodeBytes uint64, memoryPages uint32, execution WASMContext) (*ExecutionResult, error) {
	overlay := newWASMReadOnlyStore(store)
	execution.Transfer = func(string, uint64) error {
		return errors.New("WASM transfer unavailable in read-only execution")
	}
	return executeWASMWithStore(overlay, address, code, callData, maxCodeBytes, memoryPages, execution)
}

// WASMContext exposes deterministic transaction/block values. Address-like
// values are represented as the first 64 bits of SHA-256(address), avoiding a
// non-portable pointer/string ABI across Rust, C/C++, TinyGo and AssemblyScript.
type WASMContext struct {
	Caller      string
	Value       uint64
	BlockHeight uint64
	MaxEvents   uint64
	Transfer    func(to string, amount uint64) error
}

func ExecuteWASMWithContext(store Store, address string, code, callData []byte, maxCodeBytes uint64, memoryPages uint32, execution WASMContext) (*ExecutionResult, error) {
	return executeWASMWithStore(store, address, code, callData, maxCodeBytes, memoryPages, execution)
}

func executeWASMWithStore(store Store, address string, code, callData []byte, maxCodeBytes uint64, memoryPages uint32, execution WASMContext) (*ExecutionResult, error) {
	if store == nil {
		return nil, errors.New("nil contract store")
	}
	if err := ValidateWASM(code, maxCodeBytes, memoryPages); err != nil {
		return nil, err
	}
	ctx := context.Background()
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter().WithMemoryLimitPages(memoryPages).WithDebugInfoEnabled(false))
	defer runtime.Close(ctx)
	key := func(value uint64) string { return fmt.Sprintf("wasm:%016x", value) }
	callerHash := sha256.Sum256([]byte(execution.Caller))
	caller := uint64(callerHash[0])<<56 | uint64(callerHash[1])<<48 | uint64(callerHash[2])<<40 | uint64(callerHash[3])<<32 | uint64(callerHash[4])<<24 | uint64(callerHash[5])<<16 | uint64(callerHash[6])<<8 | uint64(callerHash[7])
	events := make([]ContractEvent, 0)
	_, err := runtime.NewHostModuleBuilder("sphinx").
		NewFunctionBuilder().WithFunc(func(k uint64) uint64 {
		data, err := store.GetContractStorage(address, key(k))
		if err != nil || len(data) != 8 {
			return 0
		}
		return uint64(data[0])<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 | uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
	}).Export("storage_get").
		NewFunctionBuilder().WithFunc(func(k, value uint64) {
		store.SetContractStorage(address, key(k), []byte{byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	}).Export("storage_set").
		NewFunctionBuilder().WithFunc(func(offset uint64) uint64 {
		var word [8]byte
		if offset < uint64(len(callData)) {
			copy(word[:], callData[offset:])
		}
		return uint64(word[0])<<56 | uint64(word[1])<<48 | uint64(word[2])<<40 | uint64(word[3])<<32 | uint64(word[4])<<24 | uint64(word[5])<<16 | uint64(word[6])<<8 | uint64(word[7])
	}).Export("calldata_word").
		NewFunctionBuilder().WithFunc(func() uint64 { return caller }).Export("caller").
		NewFunctionBuilder().WithFunc(func() uint64 { return execution.Value }).Export("transferred_value").
		NewFunctionBuilder().WithFunc(func() uint64 { return execution.BlockHeight }).Export("block_height").
		NewFunctionBuilder().WithFunc(func(topic, value uint64) {
		if uint64(len(events)) < execution.MaxEvents {
			events = append(events, ContractEvent{Topic: fmt.Sprintf("%016x", topic), Data: fmt.Sprintf("%d", value)})
		}
	}).Export("emit_event").
		NewFunctionBuilder().WithFunc(func(_ context.Context, module api.Module, pointer, length uint32, amount uint64) uint32 {
		if execution.Transfer == nil || length == 0 || length > 128 {
			return 1
		}
		address, ok := module.Memory().Read(pointer, length)
		if !ok || len(address) == 0 || execution.Transfer(string(address), amount) != nil {
			return 1
		}
		return 0
	}).Export("transfer").
		Instantiate(ctx)
	if err != nil {
		return nil, fmt.Errorf("instantiate Sphinx WASM ABI: %w", err)
	}
	compiled, err := runtime.CompileModule(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("compile WASM: %w", err)
	}
	defer compiled.Close(ctx)
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return nil, fmt.Errorf("instantiate WASM: %w", err)
	}
	defer module.Close(ctx)
	result, err := module.ExportedFunction("sphinx_main").Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("execute WASM: %w", err)
	}
	output := "0"
	if len(result) > 0 {
		output = fmt.Sprintf("%d", result[0])
	}
	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{"result": output, "runtime": RuntimeWASM}, Events: events}, nil
}
