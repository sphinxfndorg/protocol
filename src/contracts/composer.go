// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// CallDepthLimit is the maximum nesting depth for contract-to-contract calls
const CallDepthLimit = 64

// CallContext tracks the state of nested contract calls for reentrancy detection
// and depth accounting. It is immutable during execution and passed through the
// call stack to enforce safety limits.
type CallContext struct {
	// Depth is the current call nesting depth (0 for top-level calls)
	Depth uint32

	// CallStack tracks the contracts called in this execution path for reentrancy detection
	CallStack []string

	// MaxDepth is the maximum nesting depth allowed (typically CallDepthLimit)
	MaxDepth uint32

	// ReentrancyProtection enables reentrancy checks (mutual exclusion)
	ReentrancyProtection bool

	// mutex protects concurrent updates to CallStack during async operations
	mu sync.Mutex
}

// NewCallContext creates a new call context for a top-level transaction
func NewCallContext(maxDepth uint32, reentrancy bool) *CallContext {
	if maxDepth == 0 {
		maxDepth = CallDepthLimit
	}
	return &CallContext{
		Depth:                0,
		CallStack:           []string{},
		MaxDepth:            maxDepth,
		ReentrancyProtection: reentrancy,
	}
}

// CanCall checks if a call to targetContract is allowed under current depth and reentrancy rules
func (cc *CallContext) CanCall(targetContract string) error {
	if cc.Depth >= cc.MaxDepth {
		return fmt.Errorf("call depth limit exceeded: %d >= %d", cc.Depth, cc.MaxDepth)
	}

	if cc.ReentrancyProtection {
		for _, addr := range cc.CallStack {
			if addr == targetContract {
				return fmt.Errorf("reentrancy protection: contract %s already in call stack", targetContract)
			}
		}
	}

	return nil
}

// Push adds a contract to the call stack and increments depth
func (cc *CallContext) Push(contract string) error {
	if err := cc.CanCall(contract); err != nil {
		return err
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.CallStack = append(cc.CallStack, contract)
	cc.Depth++
	return nil
}

// Pop removes a contract from the call stack and decrements depth
func (cc *CallContext) Pop() error {
	if len(cc.CallStack) == 0 {
		return errors.New("call stack underflow")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.CallStack = cc.CallStack[:len(cc.CallStack)-1]
	cc.Depth--
	return nil
}

// IsNestedCall returns true if this is a nested contract call
func (cc *CallContext) IsNestedCall() bool {
	return cc.Depth > 0
}

// CurrentCaller returns the immediate caller in the call stack
func (cc *CallContext) CurrentCaller() string {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if len(cc.CallStack) == 0 {
		return ""
	}
	return cc.CallStack[len(cc.CallStack)-1]
}

// ComposableStore wraps a Store and provides contract-to-contract call support
type ComposableStore struct {
	Store
	callContext *CallContext
	txBuffer    map[string][]byte // transaction-scoped write buffer for atomic rollback
}

// NewComposableStore creates a composable store with call tracking
func NewComposableStore(underlying Store, callContext *CallContext) *ComposableStore {
	if callContext == nil {
		callContext = NewCallContext(CallDepthLimit, true)
	}
	return &ComposableStore{
		Store:       underlying,
		callContext: callContext,
		txBuffer:    make(map[string][]byte),
	}
}

// SetContractStorage buffers writes for atomic rollback on call failure
func (cs *ComposableStore) SetContractStorage(address, key string, value []byte) {
	// Write to buffer
	compositeKey := address + ":" + key
	if value == nil {
		cs.txBuffer[compositeKey] = []byte{}
	} else {
		cs.txBuffer[compositeKey] = append([]byte(nil), value...)
	}
	// Also write through to underlying store for immediate reads in the same call
	cs.Store.SetContractStorage(address, key, value)
}

// GetContractStorage reads from buffer first, then falls back to underlying store
func (cs *ComposableStore) GetContractStorage(address, key string) ([]byte, error) {
	compositeKey := address + ":" + key
	if buffered, ok := cs.txBuffer[compositeKey]; ok {
		return append([]byte(nil), buffered...), nil
	}
	return cs.Store.GetContractStorage(address, key)
}

// RollbackWrites discards buffered writes (used on call failure)
func (cs *ComposableStore) RollbackWrites() {
	cs.txBuffer = make(map[string][]byte)
}

// CommitWrites persists all buffered writes to the underlying store
func (cs *ComposableStore) CommitWrites() error {
	for compositeKey, value := range cs.txBuffer {
		// Find the last occurrence of ":" to split address:key
		lastColon := -1
		for i := len(compositeKey) - 1; i >= 0; i-- {
			if compositeKey[i] == ':' {
				if lastColon == -1 {
					lastColon = i
				} else {
					// Found the first colon (the one between address and key)
					address := compositeKey[:i]
					key := compositeKey[i+1:]
					cs.Store.SetContractStorage(address, key, value)
					break
				}
			}
		}
	}
	return nil
}

// ContractCallMessage is sent to a contract via the call interface
type ContractCallMessage struct {
	To       string      `json:"to"`
	Method   string      `json:"method"`
	Args     []ABIValue  `json:"args,omitempty"`
	Value    string      `json:"value,omitempty"`    // amount in wei/units
	From     string      `json:"from,omitempty"`     // caller address
	ReadOnly bool        `json:"readonly,omitempty"`
}

// ContractCallResult contains the result of a contract call
type ContractCallResult struct {
	Success bool                `json:"success"`
	Return  []ABIValue          `json:"return,omitempty"`
	Error   string              `json:"error,omitempty"`
	Events  []ContractEvent     `json:"events,omitempty"`
	GasUsed uint64              `json:"gas_used,omitempty"`
}

// ComposabilityExecutor handles contract-to-contract calls safely
type ComposabilityExecutor struct {
	store           *ComposableStore
	callContext     *CallContext
	maxGasPerCall   uint64
	callFrameBuilder *CallFrameBuilder
}

// NewComposabilityExecutor creates an executor for composable contracts
func NewComposabilityExecutor(store Store, callContext *CallContext, maxGasPerCall uint64) *ComposabilityExecutor {
	if callContext == nil {
		callContext = NewCallContext(CallDepthLimit, true)
	}
	if maxGasPerCall == 0 {
		maxGasPerCall = 1_000_000 // Default 1M gas per nested call
	}
	return &ComposabilityExecutor{
		store:           NewComposableStore(store, callContext),
		callContext:     callContext,
		maxGasPerCall:   maxGasPerCall,
		callFrameBuilder: NewCallFrameBuilder(0, "", "", "", "", nil),
	}
}

// SetCallFrameBuilder sets the call frame builder for tracing
func (ce *ComposabilityExecutor) SetCallFrameBuilder(builder *CallFrameBuilder) {
	ce.callFrameBuilder = builder
}

// Call invokes a contract method and returns the result
// If the call succeeds, writes are committed; if it fails, writes are rolled back
func (ce *ComposabilityExecutor) Call(msg *ContractCallMessage) (*ContractCallResult, error) {
	if msg == nil {
		return nil, errors.New("nil call message")
	}

	if err := ce.callContext.Push(msg.To); err != nil {
		return &ContractCallResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}
	defer ce.callContext.Pop()

	// Check if contract exists
	if !ce.store.ContractExists(msg.To) {
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("contract does not exist: %s", msg.To),
		}, nil
	}

	// Get contract code and metadata
	code, err := ce.store.GetContractCode(msg.To)
	if err != nil {
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("failed to get contract code: %v", err),
		}, nil
	}

	metaBytes, err := ce.store.GetContractMeta(msg.To)
	if err != nil {
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("failed to get contract metadata: %v", err),
		}, nil
	}

	var meta ContractMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("invalid contract metadata: %v", err),
		}, nil
	}

	// Validate contract version
	if err := ValidateContractMeta(&meta); err != nil {
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("invalid contract version: %v", err),
		}, nil
	}

	// Convert typed arguments to bytes for execution
	callDataSpec := &RichCallSpec{
		Method:   msg.Method,
		Args:     msg.Args,
		ReadOnly: msg.ReadOnly,
	}

	callData, err := BuildRichCallData(callDataSpec)
	if err != nil {
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("invalid call data: %v", err),
		}, nil
	}

	// Determine runtime kind for tracing using tagged switch
	var runtimeKind string
	switch meta.Runtime {
	case RuntimeWASM:
		runtimeKind = "wasm"
	case RuntimeNative:
		runtimeKind = "native"
	case RuntimeSVM1:
		runtimeKind = "svm1"
	default:
		runtimeKind = "unknown"
	}

	// Push a call frame for this execution if we have a builder
	var frame *CallFrame
	if ce.callFrameBuilder != nil {
		frame = ce.callFrameBuilder.PushFrame(runtimeKind, msg.To, msg.From, msg.Method, abivarsToMap(msg.Args))
		defer ce.callFrameBuilder.PopFrame()
	}

	// Execute based on runtime
	var result *ExecutionResult
	var execErr error

	switch meta.Runtime {
	case RuntimeWASM:
		if msg.ReadOnly {
			result, execErr = ExecuteWASMReadOnly(ce.store, msg.To, code, callData, 1_000_000, 512)
		} else {
			result, execErr = ExecuteWASM(ce.store, msg.To, code, callData, 1_000_000, 512)
		}

	case RuntimeNative:
		// Native contracts handle their own logic
		result, execErr = executeNativeCall(ce.store, ce.callFrameBuilder, &meta, callData, NativeCallContext{})

	case RuntimeSVM1:
		// SVM1 execution
		result, execErr = executeSVM1Call(ce.store, ce.callFrameBuilder, &meta, code, callData)

	default:
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("unsupported runtime: %s", meta.Runtime),
		}, nil
	}

	if execErr != nil {
		if frame != nil {
			frame.Reverted = true
			frame.RevertReason = execErr.Error()
		}
		ce.store.RollbackWrites()
		return &ContractCallResult{
			Success: false,
			Error:   execErr.Error(),
		}, nil
	}

	// Commit writes on success
	if err := ce.store.CommitWrites(); err != nil {
		if frame != nil {
			frame.Reverted = true
			frame.RevertReason = err.Error()
		}
		return &ContractCallResult{
			Success: false,
			Error:   fmt.Sprintf("failed to commit writes: %v", err),
		}, nil
	}

	// Set gas used on frame (use ContractCallResult's GasUsed which is tracked separately)
	if frame != nil {
		// Gas accounting is handled by the executor; set a placeholder for now
		// In production, this would be the actual gas consumed from the call
		frame.GasUsed = 0 // Will be populated by the caller based on actual gas tracking
	}

	// Parse the result into typed return values
	convertedResult := &ContractCallResult{
		Success: result.Status == "success",
		Events:  result.Events,
	}

	// Convert return values from map[string]string to ABIValues if possible
	if result.Return != nil {
		// This is a simplified conversion; full implementation would parse ABI
		for k, v := range result.Return {
			convertedResult.Return = append(convertedResult.Return, *NewABIValueString(fmt.Sprintf("%s=%s", k, v)))
		}
	}

	return convertedResult, nil
}

// CallReadOnly executes a read-only call that cannot modify state
func (ce *ComposabilityExecutor) CallReadOnly(msg *ContractCallMessage) (*ContractCallResult, error) {
	msg.ReadOnly = true
	result, err := ce.Call(msg)
	// Read-only calls don't persist any changes
	ce.store.RollbackWrites()
	return result, err
}

// executeNativeCall executes a native contract call with the given metadata,
// call data, and context. It parses the call data, validates the contract standard,
// and dispatches to the appropriate native contract handler.
func executeNativeCall(store Store, builder *CallFrameBuilder, meta *ContractMeta, callData []byte, ctx NativeCallContext) (*ExecutionResult, error) {
	if meta == nil {
		return nil, errors.New("nil contract metadata")
	}

	// Parse the call data to extract method and args
	var call CallSpec
	if err := json.Unmarshal(callData, &call); err != nil {
		return nil, fmt.Errorf("decode call data: %w", err)
	}

	call.Method = strings.ToLower(strings.TrimSpace(call.Method))
	if call.Method == "" {
		return nil, errors.New("missing method in call data")
	}
	if call.Args == nil {
		call.Args = map[string]string{}
	}

	// Update the current frame's args if we have a builder
	if builder != nil && builder.current != nil {
		builder.current.Args = call.Args
	}

	// Determine caller from context or default to empty string
	caller := ""
	if ctx.Value != nil {
		caller = ""
	}

	// Dispatch to the appropriate standard handler
	switch meta.Standard {
	case StandardSIP20:
		// For SIP20, we need a store to call the actual implementation
		if store == nil {
			return nil, errors.New("store required for SIP20 execution")
		}
		// Call the actual SIP20 handler with the decoded call spec
		callSpec := &CallSpec{
			Method: call.Method,
			Args:   call.Args,
		}
		result, err := callSIP20(store, meta.Address, caller, callSpec)
		if err != nil {
			return nil, err
		}
		// Record events if we have a builder
		if builder != nil && builder.current != nil && len(result.Events) > 0 {
			for _, event := range result.Events {
				builder.AddEvent(meta.Address, event.Topic, map[string]string{"data": event.Data})
			}
		}
		return result, nil

	case StandardSIP721:
		// For SIP721 with context, we would call SIP721 handlers
		if store == nil {
			return nil, errors.New("store required for SIP721 execution")
		}
		callSpec := &CallSpec{
			Method: call.Method,
			Args:   call.Args,
		}
		result, err := callSIP721WithContext(store, meta.Address, caller, callSpec, &ctx)
		if err != nil {
			return nil, err
		}
		if builder != nil && builder.current != nil && len(result.Events) > 0 {
			for _, event := range result.Events {
				builder.AddEvent(meta.Address, event.Topic, map[string]string{"data": event.Data})
			}
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported contract standard: %s", meta.Standard)
	}
}

// executeSVM1Call executes SVM1 bytecode using the kernel's SVM1 execution engine.
// It takes the store, contract metadata, bytecode, and call data, and returns
// the execution result with status and any return value.
func executeSVM1Call(store Store, builder *CallFrameBuilder, meta *ContractMeta, code, callData []byte) (*ExecutionResult, error) {
	if store == nil {
		return nil, errors.New("nil store")
	}
	if meta == nil {
		return nil, errors.New("nil contract metadata")
	}
	if code == nil {
		return nil, errors.New("nil contract code")
	}

	// Use the kernel's SVM1 execution engine
	// The store must satisfy the SVM1Store interface (GetContractStorage, SetContractStorage)
	result, ops, execErr := ExecuteSVMWithCallData(store, meta.Address, code, callData, 1_000_000)
	if execErr != nil {
		return nil, execErr
	}

	// Set gas used on the frame if we have a builder
	if builder != nil && builder.current != nil {
		builder.SetGasUsed(ops)
	}

	return result, nil
}
