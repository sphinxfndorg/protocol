# Sphinx Smart Contract Platform - Production Features

This document describes the complete smart contract platform implementation for the Sphinx Protocol, including composability, typed storage, and developer tooling.

## Table of Contents

1. [Rich ABI System](#rich-abi-system)
2. [Contract Composability](#contract-composability)
3. [Typed Storage](#typed-storage)
4. [Developer Tools](#developer-tools)
5. [Security & Auditing](#security--auditing)
6. [Contract Templates](#contract-templates)
7. [Best Practices](#best-practices)

---

## Rich ABI System

The Sphinx protocol supports a rich, type-safe ABI for contract arguments and return values. This enables safe composition of contracts and better tooling support.

### Supported Types

- **Primitive Types:**
  - `uint64` - Unsigned 64-bit integer
  - `int64` - Signed 64-bit integer
  - `bool` - Boolean value
  - `bytes` - Variable-length byte array
  - `address` - Contract or account address
  - `string` - UTF-8 string
  - `amount` - Big integer (arbitrary precision)

- **Composite Types:**
  - `array` - Homogeneous collection of values
  - `struct` - Named fields with typed values
  - `optional` - Nullable value (0 or 1 items)

### Example: Creating Typed Arguments

```go
import "github.com/sphinxfndorg/protocol/src/contracts"

// Create a transfer call with typed arguments
args := []contracts.ABIValue{
    *contracts.NewABIValueAddress("SPIF 1234 5678"),  // to
    *contracts.NewABIValueAmount(big.NewInt(1000)),   // amount
}

callSpec := &contracts.RichCallSpec{
    Method:   "transfer",
    Args:     args,
    Value:    big.NewInt(0),
}

callData, err := contracts.BuildRichCallData(callSpec)
```

### Extracting Typed Return Values

```go
// In contract execution
result, _ := executor.CallContractReadOnly(addr, callData)

// Extract typed returns
if len(result.Return) > 0 {
    val := &result.Return[0]
    amount, _ := val.AsAmount()  // big.Int
    recipient, _ := val.AsAddress()  // string
}
```

---

## Contract Composability

Contracts can safely call other contracts with built-in protections against reentrancy and call depth exhaustion.

### Call Context & Depth Protection

```go
import "github.com/sphinxfndorg/protocol/src/contracts"

// Create a call context with depth limit and reentrancy protection
ctx := contracts.NewCallContext(64, true)

// Track nested calls
ctx.Push("contract_a")
ctx.Push("contract_b")  // Different contract - OK
// ctx.Push("contract_a")  // Would fail: reentrancy protection

currentDepth := ctx.Depth  // 2
caller := ctx.CurrentCaller()  // "contract_b"
ctx.Pop()
```

### Making Composable Calls

```go
// Create a composable executor
executor := contracts.NewComposabilityExecutor(store, ctx, 1_000_000)

// Call another contract
msg := &contracts.ContractCallMessage{
    To:      targetAddr,
    Method:  "transfer",
    Args:    args,
    Value:   big.NewInt(1000),
    From:    callerAddr,
}

result, err := executor.Call(msg)
if result.Success {
    // Process return values
    for _, event := range result.Events {
        fmt.Printf("Event: %s\n", event.Topic)
    }
} else {
    // Changes were rolled back on failure
    fmt.Printf("Call failed: %s\n", result.Error)
}
```

### Read-Only Calls

Read-only calls cannot modify state or transfer funds:

```go
// Execute contract without modifying state
result, err := executor.CallReadOnly(msg)
// All storage writes are discarded
// All transfers are rejected
```

---

## Typed Storage

The protocol provides a type-safe storage layer with bounded containers for complex data structures.

### Storage Value Types

```go
// Create typed storage values
word := contracts.NewStorageValueWord(12345)        // uint64
amount := contracts.NewStorageValueAmount(big.NewInt(1000))  // big.Int
data := contracts.NewStorageValueBytes([]byte{1, 2, 3})  // bytes
name := contracts.NewStorageValueString("Alice")    // string
flag := contracts.NewStorageValueBool(true)         // bool

// Serialize for storage
serialized := word.Bytes()  // Includes type prefix

// Deserialize from storage
parsed, _ := contracts.ParseStorageValue(serialized)
extractedWord, _ := parsed.AsWord()  // uint64
```

### Bounded Arrays

```go
// Create a bounded array (max 1000 elements)
array := contracts.NewBoundedArray(store, address, "items", 1000)

// Load from storage
array.Load()

// Manipulate
array.Push([]byte("item1"))
array.Push([]byte("item2"))

length := array.Len()  // 2

item, _ := array.Get(0)  // []byte("item1")
array.Set(0, []byte("updated"))

last, _ := array.Pop()  // []byte("updated")

// Save changes
array.Save()
```

### Bounded Maps

```go
// Create a bounded map (max 100,000 keys)
balances := contracts.NewBoundedMap(store, address, "balances", 100_000)

// Load from storage
balances.Load()

// Manipulate
balances.Set("alice", []byte("1000"))
balances.Set("bob", []byte("500"))

size := balances.Size()  // 2
keys := balances.Keys()  // []string{"alice", "bob"}

balance, _ := balances.Get("alice")  // []byte("1000")
balances.Delete("bob")

// Save changes
balances.Save()
```

---

## Developer Tools

### Local Contract Simulator

```go
import "github.com/sphinxfndorg/protocol/src/contracts"

// Create a simulator with in-memory storage
sim := contracts.NewContractSimulator()

// Deploy a contract
spec := &contracts.DeploySpec{
    Runtime:  contracts.RuntimeNative,
    Standard: contracts.StandardSIP20,
    Name:     "MyToken",
    Symbol:   "MTK",
}
addr, _ := sim.Deploy(spec)

// Execute a contract call with tracing
callSpec := &contracts.RichCallSpec{
    Method: "balanceOf",
    Args: []contracts.ABIValue{
        *contracts.NewABIValueAddress("SPIF 1234 5678"),
    },
}

trace, _ := sim.Call(addr, callSpec)

// Access execution trace
fmt.Printf("Gas Used: %d\n", trace.GasUsed)
fmt.Printf("Storage Reads: %d\n", len(trace.StorageReads))
fmt.Printf("Storage Writes: %d\n", len(trace.StorageWrites))
for _, read := range trace.StorageReads {
    fmt.Printf("  Read %s[%s]\n", read.Address, read.Key)
}
```

### Execution Tracing

```go
// Create a debug adapter
debugAdapter := contracts.NewSimpleDebugAdapter(address, "wasm1")

// Execute with tracing
result, _ := contracts.ExecuteWASM(store, address, code, callData, 1_000_000, 512)

// Get detailed trace
trace := debugAdapter.GetTrace()
fmt.Printf("Success: %v\n", trace.Success)
fmt.Printf("Duration: %d ms\n", trace.Duration)
fmt.Printf("Storage Operations: %d reads, %d writes\n", 
    len(trace.StorageReads), len(trace.StorageWrites))
```

### Contract Templates

Get started quickly with language-specific templates:

```go
// Get Rust template
helper := &contracts.ContractTemplateHelper{}
rustTemplate := helper.GetTemplate("rust")

// Get C++ template
cppTemplate := helper.GetTemplate("cpp")

// Get TinyGo template
goTemplate := helper.GetTemplate("go")

// Get supported languages
languages := helper.GetSupportedLanguages()
// []string{"rust", "cpp", "go", "assemblyscript", ...}

// Get sample ABI for SIP-20
sip20ABI := helper.GetABITemplate("sip20")
for _, method := range sip20ABI.Methods {
    fmt.Printf("Method: %s\n", method.Name)
    fmt.Printf("  Read-only: %v\n", method.ReadOnly)
}
```

---

## Security & Auditing

### Security Policies

```go
import "github.com/sphinxfndorg/protocol/src/contracts"

// Use default production policy
policy := contracts.DefaultSecurityPolicy()

// Customize
policy.MaxCodeSize = 5 * 1024 * 1024  // 5 MB
policy.MaxCallDepth = 32
policy.ReentrancyProtection = true
```

### Security Auditing

```go
// Create a security auditor
auditor := contracts.NewSecurityAuditor(policy)

// Audit a contract deployment
meta := &contracts.ContractMeta{
    Runtime:        "wasm1",
    RuntimeVersion: 1,
}

audit := auditor.AuditDeployment(address, meta, code)

if !audit.Passed {
    fmt.Printf("Audit failed with score: %d/100\n", audit.Score)
    for _, issue := range audit.Issues {
        fmt.Printf("%s [%s]: %s\n", issue.Severity, issue.Category, issue.Title)
        fmt.Printf("  %s\n", issue.Description)
        fmt.Printf("  Confidence: %d%%\n", issue.Confidence)
    }
} else {
    fmt.Printf("Audit passed with score: %d/100\n", audit.Score)
}
```

### Compliance Checking

```go
// Define upgrade policy
upgradePolicy := contracts.UpgradePolicy{
    AllowBreakingChanges:       false,
    RequireDeploymentApproval:  true,
    MaxUpgradesPerBlock:        10,
    VersionIncrement:           1,
    DeprecationPeriod:          100,
    RequireMigration:           true,
}

checker := contracts.NewComplianceChecker(upgradePolicy)

// Check if an upgrade is compliant
errs := checker.CheckUpgrade(oldMeta, newMeta, oldABI, newABI)
if len(errs) > 0 {
    for _, err := range errs {
        fmt.Printf("Compliance error: %v\n", err)
    }
}
```

### Resource Limiting

```go
// Track resource consumption during execution
limiter := contracts.NewResourceLimiter(policy, 1_000_000)  // 1M gas budget

// During execution
limiter.ChargeGas(1000)
limiter.ChargeMemory(1024)
limiter.ChargeStorage(512)
limiter.EnterCall()
// ... nested call ...
limiter.ExitCall()

// Check current usage
stats := limiter.GetStats()
fmt.Printf("Gas: %d/%d\n", stats["gas_used"], stats["gas_budget"])
fmt.Printf("Memory: %d bytes\n", stats["memory_used"])
fmt.Printf("Call depth: %d\n", stats["call_depth"])
```

---

## Contract Templates

### Rust/WASM Template

```rust
// Sphinx Contract Template - Rust/WASM
// Compile with: wasm-pack build --target wasm32-unknown-unknown

extern "C" {
    pub fn storage_get(key: u64) -> u64;
    pub fn storage_set(key: u64, value: u64);
    pub fn caller() -> u64;
    pub fn transferred_value() -> u64;
    pub fn emit_event(topic: u32, data: u32);
    pub fn transfer(recipient_ptr: i32, recipient_len: i32, amount: u64) -> i32;
}

#[no_mangle]
pub extern "C" fn sphinx_main() -> i64 {
    unsafe {
        let counter_key = 0u64;
        let current = storage_get(counter_key);
        let new_value = current.wrapping_add(1);
        storage_set(counter_key, new_value);
        emit_event(0, new_value as u32);
        new_value as i64
    }
}
```

### C++/WASM Template

```cpp
// Sphinx Contract Template - C++/WASM
extern "C" {
    extern u64 storage_get(u64 key);
    extern void storage_set(u64 key, u64 value);
    extern i64 sphinx_main() {
        const u64 COUNTER_KEY = 0;
        u64 current = storage_get(COUNTER_KEY);
        u64 new_value = current + 1;
        storage_set(COUNTER_KEY, new_value);
        return (i64)new_value;
    }
}
```

### TinyGo Template

```go
// Sphinx Contract Template - TinyGo/WASM
package main

//export storage_get
func storage_get(key uint64) uint64

//export storage_set
func storage_set(key uint64, value uint64)

//export sphinx_main
func sphinx_main() int64 {
    const counterKey = 0
    current := storage_get(counterKey)
    newValue := current + 1
    storage_set(counterKey, newValue)
    return int64(newValue)
}
```

---

## Best Practices

### 1. Always Use Type-Safe ABI

❌ **Bad:** Untyped string arguments that require manual parsing
```go
args := map[string]string{"amount": "1000"}  // Unsafe
```

✅ **Good:** Typed ABIValue with validation
```go
args := []contracts.ABIValue{
    *contracts.NewABIValueAmount(big.NewInt(1000)),
}
```

### 2. Protect Against Reentrancy

❌ **Bad:** Making external calls without state guards
```go
transfer(to, amount)  // Attacker can call back into contract
```

✅ **Good:** Use checks-effects-interactions pattern
```go
// 1. Check (reentrancy guard via CallContext)
// 2. Effect (update state first)
// 3. Interact (call external contract)
```

### 3. Validate Input Size

❌ **Bad:** Accepting unbounded input
```go
lines := input  // Could be billions of items
```

✅ **Good:** Use bounded containers
```go
items := contracts.NewBoundedArray(store, addr, "items", 10_000)
```

### 4. Use Read-Only Calls for Queries

❌ **Bad:** Calling potentially state-modifying contracts for data
```go
balance, _ := executor.Call(msg)
```

✅ **Good:** Use read-only execution for queries
```go
balance, _ := executor.CallReadOnly(msg)
```

### 5. Audit Before Deployment

```go
auditor := contracts.NewSecurityAuditor(policy)
audit := auditor.AuditDeployment(addr, meta, code)
if !audit.Passed {
    return fmt.Errorf("audit failed: %v", audit.Issues)
}
// Proceed with deployment
```

### 6. Test With Simulator

```go
sim := contracts.NewContractSimulator()
trace, err := sim.Call(contractAddr, callSpec)
if trace.GasUsed > 1_000_000 {
    fmt.Println("Warning: High gas usage")
}
```

### 7. Document Contract ABI

```go
// Provide ABI specification for tooling
sip20ABI := helper.GetABITemplate("sip20")
abiJSON, _ := json.MarshalIndent(sip20ABI, "", "  ")
fmt.Println(string(abiJSON))
```

---

## Version Information

- **Native Runtime Version:** 1
- **SVM1 Runtime Version:** 1  
- **WASM Runtime Version:** 1
- **Max Call Depth:** 64
- **Max Code Size:** 10 MB
- **Max Memory Pages:** 512 (32 MB)

---

## Migration from Previous Versions

### Legacy CallSpec → RichCallSpec

Old (untyped):
```go
call := &contracts.CallSpec{
    Method: "transfer",
    Args:   map[string]string{"to": "addr", "amount": "1000"},
}
```

New (typed):
```go
call := &contracts.RichCallSpec{
    Method: "transfer",
    Args: []contracts.ABIValue{
        *contracts.NewABIValueAddress("addr"),
        *contracts.NewABIValueAmount(big.NewInt(1000)),
    },
}
```

### Legacy Storage → Typed Storage

Old (untyped):
```go
store.SetContractStorage(addr, "balance", []byte("1000"))
```

New (typed):
```go
value := contracts.NewStorageValueAmount(big.NewInt(1000))
store.SetContractStorage(addr, "balance", value.Bytes())
```

---

## Further Reading

- [Sphinx Protocol Documentation](../README.md)
- [Contract Execution Reference](./contract_execution.md)
- [ABI Specification](./abi_spec.md)
- [Security Guidelines](./security.md)

---

**Last Updated:** 2024
**Status:** Production Ready
