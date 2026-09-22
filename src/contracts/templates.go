// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"fmt"
	"strings"
)

// This file provides contract templates for common use cases

// RustContractTemplate is a template for Rust contracts compiled to WASM
const RustContractTemplate = `
// Sphinx Contract Template - Rust/WASM
// Compile with: wasm-pack build --target wasm32-unknown-unknown

use serde::{Serialize, Deserialize};

#[link(wasm_import_module = "sphinx")]
extern "C" {
    pub fn storage_get(key: u64) -> u64;
    pub fn storage_set(key: u64, value: u64);
    pub fn caller() -> u64;
    pub fn transferred_value() -> u64;
    pub fn block_height() -> u64;
    pub fn emit_event(topic: u32, data: u32);
    pub fn transfer(recipient_ptr: i32, recipient_len: i32, amount: u64) -> i32;
    pub fn calldata_word(index: u64) -> u64;
}

#[no_mangle]
pub extern "C" fn sphinx_main() -> i64 {
    unsafe {
        // Example: Simple counter increment
        let counter_key = 0u64;
        let current = storage_get(counter_key);
        let new_value = current.wrapping_add(1);
        storage_set(counter_key, new_value);
        
        // Emit event
        emit_event(0, new_value as u32);
        
        // Return new value
        new_value as i64
    }
}

// Example state structure for managing typed storage
pub struct ContractState {
    pub owner: u64,
    pub balance: u64,
    pub total_supply: u64,
}

impl ContractState {
    pub fn owner_key() -> u64 { 0 }
    pub fn balance_key(user: u64) -> u64 { 1000 + user }
    pub fn total_supply_key() -> u64 { 2000 }
    
    pub fn set_owner(owner: u64) {
        unsafe { storage_set(Self::owner_key(), owner); }
    }
    
    pub fn get_owner() -> u64 {
        unsafe { storage_get(Self::owner_key()) }
    }
    
    pub fn set_balance(user: u64, balance: u64) {
        unsafe { storage_set(Self::balance_key(user), balance); }
    }
    
    pub fn get_balance(user: u64) -> u64 {
        unsafe { storage_get(Self::balance_key(user)) }
    }
}
`

// CppContractTemplate is a template for C++ contracts compiled to WASM
const CppContractTemplate = `
// Sphinx Contract Template - C++/WASM
// Compile with: clang++ --target=wasm32 -nostdlib -fno-builtin -O3

extern "C" {
    // Sphinx runtime imports
    extern u64 storage_get(u64 key);
    extern void storage_set(u64 key, u64 value);
    extern u64 caller();
    extern u64 transferred_value();
    extern u64 block_height();
    extern void emit_event(u32 topic, u32 data);
    extern i32 transfer(const char* recipient, u32 len, u64 amount);
    extern u64 calldata_word(u64 index);
    
    // Entry point
    extern "C" __attribute__((export_name("sphinx_main")))
    i64 sphinx_main() {
        // Example: Simple counter
        const u64 COUNTER_KEY = 0;
        u64 current = storage_get(COUNTER_KEY);
        u64 new_value = current + 1;
        storage_set(COUNTER_KEY, new_value);
        
        emit_event(0, (u32)new_value);
        
        return (i64)new_value;
    }
}

// Storage management utilities
class StorageManager {
public:
    static const u64 OWNER_KEY = 0;
    static const u64 BALANCE_BASE = 1000;
    static const u64 TOTAL_SUPPLY_KEY = 2000;
    
    static u64 get_owner() {
        return storage_get(OWNER_KEY);
    }
    
    static void set_owner(u64 owner) {
        storage_set(OWNER_KEY, owner);
    }
    
    static u64 get_balance(u64 user) {
        return storage_get(BALANCE_BASE + user);
    }
    
    static void set_balance(u64 user, u64 balance) {
        storage_set(BALANCE_BASE + user, balance);
    }
};
`

// GoContractTemplate is a template for TinyGo contracts compiled to WASM
const GoContractTemplate = `
// Sphinx Contract Template - TinyGo/WASM
// Compile with: tinygo build -o contract.wasm -target wasm contract.go

package main

//export storage_get
func storage_get(key uint64) uint64

//export storage_set
func storage_set(key uint64, value uint64)

//export caller
func caller() uint64

//export transferred_value
func transferred_value() uint64

//export block_height
func block_height() uint64

//export emit_event
func emit_event(topic uint32, data uint32)

//export transfer
func transfer(recipientPtr int32, recipientLen int32, amount uint64) int32

//export calldata_word
func calldata_word(index uint64) uint64

// Entry point - must be exported as "sphinx_main"
//export sphinx_main
func sphinx_main() int64 {
	// Example: Simple counter
	const counterKey = 0
	current := storage_get(counterKey)
	newValue := current + 1
	storage_set(counterKey, newValue)
	
	emit_event(0, uint32(newValue))
	
	return int64(newValue)
}

// Storage constants
const (
	OwnerKey       = 0
	BalanceBase    = 1000
	TotalSupplyKey = 2000
)

// Storage helper functions
func GetOwner() uint64 {
	return storage_get(OwnerKey)
}

func SetOwner(owner uint64) {
	storage_set(OwnerKey, owner)
}

func GetBalance(user uint64) uint64 {
	return storage_get(BalanceBase + user)
}

func SetBalance(user uint64, balance uint64) {
	storage_set(BalanceBase+user, balance)
}
`

// AssemblyScriptContractTemplate is a template for AssemblyScript contracts
const AssemblyScriptContractTemplate = `
// Sphinx Contract Template - AssemblyScript/WASM
// Compile with: asc contract.ts --target release --exportRuntime

declare function storage_get(key: u64): u64;
declare function storage_set(key: u64, value: u64): void;
declare function caller(): u64;
declare function transferred_value(): u64;
declare function block_height(): u64;
declare function emit_event(topic: u32, data: u32): void;
declare function transfer(recipientPtr: i32, recipientLen: i32, amount: u64): i32;
declare function calldata_word(index: u64): u64;

// Entry point
export function sphinx_main(): i64 {
    // Example: Simple counter
    const counterKey: u64 = 0;
    const current = storage_get(counterKey);
    const newValue = current + 1;
    storage_set(counterKey, newValue);
    
    emit_event(0, <u32>newValue);
    
    return <i64>newValue;
}

// Storage utilities
namespace Storage {
    export const OWNER_KEY: u64 = 0;
    export const BALANCE_BASE: u64 = 1000;
    export const TOTAL_SUPPLY_KEY: u64 = 2000;
    
    export function getOwner(): u64 {
        return storage_get(OWNER_KEY);
    }
    
    export function setOwner(owner: u64): void {
        storage_set(OWNER_KEY, owner);
    }
    
    export function getBalance(user: u64): u64 {
        return storage_get(BALANCE_BASE + user);
    }
    
    export function setBalance(user: u64, balance: u64): void {
        storage_set(BALANCE_BASE + user, balance);
    }
}
`

// SolidityLikeContractTemplate provides a high-level template documentation
// Note: Solidity is not directly supported; instead developers use Rust/TinyGo/C++
const SolidityLikeContractTemplate = `
// Sphinx Contract Pattern - High-Level Contract Structure
// (Implement in Rust, C++, TinyGo, or AssemblyScript)

// For developers familiar with Solidity, here's a mapping:
// 
// Solidity: contract MyToken { ... }
// Sphinx:   Implement in Rust/Go/C++ and compile to WASM
//
// Solidity: mapping(address => uint256) balances;
// Sphinx:   Use TypedStorage + BoundedMap
//   store := contracts.NewBoundedMap(stateDB, contractAddr, "balances", 1_000_000)
//   store.Set(userAddr, amount.String())
//
// Solidity: function transfer(to, amount) public { ... }
// Sphinx:   Implement as exported WASM function or via native contract
//
// Solidity: event Transfer(indexed from, indexed to, amount);
// Sphinx:   Use sphinx_emit_event(topic, data) in WASM
//
// Solidity: require(msg.sender == owner);
// Sphinx:   caller := calldata_word(0); // or extract from calldata
//
// Example SIP-20 Token Contract Pattern:
//
// Contract Layout:
//   - Owner: storage key 0
//   - Balances: storage keys 1000+
//   - Allowances: storage keys 2000+
//   - Total Supply: storage key 3000
//
// Methods:
//   - balanceOf(address): read-only, returns balance
//   - transfer(to, amount): transfer tokens, emit Transfer event
//   - approve(spender, amount): approve spender to use tokens
//   - transferFrom(from, to, amount): transfer on behalf
//   - mint(amount): owner only, increase total supply
//   - burn(amount): decrease user balance and supply
`

// NativeContractTemplate provides guidance for native (non-WASM) contracts
const NativeContractTemplate = `
// Native Sphinx Contract - SIP-20 Token Pattern
//
// Native contracts are implemented directly in Go within the runtime,
// not compiled to WASM. They are suitable for:
//   - Standard token implementations (SIP-20, SIP-721)
//   - System contracts
//   - Complex logic requiring direct access to state
//
// To create a native contract:
//
// 1. Implement the contract in Go with contract execution hooks
// 2. Register it in the runtime dispatcher
// 3. Deploy via native DeploySpec with runtime="native"
//
// Example SIP-20 Native Implementation:
//
// type SIP20Contract struct {
//     Name         string
//     Symbol       string
//     Decimals     uint8
//     Owner        string
//     TotalSupply  *big.Int
//     Balances     map[string]*big.Int
//     Allowances   map[string]map[string]*big.Int
// }
//
// func (c *SIP20Contract) Transfer(to string, amount *big.Int) error {
//     caller := executionContext.Caller
//     if c.Balances[caller].Cmp(amount) < 0 {
//         return errors.New("insufficient balance")
//     }
//     c.Balances[caller].Sub(c.Balances[caller], amount)
//     c.Balances[to].Add(c.Balances[to], amount)
//     return nil
// }
`

// ContractTemplateManifest describes a generated SDK scaffold for a contract.
type ContractTemplateManifest struct {
	Language     string
	ContractName string
	Standard     string
	BuildCommand string
	Template     string
	ABI          *ContractABI
}

// ContractTemplateHelper provides methods to get templates
type ContractTemplateHelper struct{}

// GenerateScaffold creates a language-specific SDK scaffold for a contract standard.
func (h *ContractTemplateHelper) GenerateScaffold(language, standard, contractName string) (*ContractTemplateManifest, error) {
	lang := strings.ToLower(strings.TrimSpace(language))
	if lang == "" {
		lang = "rust"
	}
	std := strings.ToLower(strings.TrimSpace(standard))
	if std == "" {
		std = StandardSIP20
	}
	if std == "stablecoin" {
		std = StandardSIP20
	}
	name := strings.TrimSpace(contractName)
	if name == "" {
		name = "sphinx_contract"
	}
	buildCmd, ok := map[string]string{
		"rust":           "wasm-pack build --target wasm32-unknown-unknown",
		"cpp":            "clang++ --target=wasm32-unknown-unknown -O2 -nostdlib -Wl,--export=sphinx_main -o contract.wasm contract.cpp",
		"go":             "tinygo build -o contract.wasm -target wasm contract.go",
		"assemblyscript": "asc contract.ts --target release --exportRuntime",
		"native":         "go build ./cmd/<contract>",
	}[lang]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %s", language)
	}
	abi := h.GetABITemplate(std)
	if abi == nil {
		return nil, fmt.Errorf("unsupported standard: %s", standard)
	}
	template := h.GetTemplate(lang)
	if template == "" {
		return nil, fmt.Errorf("no template found for language: %s", language)
	}
	return &ContractTemplateManifest{
		Language:     lang,
		ContractName: name,
		Standard:     std,
		BuildCommand: buildCmd,
		Template:     template,
		ABI:          abi,
	}, nil
}

// GetTemplate returns a contract template for the specified language
func (h *ContractTemplateHelper) GetTemplate(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "rust":
		return RustContractTemplate
	case "cpp", "c++", "c":
		return CppContractTemplate
	case "go", "tinygo":
		return GoContractTemplate
	case "assemblyscript", "ts", "typescript":
		return AssemblyScriptContractTemplate
	case "solidity-pattern", "solidity":
		return SolidityLikeContractTemplate
	case "native":
		return NativeContractTemplate
	default:
		return ""
	}
}

// GetSupportedLanguages returns a list of supported languages
func (h *ContractTemplateHelper) GetSupportedLanguages() []string {
	return []string{
		"rust",
		"cpp",
		"go",
		"assemblyscript",
		"solidity-pattern",
		"native",
	}
}

// GetSupportedStandards returns the supported token standards for SDK scaffolding.
func (h *ContractTemplateHelper) GetSupportedStandards() []string {
	return []string{StandardSIP20, StandardSIP721, "stablecoin"}
}

// GetABITemplate returns a sample ABI for a SIP-20 token
func (h *ContractTemplateHelper) GetABITemplate(standard string) *ContractABI {
	switch standard {
	case StandardSIP20:
		return &ContractABI{
			Version: 1,
			Methods: []ABIMethod{
				{
					Name:        "balanceOf",
					Description: "Get token balance of an address",
					ReadOnly:    true,
					Parameters: []ABIParameter{
						{Name: "account", Type: ABITypeAddress},
					},
					Returns: []ABIParameter{
						{Name: "balance", Type: ABITypeAmount},
					},
				},
				{
					Name:        "transfer",
					Description: "Transfer tokens to an address",
					ReadOnly:    false,
					Parameters: []ABIParameter{
						{Name: "to", Type: ABITypeAddress},
						{Name: "amount", Type: ABITypeAmount},
					},
					Returns: []ABIParameter{
						{Name: "success", Type: ABITypeBool},
					},
				},
				{
					Name:        "approve",
					Description: "Approve spending limit",
					ReadOnly:    false,
					Parameters: []ABIParameter{
						{Name: "spender", Type: ABITypeAddress},
						{Name: "amount", Type: ABITypeAmount},
					},
					Returns: []ABIParameter{
						{Name: "success", Type: ABITypeBool},
					},
				},
				{
					Name:        "transferFrom",
					Description: "Transfer tokens on behalf",
					ReadOnly:    false,
					Parameters: []ABIParameter{
						{Name: "from", Type: ABITypeAddress},
						{Name: "to", Type: ABITypeAddress},
						{Name: "amount", Type: ABITypeAmount},
					},
					Returns: []ABIParameter{
						{Name: "success", Type: ABITypeBool},
					},
				},
			},
			Events: []string{
				"Transfer",
				"Approval",
			},
		}

	case StandardSIP721:
		return &ContractABI{
			Version: 1,
			Methods: []ABIMethod{
				{
					Name:        "ownerOf",
					Description: "Get owner of an NFT",
					ReadOnly:    true,
					Parameters: []ABIParameter{
						{Name: "tokenId", Type: ABITypeUint64},
					},
					Returns: []ABIParameter{
						{Name: "owner", Type: ABITypeAddress},
					},
				},
				{
					Name:        "mint",
					Description: "Mint a new NFT",
					ReadOnly:    false,
					Parameters: []ABIParameter{
						{Name: "to", Type: ABITypeAddress},
						{Name: "tokenId", Type: ABITypeUint64},
						{Name: "uri", Type: ABITypeString},
					},
					Returns: []ABIParameter{
						{Name: "success", Type: ABITypeBool},
					},
				},
				{
					Name:        "burn",
					Description: "Burn an NFT",
					ReadOnly:    false,
					Parameters: []ABIParameter{
						{Name: "tokenId", Type: ABITypeUint64},
					},
					Returns: []ABIParameter{
						{Name: "success", Type: ABITypeBool},
					},
				},
			},
			Events: []string{
				"Transfer",
				"Approval",
			},
		}
	}

	return nil
}
