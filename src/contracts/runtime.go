// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

const (
	RuntimeNative               = "native"
	StandardSIP20               = "sip20"
	StandardSIP721              = "sip721"
	NativeRuntimeVersion uint32 = 1
	SVM1RuntimeVersion   uint32 = 1
	WASMRuntimeVersion   uint32 = 1
	// Runtime*Version aliases keep the naming parallel with RuntimeNative,
	// RuntimeSVM1, and RuntimeWASM for callers defining ABI tables.
	RuntimeNativeVersion = NativeRuntimeVersion
	RuntimeSVM1Version   = SVM1RuntimeVersion
	RuntimeWASMVersion   = WASMRuntimeVersion
)

// RuntimeVersion returns the ABI version supported for a runtime.
func RuntimeVersion(runtime string) (uint32, bool) {
	switch strings.ToLower(strings.TrimSpace(runtime)) {
	case RuntimeNative:
		return NativeRuntimeVersion, true
	case RuntimeSVM1:
		return SVM1RuntimeVersion, true
	case RuntimeWASM:
		return WASMRuntimeVersion, true
	default:
		return 0, false
	}
}

// ValidateContractMeta validates the versioned runtime identity stored with a
// contract. Missing versions are legacy v1 metadata and remain valid.
func ValidateContractMeta(meta *ContractMeta) error {
	if meta == nil {
		return errors.New("nil contract metadata")
	}
	runtime := strings.ToLower(strings.TrimSpace(meta.Runtime))
	expected, ok := RuntimeVersion(runtime)
	if !ok {
		return fmt.Errorf("unsupported runtime: %s", meta.Runtime)
	}
	if meta.RuntimeVersion != 0 && meta.RuntimeVersion != expected {
		return fmt.Errorf("unsupported %s runtime version: %d", runtime, meta.RuntimeVersion)
	}
	if meta.RuntimeVersion == 0 {
		meta.RuntimeVersion = expected
	}
	return nil
}

func BuildDeployCode(spec *DeploySpec) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nil deploy spec")
	}
	normalizeDeploySpec(spec)
	if err := ValidateDeploySpec(spec); err != nil {
		return nil, err
	}
	return json.Marshal(spec)
}

func BuildCallData(spec *CallSpec) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nil call spec")
	}
	spec.Method = strings.ToLower(strings.TrimSpace(spec.Method))
	if spec.Method == "" {
		return nil, errors.New("missing method")
	}
	if spec.Args == nil {
		spec.Args = map[string]string{}
	}
	return json.Marshal(spec)
}

func Deploy(store Store, tx *types.Transaction) (*ExecutionResult, error) {
	if store == nil {
		return nil, errors.New("nil contract store")
	}
	if tx == nil {
		return nil, errors.New("nil transaction")
	}
	var spec DeploySpec
	if err := json.Unmarshal(tx.Code, &spec); err != nil {
		return nil, fmt.Errorf("decode deploy code: %w", err)
	}
	normalizeDeploySpec(&spec)
	if err := ValidateDeploySpec(&spec); err != nil {
		return nil, err
	}

	address := ContractAddress(tx.Sender, tx.Nonce, tx.Code)
	if store.ContractExists(address) {
		return nil, fmt.Errorf("contract already exists: %s", address)
	}

	code, err := BuildDeployCode(&spec)
	if err != nil {
		return nil, err
	}
	store.SetContractCode(address, code)
	metaJSON, err := json.Marshal(&ContractMeta{
		Address:        address,
		Creator:        tx.Sender,
		Runtime:        spec.Runtime,
		RuntimeVersion: NativeRuntimeVersion,
		Standard:       spec.Standard,
		// Transaction time is consensus data. Never use local wall time in
		// execution because it would make nodes derive different state roots.
		CreatedAt: tx.Timestamp,
	})
	if err != nil {
		return nil, err
	}
	store.SetContractMeta(address, metaJSON)

	switch spec.Standard {
	case StandardSIP20:
		if err := initSIP20(store, address, tx.Sender, &spec); err != nil {
			return nil, err
		}
	case StandardSIP721:
		if err := initSIP721(store, address, tx.Sender, &spec); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported contract standard: %s", spec.Standard)
	}

	return &ExecutionResult{
		ContractAddress: address,
		Status:          "deployed",
		Return: map[string]string{
			"standard": spec.Standard,
			"runtime":  spec.Runtime,
		},
	}, nil
}

func Call(store Store, tx *types.Transaction) (*ExecutionResult, error) {
	return CallWithContext(store, tx, nil)
}

// CallWithContext executes a native contract call with the kernel's value
// context (tx.Amount, policy floor, balance-transfer hook) for standards that
// settle value — currently SIP-721 resale royalties and license fees. A nil
// context preserves legacy behavior: the standard sees no value and never
// moves balances.
func CallWithContext(store Store, tx *types.Transaction, ctx *NativeCallContext) (*ExecutionResult, error) {
	if store == nil {
		return nil, errors.New("nil contract store")
	}
	if tx == nil {
		return nil, errors.New("nil transaction")
	}
	address := strings.TrimSpace(firstNonEmpty(tx.ToContract, tx.Receiver))
	if address == "" {
		return nil, errors.New("missing contract address")
	}
	metaJSON, err := store.GetContractMeta(address)
	if err != nil {
		return nil, fmt.Errorf("load contract meta: %w", err)
	}
	var meta ContractMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("decode contract meta: %w", err)
	}
	if err := ValidateContractMeta(&meta); err != nil {
		return nil, fmt.Errorf("validate contract meta: %w", err)
	}
	var call CallSpec
	if err := json.Unmarshal(tx.CallData, &call); err != nil {
		return nil, fmt.Errorf("decode call data: %w", err)
	}
	call.Method = strings.ToLower(strings.TrimSpace(call.Method))
	if call.Args == nil {
		call.Args = map[string]string{}
	}

	switch meta.Standard {
	case StandardSIP20:
		return callSIP20(store, address, tx.Sender, &call)
	case StandardSIP721:
		return callSIP721WithContext(store, address, tx.Sender, &call, ctx)
	default:
		return nil, fmt.Errorf("unsupported contract standard: %s", meta.Standard)
	}
}

func ContractAddress(sender string, nonce uint64, code []byte) string {
	input := fmt.Sprintf("%s:%d:%x", sender, nonce, sha256.Sum256(code))
	// Same hash family, width, and wire format as every identity address on
	// the protocol: SpxHash (SphinxHash/SHAKE-256 with the protocol salt) →
	// 32 bytes → 64 hex characters, rendered as the canonical grouped SPIF
	// display form ("SPIF XXXX XXXX …", 16 groups of 4, uppercase). The
	// previous form — "SPIF" + 40 lowercase hex (a 20-byte sha256 tail) —
	// was neither grouped, nor uppercase, nor 64-hex, so generated contract
	// addresses visibly disagreed with every other SPIF address in the UI
	// (state_db.go's account classifier treats 64-hex as the SPIF form and
	// 40-hex as legacy).
	sum := common.SpxHash([]byte(input))
	if len(sum) != 32 {
		// SpxHash can only fail if the Sphinx hasher cannot initialize; fall
		// back to the full sha256 digest so a contract address is still
		// produced rather than panicking inside a consensus execution path.
		full := sha256.Sum256([]byte(input))
		sum = full[:]
	}
	addr, err := common.FormatSPIFAddress(hex.EncodeToString(sum))
	if err != nil {
		// Unreachable for 64-hex input; keep a valid address rather than
		// panicking in a consensus path.
		return common.SPIFPrefix + " " + strings.ToUpper(hex.EncodeToString(sum))
	}
	return addr
}

func normalizeDeploySpec(spec *DeploySpec) {
	spec.Runtime = strings.ToLower(strings.TrimSpace(spec.Runtime))
	spec.Standard = strings.ToLower(strings.TrimSpace(spec.Standard))
	spec.Name = strings.TrimSpace(spec.Name)
	spec.Symbol = strings.ToUpper(strings.TrimSpace(spec.Symbol))
	spec.Owner = strings.TrimSpace(spec.Owner)
	spec.InitialSupply = strings.TrimSpace(spec.InitialSupply)
	if spec.Runtime == "" {
		spec.Runtime = RuntimeNative
	}
}

// ValidateDeploySpec checks that a DeploySpec is structurally valid.
// Exported for use by mempool validation (defense-in-depth) and external callers.
func ValidateDeploySpec(spec *DeploySpec) error {
	if spec.Runtime != RuntimeNative {
		return fmt.Errorf("unsupported runtime: %s", spec.Runtime)
	}
	if spec.Standard == "" {
		return errors.New("missing contract standard")
	}
	if spec.Standard == StandardSIP20 {
		if spec.Name == "" {
			return errors.New("missing token name")
		}
		if spec.Symbol == "" {
			return errors.New("missing token symbol")
		}
		if spec.InitialSupply != "" {
			if _, ok := new(big.Int).SetString(spec.InitialSupply, 10); !ok {
				return errors.New("invalid initial_supply")
			}
		}
		return nil
	}
	if spec.Standard == StandardSIP721 {
		if spec.Name == "" {
			return errors.New("missing collection name")
		}
		if spec.Symbol == "" {
			return errors.New("missing collection symbol")
		}
		return nil
	}
	return fmt.Errorf("unsupported contract standard: %s", spec.Standard)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
