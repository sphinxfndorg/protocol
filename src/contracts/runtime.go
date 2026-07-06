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
	"time"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

const (
	RuntimeNative = "native"
	StandardSIP20 = "sip20"
)

func BuildDeployCode(spec *DeploySpec) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nil deploy spec")
	}
	normalizeDeploySpec(spec)
	if err := validateDeploySpec(spec); err != nil {
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
	if err := validateDeploySpec(&spec); err != nil {
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
		Address:   address,
		Creator:   tx.Sender,
		Runtime:   spec.Runtime,
		Standard:  spec.Standard,
		CreatedAt: time.Now().Unix(),
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
	default:
		return nil, fmt.Errorf("unsupported contract standard: %s", meta.Standard)
	}
}

func ContractAddress(sender string, nonce uint64, code []byte) string {
	input := fmt.Sprintf("%s:%d:%x", sender, nonce, sha256.Sum256(code))
	sum := sha256.Sum256([]byte(input))
	return "sc" + hex.EncodeToString(sum[:20])
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

func validateDeploySpec(spec *DeploySpec) error {
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
