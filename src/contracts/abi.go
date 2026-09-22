// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ABIType represents the type of a contract argument or return value
type ABIType string

const (
	ABITypeUint64   ABIType = "uint64"
	ABITypeInt64    ABIType = "int64"
	ABITypeBool     ABIType = "bool"
	ABITypeBytes    ABIType = "bytes"
	ABITypeAddress  ABIType = "address"
	ABITypeString   ABIType = "string"
	ABITypeAmount   ABIType = "amount" // big.Int represented as decimal string
	ABITypeArray    ABIType = "array"
	ABITypeStruct   ABIType = "struct"
	ABITypeOptional ABIType = "optional"
)

// ABIValue is a type-safe container for contract arguments and return values
type ABIValue struct {
	Type  ABIType              `json:"type"`
	Value interface{}          `json:"value"`
	Items []ABIValue           `json:"items,omitempty"` // for array and optional types
	Field map[string]*ABIValue `json:"field,omitempty"` // for struct types
}

// ABIParameter describes a method parameter
type ABIParameter struct {
	Name     string  `json:"name"`
	Type     ABIType `json:"type"`
	Optional bool    `json:"optional,omitempty"`
}

// ABIMethod describes a contract method
type ABIMethod struct {
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	ReadOnly        bool           `json:"readonly,omitempty"`
	Parameters      []ABIParameter `json:"parameters,omitempty"`
	Returns         []ABIParameter `json:"returns,omitempty"`
	PaymentRequired bool           `json:"payment_required,omitempty"`
}

// ContractABI defines the interface and version of a contract
type ContractABI struct {
	Version   uint32         `json:"version"` // version of this ABI
	Methods   []ABIMethod    `json:"methods"`
	Events    []string       `json:"events,omitempty"`
	StateVars []ABIParameter `json:"state_vars,omitempty"`
}

// RichCallSpec replaces the simple CallSpec with structured typed arguments
type RichCallSpec struct {
	Method   string     `json:"method"`
	Args     []ABIValue `json:"args,omitempty"`
	Value    *big.Int   `json:"value,omitempty"`
	ReadOnly bool       `json:"readonly,omitempty"`
}

// NewABIValue creates an ABIValue for a uint64
func NewABIValueUint64(val uint64) *ABIValue {
	return &ABIValue{
		Type:  ABITypeUint64,
		Value: val,
	}
}

// NewABIValueInt64 creates an ABIValue for an int64
func NewABIValueInt64(val int64) *ABIValue {
	return &ABIValue{
		Type:  ABITypeInt64,
		Value: val,
	}
}

// NewABIValueBool creates an ABIValue for a bool
func NewABIValueBool(val bool) *ABIValue {
	return &ABIValue{
		Type:  ABITypeBool,
		Value: val,
	}
}

// NewABIValueBytes creates an ABIValue for bytes
func NewABIValueBytes(val []byte) *ABIValue {
	return &ABIValue{
		Type:  ABITypeBytes,
		Value: fmt.Sprintf("0x%x", val),
	}
}

// NewABIValueAddress creates an ABIValue for an address
func NewABIValueAddress(addr string) *ABIValue {
	return &ABIValue{
		Type:  ABITypeAddress,
		Value: addr,
	}
}

// NewABIValueString creates an ABIValue for a string
func NewABIValueString(val string) *ABIValue {
	return &ABIValue{
		Type:  ABITypeString,
		Value: val,
	}
}

// NewABIValueAmount creates an ABIValue for a big.Int amount
func NewABIValueAmount(val *big.Int) *ABIValue {
	return &ABIValue{
		Type:  ABITypeAmount,
		Value: val.String(),
	}
}

// NewABIValueArray creates an ABIValue for an array of values
func NewABIValueArray(items []ABIValue) *ABIValue {
	itemsCopy := make([]ABIValue, len(items))
	copy(itemsCopy, items)
	return &ABIValue{
		Type:  ABITypeArray,
		Items: itemsCopy,
	}
}

// NewABIValueStruct creates an ABIValue for a struct
func NewABIValueStruct(fields map[string]*ABIValue) *ABIValue {
	return &ABIValue{
		Type:  ABITypeStruct,
		Field: fields,
	}
}

// NewABIValueOptional creates an ABIValue for an optional value
func NewABIValueOptional(val *ABIValue) *ABIValue {
	if val == nil {
		return &ABIValue{
			Type:  ABITypeOptional,
			Items: []ABIValue{},
		}
	}
	return &ABIValue{
		Type:  ABITypeOptional,
		Items: []ABIValue{*val},
	}
}

// AsUint64 extracts the value as uint64
func (v *ABIValue) AsUint64() (uint64, error) {
	if v.Type != ABITypeUint64 {
		return 0, fmt.Errorf("expected uint64, got %s", v.Type)
	}
	u, ok := v.Value.(uint64)
	if !ok {
		return 0, errors.New("value is not uint64")
	}
	return u, nil
}

// AsInt64 extracts the value as int64
func (v *ABIValue) AsInt64() (int64, error) {
	if v.Type != ABITypeInt64 {
		return 0, fmt.Errorf("expected int64, got %s", v.Type)
	}
	i, ok := v.Value.(int64)
	if !ok {
		return 0, errors.New("value is not int64")
	}
	return i, nil
}

// AsBool extracts the value as bool
func (v *ABIValue) AsBool() (bool, error) {
	if v.Type != ABITypeBool {
		return false, fmt.Errorf("expected bool, got %s", v.Type)
	}
	b, ok := v.Value.(bool)
	if !ok {
		return false, errors.New("value is not bool")
	}
	return b, nil
}

// AsBytes extracts the value as bytes
func (v *ABIValue) AsBytes() ([]byte, error) {
	if v.Type != ABITypeBytes {
		return nil, fmt.Errorf("expected bytes, got %s", v.Type)
	}
	s, ok := v.Value.(string)
	if !ok {
		return nil, errors.New("value is not string")
	}
	if len(s) < 2 || s[0:2] != "0x" {
		return nil, errors.New("bytes must be hex-encoded with 0x prefix")
	}
	// Parse hex string
	var result []byte
	hexStr := s[2:]
	if len(hexStr)%2 != 0 {
		return nil, errors.New("hex string must have even length")
	}
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		result = append(result, b)
	}
	return result, nil
}

// AsAddress extracts the value as an address string
func (v *ABIValue) AsAddress() (string, error) {
	if v.Type != ABITypeAddress {
		return "", fmt.Errorf("expected address, got %s", v.Type)
	}
	s, ok := v.Value.(string)
	if !ok {
		return "", errors.New("value is not string")
	}
	return s, nil
}

// AsString extracts the value as a string
func (v *ABIValue) AsString() (string, error) {
	if v.Type != ABITypeString {
		return "", fmt.Errorf("expected string, got %s", v.Type)
	}
	s, ok := v.Value.(string)
	if !ok {
		return "", errors.New("value is not string")
	}
	return s, nil
}

// AsAmount extracts the value as a big.Int
func (v *ABIValue) AsAmount() (*big.Int, error) {
	if v.Type != ABITypeAmount {
		return nil, fmt.Errorf("expected amount, got %s", v.Type)
	}
	s, ok := v.Value.(string)
	if !ok {
		return nil, errors.New("value is not string")
	}
	val := new(big.Int)
	if _, ok := val.SetString(s, 10); !ok {
		return nil, fmt.Errorf("invalid big.Int: %s", s)
	}
	return val, nil
}

// AsArray extracts the value as an array of ABIValues
func (v *ABIValue) AsArray() ([]ABIValue, error) {
	if v.Type != ABITypeArray {
		return nil, fmt.Errorf("expected array, got %s", v.Type)
	}
	return append([]ABIValue{}, v.Items...), nil
}

// AsStruct extracts the value as a struct (map of field names to values)
func (v *ABIValue) AsStruct() (map[string]*ABIValue, error) {
	if v.Type != ABITypeStruct {
		return nil, fmt.Errorf("expected struct, got %s", v.Type)
	}
	result := make(map[string]*ABIValue, len(v.Field))
	for k, val := range v.Field {
		result[k] = val
	}
	return result, nil
}

// AsOptional extracts the optional value (nil if not present)
func (v *ABIValue) AsOptional() (*ABIValue, error) {
	if v.Type != ABITypeOptional {
		return nil, fmt.Errorf("expected optional, got %s", v.Type)
	}
	if len(v.Items) == 0 {
		return nil, nil
	}
	return &v.Items[0], nil
}

// ValidateABIValue checks that a value conforms to its type
func ValidateABIValue(v *ABIValue) error {
	if v == nil {
		return errors.New("nil ABI value")
	}
	switch v.Type {
	case ABITypeUint64, ABITypeInt64:
		if _, ok := v.Value.(float64); !ok && !isInt(v.Value) {
			return fmt.Errorf("invalid %s: %T", v.Type, v.Value)
		}
	case ABITypeBool:
		if _, ok := v.Value.(bool); !ok {
			return fmt.Errorf("invalid bool: %T", v.Value)
		}
	case ABITypeBytes, ABITypeAddress, ABITypeString, ABITypeAmount:
		if _, ok := v.Value.(string); !ok {
			return fmt.Errorf("invalid %s: %T", v.Type, v.Value)
		}
	case ABITypeArray:
		for i, item := range v.Items {
			if err := ValidateABIValue(&item); err != nil {
				return fmt.Errorf("array[%d]: %w", i, err)
			}
		}
	case ABITypeStruct:
		for name, field := range v.Field {
			if err := ValidateABIValue(field); err != nil {
				return fmt.Errorf("struct.%s: %w", name, err)
			}
		}
	case ABITypeOptional:
		if len(v.Items) > 1 {
			return errors.New("optional can have at most one item")
		}
		if len(v.Items) == 1 {
			if err := ValidateABIValue(&v.Items[0]); err != nil {
				return fmt.Errorf("optional: %w", err)
			}
		}
	default:
		return fmt.Errorf("unknown ABI type: %s", v.Type)
	}
	return nil
}

func isInt(v interface{}) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	}
	return false
}

// BuildRichCallData encodes a RichCallSpec to JSON bytes
func BuildRichCallData(spec *RichCallSpec) ([]byte, error) {
	if spec == nil {
		return nil, errors.New("nil rich call spec")
	}
	spec.Method = strings.ToLower(strings.TrimSpace(spec.Method))
	if spec.Method == "" {
		return nil, errors.New("missing method")
	}
	for i, arg := range spec.Args {
		if err := ValidateABIValue(&arg); err != nil {
			return nil, fmt.Errorf("arg[%d]: %w", i, err)
		}
	}
	return json.Marshal(spec)
}

// ToCallSpec converts a typed RichCallSpec into the legacy CallSpec shape used
// by the native runtime. The output uses method parameter names whenever the ABI
// metadata is known, which keeps contract calls stable across SDKs.
func (spec *RichCallSpec) ToCallSpec(abi *ContractABI) (*CallSpec, error) {
	if spec == nil {
		return nil, errors.New("nil rich call spec")
	}
	methodName := strings.ToLower(strings.TrimSpace(spec.Method))
	if methodName == "" {
		return nil, errors.New("missing method")
	}
	call := &CallSpec{Method: methodName, Args: map[string]string{}}
	if len(spec.Args) == 0 {
		return call, nil
	}
	methodParams := []ABIParameter{}
	if abi != nil {
		for _, method := range abi.Methods {
			if strings.EqualFold(method.Name, spec.Method) {
				methodParams = method.Parameters
				break
			}
		}
	}
	for i, arg := range spec.Args {
		if err := ValidateABIValue(&arg); err != nil {
			return nil, fmt.Errorf("arg[%d]: %w", i, err)
		}
		name := fmt.Sprintf("arg%d", i)
		if i < len(methodParams) {
			name = methodParams[i].Name
		}
		value, err := abiValueToCallArg(arg)
		if err != nil {
			return nil, fmt.Errorf("arg[%d]: %w", i, err)
		}
		call.Args[name] = value
	}
	return call, nil
}

func abiValueToCallArg(v ABIValue) (string, error) {
	switch v.Type {
	case ABITypeUint64:
		u, err := v.AsUint64(); if err != nil { return "", err }
		return strconv.FormatUint(u, 10), nil
	case ABITypeInt64:
		i, err := v.AsInt64(); if err != nil { return "", err }
		return strconv.FormatInt(i, 10), nil
	case ABITypeBool:
		b, err := v.AsBool(); if err != nil { return "", err }
		return strconv.FormatBool(b), nil
	case ABITypeBytes:
		b, err := v.AsBytes(); if err != nil { return "", err }
		return hex.EncodeToString(b), nil
	case ABITypeAddress:
		// AsString rejects anything whose Type is not exactly "string", so
		// routing addresses through it made every address-typed argument
		// ("expected string, got address") unconvertible — breaking Simulate/
		// ToCallSpec for any method with an address parameter (balance_of,
		// transfer, mint, …). AsAddress validates the type it is given and
		// still guarantees the underlying value is a string.
		return v.AsAddress()
	case ABITypeString, ABITypeAmount:
		s, err := v.AsString(); if err != nil {
			if v.Type == ABITypeAmount {
				amt, err2 := v.AsAmount(); if err2 != nil { return "", err2 }
				return amt.String(), nil
			}
			return "", err
		}
		return s, nil
	case ABITypeArray:
		items, err := v.AsArray(); if err != nil { return "", err }
		payload, err := json.Marshal(items); if err != nil { return "", err }
		return string(payload), nil
	case ABITypeStruct:
		fields, err := v.AsStruct(); if err != nil { return "", err }
		payload, err := json.Marshal(fields); if err != nil { return "", err }
		return string(payload), nil
	case ABITypeOptional:
		opt, err := v.AsOptional(); if err != nil { return "", err }
		if opt == nil { return "", nil }
		return abiValueToCallArg(*opt)
	default:
		return "", fmt.Errorf("unsupported ABI type: %s", v.Type)
	}
}

// ValidateContractABI verifies that a contract interface is structurally valid.
func ValidateContractABI(abi *ContractABI) error {
	if abi == nil {
		return errors.New("nil ABI")
	}
	if abi.Version == 0 {
		return errors.New("missing ABI version")
	}
	seen := make(map[string]struct{}, len(abi.Methods))
	for i, method := range abi.Methods {
		name := strings.TrimSpace(method.Name)
		if name == "" {
			return fmt.Errorf("method[%d]: missing name", i)
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate method: %s", name)
		}
		seen[key] = struct{}{}
		for j, param := range method.Parameters {
			if err := validateABIParameter(param); err != nil {
				return fmt.Errorf("method %s parameter[%d]: %w", name, j, err)
			}
		}
		for j, ret := range method.Returns {
			if err := validateABIParameter(ret); err != nil {
				return fmt.Errorf("method %s return[%d]: %w", name, j, err)
			}
		}
	}
	for i, state := range abi.StateVars {
		if err := validateABIParameter(state); err != nil {
			return fmt.Errorf("state[%d]: %w", i, err)
		}
	}
	return nil
}

func validateABIParameter(param ABIParameter) error {
	param.Name = strings.TrimSpace(param.Name)
	if param.Name == "" {
		return errors.New("missing name")
	}
	if !isSupportedABIType(param.Type) {
		return fmt.Errorf("unsupported type: %s", param.Type)
	}
	return nil
}

func isSupportedABIType(t ABIType) bool {
	switch t {
	case ABITypeUint64, ABITypeInt64, ABITypeBool, ABITypeBytes,
		ABITypeAddress, ABITypeString, ABITypeAmount,
		ABITypeArray, ABITypeStruct, ABITypeOptional:
		return true
	default:
		return false
	}
}

// StablecoinABI describes the production-facing stablecoin interface used by
// the Sphinx runtime and SDKs for mint, transfer, burn, and read-only queries.
var StablecoinABI = ContractABI{
	Version: 1,
	Methods: []ABIMethod{
		{
			Name:        "mint",
			Description: "Mint new stablecoin into a recipient account. Only the owning admin may do this.",
			Parameters: []ABIParameter{
				{Name: "to", Type: ABITypeAddress},
				{Name: "amount", Type: ABITypeAmount},
			},
			Returns: []ABIParameter{{Name: "ok", Type: ABITypeBool}},
		},
		{
			Name:        "transfer",
			Description: "Move funds from sender to recipient.",
			Parameters: []ABIParameter{
				{Name: "to", Type: ABITypeAddress},
				{Name: "amount", Type: ABITypeAmount},
			},
			Returns: []ABIParameter{{Name: "ok", Type: ABITypeBool}},
		},
		{
			Name:        "burn",
			Description: "Burn tokens from a recipient account as the admin.",
			Parameters: []ABIParameter{
				{Name: "from", Type: ABITypeAddress},
				{Name: "amount", Type: ABITypeAmount},
			},
			Returns: []ABIParameter{{Name: "ok", Type: ABITypeBool}},
		},
		{
			Name:        "burn_self",
			Description: "Burn a caller-owned balance.",
			Parameters:  []ABIParameter{{Name: "amount", Type: ABITypeAmount}},
			Returns:     []ABIParameter{{Name: "ok", Type: ABITypeBool}},
		},
		{
			Name:       "balance_of",
			ReadOnly:   true,
			Parameters: []ABIParameter{{Name: "owner", Type: ABITypeAddress, Optional: true}},
			Returns:    []ABIParameter{{Name: "balance", Type: ABITypeAmount}},
		},
		{
			Name:     "info",
			ReadOnly: true,
			Returns: []ABIParameter{
				{Name: "name", Type: ABITypeString},
				{Name: "symbol", Type: ABITypeString},
				{Name: "decimals", Type: ABITypeUint64},
				{Name: "owner", Type: ABITypeAddress},
				{Name: "total_supply", Type: ABITypeAmount},
			},
		},
	},
	Events: []string{"mint", "burn", "transfer"},
	StateVars: []ABIParameter{
		{Name: "owner", Type: ABITypeAddress},
		{Name: "total_supply", Type: ABITypeAmount},
	},
}

// NewStablecoinMintCall creates a typed mint call for the production stablecoin ABI.
func NewStablecoinMintCall(to string, amount *big.Int) *RichCallSpec {
	return &RichCallSpec{
		Method: "mint",
		Args: []ABIValue{
			*NewABIValueAddress(to),
			*NewABIValueAmount(amount),
		},
	}
}

// NewStablecoinTransferCall creates a typed transfer call for the production stablecoin ABI.
func NewStablecoinTransferCall(to string, amount *big.Int) *RichCallSpec {
	return &RichCallSpec{
		Method: "transfer",
		Args: []ABIValue{
			*NewABIValueAddress(to),
			*NewABIValueAmount(amount),
		},
	}
}

// NewStablecoinBurnCall creates a typed burn call for the production stablecoin ABI.
func NewStablecoinBurnCall(from string, amount *big.Int) *RichCallSpec {
	return &RichCallSpec{
		Method: "burn",
		Args: []ABIValue{
			*NewABIValueAddress(from),
			*NewABIValueAmount(amount),
		},
	}
}

// NewStablecoinBurnSelfCall creates a typed self-burn call for the production stablecoin ABI.
func NewStablecoinBurnSelfCall(amount *big.Int) *RichCallSpec {
	return &RichCallSpec{
		Method: "burn_self",
		Args: []ABIValue{
			*NewABIValueAmount(amount),
		},
	}
}

// NewStablecoinBalanceOfCall creates a typed read-only account query.
func NewStablecoinBalanceOfCall(owner string) *RichCallSpec {
	return &RichCallSpec{
		Method:   "balance_of",
		ReadOnly: true,
		Args: []ABIValue{
			*NewABIValueAddress(owner),
		},
	}
}

// NewStablecoinInfoCall creates a typed metadata query.
func NewStablecoinInfoCall() *RichCallSpec {
	return &RichCallSpec{Method: "info", ReadOnly: true}
}
