// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// StorageValue is a type-safe wrapper for contract storage
type StorageValue struct {
	data []byte
	typ  ValueType
}

// ValueType defines the kind of storage value
type ValueType uint8

const (
	ValueTypeRaw      ValueType = 0 // Untyped raw bytes
	ValueTypeWord     ValueType = 1 // uint64
	ValueTypeInt      ValueType = 2 // int64
	ValueTypeBigInt   ValueType = 3 // big.Int stored as decimal bytes
	ValueTypeAddress  ValueType = 4 // Address string
	ValueTypeBytes    ValueType = 5 // Variable-length byte array with length prefix
	ValueTypeString   ValueType = 6 // UTF-8 string with length prefix
	ValueTypeBool     ValueType = 7 // Boolean (1 byte)
	ValueTypeArray    ValueType = 8 // Array of values (serialized JSON)
	ValueTypeMap      ValueType = 9 // Map/dict values (serialized JSON)
)

// TypedStorageKey represents a storage key with optional type information
type TypedStorageKey struct {
	Namespace string // e.g., "balances", "allowances"
	Key       string // e.g., user address
	ValueType ValueType
}

// NewStorageValueWord creates a typed storage value for uint64
func NewStorageValueWord(val uint64) *StorageValue {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, val)
	return &StorageValue{data: data, typ: ValueTypeWord}
}

// NewStorageValueInt creates a typed storage value for int64
func NewStorageValueInt(val int64) *StorageValue {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(val))
	return &StorageValue{data: data, typ: ValueTypeInt}
}

// NewStorageValueBigInt creates a typed storage value for big.Int
func NewStorageValueBigInt(val *big.Int) *StorageValue {
	data := []byte(val.String())
	return &StorageValue{data: data, typ: ValueTypeBigInt}
}

// NewStorageValueAddress creates a typed storage value for an address
func NewStorageValueAddress(addr string) *StorageValue {
	return &StorageValue{data: []byte(addr), typ: ValueTypeAddress}
}

// NewStorageValueBytes creates a typed storage value for byte array
func NewStorageValueBytes(val []byte) *StorageValue {
	// Prefix with length
	data := make([]byte, 4+len(val))
	binary.BigEndian.PutUint32(data, uint32(len(val)))
	copy(data[4:], val)
	return &StorageValue{data: data, typ: ValueTypeBytes}
}

// NewStorageValueString creates a typed storage value for string
func NewStorageValueString(val string) *StorageValue {
	data := make([]byte, 4+len(val))
	binary.BigEndian.PutUint32(data, uint32(len(val)))
	copy(data[4:], val)
	return &StorageValue{data: data, typ: ValueTypeString}
}

// NewStorageValueBool creates a typed storage value for bool
func NewStorageValueBool(val bool) *StorageValue {
	data := []byte{0}
	if val {
		data[0] = 1
	}
	return &StorageValue{data: data, typ: ValueTypeBool}
}

// NewStorageValueArray creates a typed storage value for an array (serialized as JSON)
func NewStorageValueArray(items []interface{}) (*StorageValue, error) {
	data, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	return &StorageValue{data: data, typ: ValueTypeArray}, nil
}

// NewStorageValueMap creates a typed storage value for a map (serialized as JSON)
func NewStorageValueMap(m map[string]interface{}) (*StorageValue, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return &StorageValue{data: data, typ: ValueTypeMap}, nil
}

// AsWord extracts the value as uint64
func (sv *StorageValue) AsWord() (uint64, error) {
	if sv.typ != ValueTypeWord {
		return 0, fmt.Errorf("expected word, got %d", sv.typ)
	}
	if len(sv.data) != 8 {
		return 0, fmt.Errorf("invalid word length: %d", len(sv.data))
	}
	return binary.BigEndian.Uint64(sv.data), nil
}

// AsInt extracts the value as int64
func (sv *StorageValue) AsInt() (int64, error) {
	if sv.typ != ValueTypeInt {
		return 0, fmt.Errorf("expected int, got %d", sv.typ)
	}
	if len(sv.data) != 8 {
		return 0, fmt.Errorf("invalid int length: %d", len(sv.data))
	}
	return int64(binary.BigEndian.Uint64(sv.data)), nil
}

// AsBigInt extracts the value as big.Int
func (sv *StorageValue) AsBigInt() (*big.Int, error) {
	if sv.typ != ValueTypeBigInt {
		return nil, fmt.Errorf("expected bigint, got %d", sv.typ)
	}
	val := new(big.Int)
	if _, ok := val.SetString(string(sv.data), 10); !ok {
		return nil, fmt.Errorf("invalid big.Int: %s", string(sv.data))
	}
	return val, nil
}

// AsAddress extracts the value as an address string
func (sv *StorageValue) AsAddress() (string, error) {
	if sv.typ != ValueTypeAddress {
		return "", fmt.Errorf("expected address, got %d", sv.typ)
	}
	return string(sv.data), nil
}

// AsBytes extracts the value as byte array (removing length prefix)
func (sv *StorageValue) AsBytes() ([]byte, error) {
	if sv.typ != ValueTypeBytes {
		return nil, fmt.Errorf("expected bytes, got %d", sv.typ)
	}
	if len(sv.data) < 4 {
		return nil, errors.New("invalid bytes: too short")
	}
	length := binary.BigEndian.Uint32(sv.data)
	if len(sv.data) != 4+int(length) {
		return nil, errors.New("invalid bytes: length mismatch")
	}
	return append([]byte{}, sv.data[4:]...), nil
}

// AsString extracts the value as string (removing length prefix)
func (sv *StorageValue) AsString() (string, error) {
	if sv.typ != ValueTypeString {
		return "", fmt.Errorf("expected string, got %d", sv.typ)
	}
	if len(sv.data) < 4 {
		return "", errors.New("invalid string: too short")
	}
	length := binary.BigEndian.Uint32(sv.data)
	if len(sv.data) != 4+int(length) {
		return "", errors.New("invalid string: length mismatch")
	}
	return string(sv.data[4:]), nil
}

// AsBool extracts the value as bool
func (sv *StorageValue) AsBool() (bool, error) {
	if sv.typ != ValueTypeBool {
		return false, fmt.Errorf("expected bool, got %d", sv.typ)
	}
	if len(sv.data) != 1 {
		return false, errors.New("invalid bool length")
	}
	return sv.data[0] != 0, nil
}

// AsArray extracts the value as an array (deserialized from JSON)
func (sv *StorageValue) AsArray() ([]interface{}, error) {
	if sv.typ != ValueTypeArray {
		return nil, fmt.Errorf("expected array, got %d", sv.typ)
	}
	var items []interface{}
	if err := json.Unmarshal(sv.data, &items); err != nil {
		return nil, fmt.Errorf("unmarshal array: %w", err)
	}
	return items, nil
}

// AsMap extracts the value as a map (deserialized from JSON)
func (sv *StorageValue) AsMap() (map[string]interface{}, error) {
	if sv.typ != ValueTypeMap {
		return nil, fmt.Errorf("expected map, got %d", sv.typ)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(sv.data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal map: %w", err)
	}
	return m, nil
}

// Bytes returns the serialized representation with type prefix
func (sv *StorageValue) Bytes() []byte {
	result := make([]byte, 1+len(sv.data))
	result[0] = byte(sv.typ)
	copy(result[1:], sv.data)
	return result
}

// ParseStorageValue deserializes a storage value from its encoded form
func ParseStorageValue(data []byte) (*StorageValue, error) {
	if len(data) == 0 {
		return nil, errors.New("empty storage value")
	}
	typ := ValueType(data[0])
	return &StorageValue{data: data[1:], typ: typ}, nil
}

// BoundedArray is a length-limited array storage container
type BoundedArray struct {
	store      Store
	address    string
	storageKey string
	maxLen     uint32
	items      [][]byte
}

// NewBoundedArray creates a bounded array with a maximum length
func NewBoundedArray(store Store, address, key string, maxLen uint32) *BoundedArray {
	return &BoundedArray{
		store:      store,
		address:    address,
		storageKey: key,
		maxLen:     maxLen,
		items:      [][]byte{},
	}
}

// Load retrieves the array from storage
func (ba *BoundedArray) Load() error {
	data, err := ba.store.GetContractStorage(ba.address, ba.storageKey)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		ba.items = [][]byte{}
		return nil
	}

	// Remove type prefix if present
	jsonData := data
	if len(data) > 0 && data[0] == byte(ValueTypeArray) {
		jsonData = data[1:]
	}

	var items []interface{}
	if err := json.Unmarshal(jsonData, &items); err != nil {
		return err
	}
	ba.items = make([][]byte, len(items))
	for i, item := range items {
		if s, ok := item.(string); ok {
			ba.items[i] = []byte(s)
		}
	}
	return nil
}

// Push adds an item to the array
func (ba *BoundedArray) Push(item []byte) error {
	if uint32(len(ba.items)) >= ba.maxLen {
		return fmt.Errorf("bounded array at capacity: %d >= %d", len(ba.items), ba.maxLen)
	}
	ba.items = append(ba.items, append([]byte{}, item...))
	return nil
}

// Pop removes and returns the last item
func (ba *BoundedArray) Pop() ([]byte, error) {
	if len(ba.items) == 0 {
		return nil, errors.New("cannot pop from empty array")
	}
	item := ba.items[len(ba.items)-1]
	ba.items = ba.items[:len(ba.items)-1]
	return append([]byte{}, item...), nil
}

// Len returns the current length
func (ba *BoundedArray) Len() uint32 {
	return uint32(len(ba.items))
}

// Get retrieves an item at an index
func (ba *BoundedArray) Get(index uint32) ([]byte, error) {
	if index >= uint32(len(ba.items)) {
		return nil, fmt.Errorf("index out of bounds: %d >= %d", index, len(ba.items))
	}
	return append([]byte{}, ba.items[index]...), nil
}

// Set updates an item at an index
func (ba *BoundedArray) Set(index uint32, item []byte) error {
	if index >= uint32(len(ba.items)) {
		return fmt.Errorf("index out of bounds: %d >= %d", index, len(ba.items))
	}
	ba.items[index] = append([]byte{}, item...)
	return nil
}

// Save persists the array to storage
func (ba *BoundedArray) Save() error {
	items := make([]interface{}, len(ba.items))
	for i, item := range ba.items {
		items[i] = string(item)
	}
	sv, err := NewStorageValueArray(items)
	if err != nil {
		return err
	}
	ba.store.SetContractStorage(ba.address, ba.storageKey, sv.Bytes())
	return nil
}

// BoundedMap is a size-limited map storage container with key enumeration
type BoundedMap struct {
	store      Store
	address    string
	storageKey string
	maxKeys    uint32
	data       map[string][]byte
}

// NewBoundedMap creates a bounded map with a maximum number of keys
func NewBoundedMap(store Store, address, key string, maxKeys uint32) *BoundedMap {
	return &BoundedMap{
		store:      store,
		address:    address,
		storageKey: key,
		maxKeys:    maxKeys,
		data:       make(map[string][]byte),
	}
}

// Load retrieves the map from storage
func (bm *BoundedMap) Load() error {
	data, err := bm.store.GetContractStorage(bm.address, bm.storageKey)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		bm.data = make(map[string][]byte)
		return nil
	}

	// Remove type prefix if present
	jsonData := data
	if len(data) > 0 && data[0] == byte(ValueTypeMap) {
		jsonData = data[1:]
	}

	var m map[string]interface{}
	if err := json.Unmarshal(jsonData, &m); err != nil {
		return err
	}
	bm.data = make(map[string][]byte, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			bm.data[k] = []byte(s)
		}
	}
	return nil
}

// Set adds or updates a key-value pair
func (bm *BoundedMap) Set(key string, value []byte) error {
	if _, exists := bm.data[key]; !exists && uint32(len(bm.data)) >= bm.maxKeys {
		return fmt.Errorf("bounded map at capacity: %d >= %d", len(bm.data), bm.maxKeys)
	}
	bm.data[key] = append([]byte{}, value...)
	return nil
}

// Get retrieves a value by key
func (bm *BoundedMap) Get(key string) ([]byte, error) {
	value, ok := bm.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return append([]byte{}, value...), nil
}

// Delete removes a key-value pair
func (bm *BoundedMap) Delete(key string) error {
	if _, ok := bm.data[key]; !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	delete(bm.data, key)
	return nil
}

// Keys returns all keys in the map
func (bm *BoundedMap) Keys() []string {
	keys := make([]string, 0, len(bm.data))
	for k := range bm.data {
		keys = append(keys, k)
	}
	return keys
}

// Size returns the number of key-value pairs
func (bm *BoundedMap) Size() uint32 {
	return uint32(len(bm.data))
}

// Save persists the map to storage
func (bm *BoundedMap) Save() error {
	m := make(map[string]interface{}, len(bm.data))
	for k, v := range bm.data {
		m[k] = string(v)
	}
	sv, err := NewStorageValueMap(m)
	if err != nil {
		return err
	}
	bm.store.SetContractStorage(bm.address, bm.storageKey, sv.Bytes())
	return nil
}
