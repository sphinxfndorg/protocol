// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package vm

import (
	"encoding/binary"
	"errors"
	"testing"

	svm "github.com/sphinxfndorg/protocol/src/core/kernel/opcodes"
)

// testStore is a minimal SVM1Store backed by an in-memory map.
type testStore struct {
	values map[string]map[string][]byte // address -> storageKey -> value
}

func (s *testStore) GetContractStorage(address, key string) ([]byte, error) {
	if s.values == nil {
		return nil, errors.New("missing")
	}
	v, ok := s.values[address][key]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}

func (s *testStore) SetContractStorage(address, key string, value []byte) {
	if s.values == nil {
		s.values = map[string]map[string][]byte{}
	}
	if s.values[address] == nil {
		s.values[address] = map[string][]byte{}
	}
	s.values[address][key] = value
}

func push8(value uint64) []byte {
	b := make([]byte, 9)
	b[0] = svm.SVMPush8
	binary.BigEndian.PutUint64(b[1:], value)
	return b
}

func TestExecuteSVM1StoresAndLoadsValue(t *testing.T) {
	store := &testStore{}
	code := append([]byte{}, svm.SVM1Magic...)
	code = append(code, push8(7)...)
	code = append(code, push8(42)...)
	code = append(code, svm.SVMStore)
	code = append(code, push8(7)...)
	code = append(code, svm.SVMLoad, svm.SVMReturn)

	result, ops, err := ExecuteSVM1(store, "contract", code, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if ops == 0 || result != 42 {
		t.Fatalf("unexpected result=%d ops=%d", result, ops)
	}
}

func TestExecuteSVM1ReadsCallData(t *testing.T) {
	store := &testStore{}
	code := append([]byte{}, svm.SVM1Magic...)
	code = append(code, push8(0)...)
	code = append(code, svm.SVMCallDataWord, svm.SVMReturn)
	input := make([]byte, 8)
	binary.BigEndian.PutUint64(input, 99)

	result, _, err := ExecuteSVM1(store, "contract", code, input, 100)
	if err != nil || result != 99 {
		t.Fatalf("result=%d err=%v", result, err)
	}
}

func TestExecuteSVM1Arithmetic(t *testing.T) {
	store := &testStore{}
	code := append([]byte{}, svm.SVM1Magic...)
	code = append(code, push8(10)...)
	code = append(code, push8(15)...)
	code = append(code, svm.SVMAdd, svm.SVMReturn)

	result, _, err := ExecuteSVM1(store, "contract", code, nil, 100)
	if err != nil || result != 25 {
		t.Fatalf("result=%d err=%v", result, err)
	}
}

func TestExecuteSVM1DivisionByZero(t *testing.T) {
	store := &testStore{}
	code := append([]byte{}, svm.SVM1Magic...)
	code = append(code, push8(10)...)
	code = append(code, push8(0)...)
	code = append(code, svm.SVMDiv, svm.SVMReturn)

	if _, _, err := ExecuteSVM1(store, "contract", code, nil, 100); err == nil {
		t.Fatal("expected division by zero error")
	}
}

func TestExecuteSVM1RejectsTrailingCode(t *testing.T) {
	store := &testStore{}
	code := append([]byte{}, svm.SVM1Magic...)
	code = append(code, svm.SVMStop, svm.SVMStop)

	if _, _, err := ExecuteSVM1(store, "contract", code, nil, 100); err == nil {
		t.Fatal("expected trailing code after stop to be rejected")
	}
}

func TestExecuteSVM1EnforcesMaxOperations(t *testing.T) {
	store := &testStore{}
	code := append([]byte{}, svm.SVM1Magic...)
	code = append(code, push8(1)...)
	code = append(code, svm.SVMReturn)

	_, ops, err := ExecuteSVM1(store, "contract", code, nil, 1)
	if err == nil || ops != 2 {
		t.Fatalf("expected operation limit error with ops=2, got ops=%d err=%v", ops, err)
	}
}

func TestExecuteSVM1InvalidMagic(t *testing.T) {
	store := &testStore{}
	if _, _, err := ExecuteSVM1(store, "contract", []byte{'X', 'Y'}, nil, 100); err == nil {
		t.Fatal("expected invalid SVM1 code error")
	}
}
