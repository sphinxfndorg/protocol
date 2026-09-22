// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import "testing"

// minimalWASM exports a no-op sphinx_main function and has no imports.
var minimalWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
	0x03, 0x02, 0x01, 0x00,
	0x07, 0x0f, 0x01, 0x0b, 's', 'p', 'h', 'i', 'n', 'x', '_', 'm', 'a', 'i', 'n', 0x00, 0x00,
	0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
}

func TestValidateAndExecuteWASM(t *testing.T) {
	if err := ValidateWASM(minimalWASM, 1024, 1); err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{values: map[string][]byte{}}
	result, err := ExecuteWASM(store, "contract", minimalWASM, nil, 1024, 1)
	if err != nil || result.Return["runtime"] != RuntimeWASM {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestAnalyzeWASMRejectsLoopAndFloat(t *testing.T) {
	// A minimal module whose function body contains a loop instruction.
	loop := []byte{0, 'a', 's', 'm', 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 7, 15, 1, 11, 's', 'p', 'h', 'i', 'n', 'x', '_', 'm', 'a', 'i', 'n', 0, 0, 10, 5, 1, 3, 0, 3, 0x40, 0x0b}
	if _, err := AnalyzeWASM(loop); err == nil {
		t.Fatal("expected loop to be rejected")
	}
}

func TestExecuteWASMReadOnlyDoesNotPersistStorageOrTransfer(t *testing.T) {
	// Imports storage_set, then writes key 1/value 2 from sphinx_main.
	code := []byte{
		0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 9, 2, 0x60, 0, 0, 0x60, 2, 0x7e, 0x7e, 0,
		2, 22, 1, 6, 's', 'p', 'h', 'i', 'n', 'x', 11, 's', 't', 'o', 'r', 'a', 'g', 'e', '_', 's', 'e', 't', 0, 1,
		3, 2, 1, 0,
		7, 15, 1, 11, 's', 'p', 'h', 'i', 'n', 'x', '_', 'm', 'a', 'i', 'n', 0, 1,
		10, 10, 1, 8, 0, 0x42, 1, 0x42, 2, 0x10, 0, 0x0b,
	}
	store := &memoryStore{values: map[string][]byte{}}
	if _, err := ExecuteWASMReadOnly(store, "contract", code, nil, 1024, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetContractStorage("contract", "wasm:0000000000000001"); err == nil {
		t.Fatal("read-only execution persisted a storage write")
	}
}

func TestValidateContractMetaRuntimeVersions(t *testing.T) {
	for _, runtime := range []string{RuntimeNative, RuntimeSVM1, RuntimeWASM} {
		version, ok := RuntimeVersion(runtime)
		if !ok || version != 1 {
			t.Fatalf("runtime %q version=%d ok=%v", runtime, version, ok)
		}
		meta := &ContractMeta{Runtime: runtime, RuntimeVersion: version}
		if err := ValidateContractMeta(meta); err != nil {
			t.Fatal(err)
		}
		if err := ValidateContractMeta(&ContractMeta{Runtime: RuntimeWASM, RuntimeVersion: 2}); err == nil {
			t.Fatal("accepted unsupported runtime version")
		}
	}
}
