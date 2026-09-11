// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"errors"
	"testing"
)

type sip721MemoryStore struct{ values map[string][]byte }

func (s *sip721MemoryStore) key(address, kind, key string) string { return address + ":" + kind + ":" + key }
func (s *sip721MemoryStore) ContractExists(address string) bool {
	_, ok := s.values[s.key(address, "meta", "")]
	return ok
}
func (s *sip721MemoryStore) SetContractCode(address string, code []byte) {
	s.values[s.key(address, "code", "")] = code
}
func (s *sip721MemoryStore) GetContractCode(address string) ([]byte, error) {
	v, ok := s.values[s.key(address, "code", "")]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}
func (s *sip721MemoryStore) SetContractMeta(address string, meta []byte) {
	s.values[s.key(address, "meta", "")] = meta
}
func (s *sip721MemoryStore) GetContractMeta(address string) ([]byte, error) {
	v, ok := s.values[s.key(address, "meta", "")]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}
func (s *sip721MemoryStore) SetContractStorage(address, key string, value []byte) {
	s.values[s.key(address, "storage", key)] = value
}
func (s *sip721MemoryStore) GetContractStorage(address, key string) ([]byte, error) {
	v, ok := s.values[s.key(address, "storage", key)]
	if !ok {
		return nil, errors.New("missing")
	}
	return v, nil
}

func newSIP721TestStore() *sip721MemoryStore {
	return &sip721MemoryStore{values: map[string][]byte{}}
}

func deploySIP721ForTest(store *sip721MemoryStore, owner string) string {
	code, err := BuildDeployCode(&DeploySpec{
		Standard: StandardSIP721, Name: "Sphinx Pets", Symbol: "PETS", Owner: owner,
	})
	if err != nil {
		panic(err)
	}
	store.SetContractCode("sc721", code)
	store.SetContractMeta("sc721", []byte(`{"address":"sc721","creator":"` + owner + `","runtime":"native","standard":"sip721","created_at":1}`))
	if err := initSIP721(store, "sc721", owner, &DeploySpec{Standard: StandardSIP721, Name: "Sphinx Pets", Symbol: "PETS", Owner: owner}); err != nil {
		panic(err)
	}
	return "sc721"
}

func callSIP721ForTest(t *testing.T, store *sip721MemoryStore, addr, caller, method string, args map[string]string) (*ExecutionResult, error) {
	t.Helper()
	return callSIP721(store, addr, caller, &CallSpec{Method: method, Args: args})
}

func TestSIP721MintAllocatesIncrementingTokenIDs(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// tokenId counter: 1, then 2 — Ethereum-style sequential allocation.
	r1, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{"to": "alice", "token_uri": "ipfs://cid1", "mint_id": "mint0001"})
	if err != nil || r1.Return["token_id"] != "1" {
		t.Fatalf("first mint: token_id=%q err=%v", r1.Return["token_id"], err)
	}
	r2, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{"to": "bob", "token_uri": "ipfs://cid2", "mint_id": "mint0002"})
	if err != nil || r2.Return["token_id"] != "2" {
		t.Fatalf("second mint: token_id=%q err=%v", r2.Return["token_id"], err)
	}

	// Contract storage tokenURI[tokenId] — the exact ERC-721 mapping.
	uri, err := store.GetContractStorage(addr, sip721TokenURIKey(1))
	if err != nil || string(uri) != "ipfs://cid1" {
		t.Fatalf("tokenURI[1]: %q err=%v", uri, err)
	}
	owner, err := store.GetContractStorage(addr, sip721TokenOwnerKey(2))
	if err != nil || string(owner) != "bob" {
		t.Fatalf("ownerOf[2]: %q err=%v", owner, err)
	}

	// mint_id -> tokenId reverse index.
	tokID, err := store.GetContractStorage(addr, sip721MintTokenKey("mint0002"))
	if err != nil || string(tokID) != "2" {
		t.Fatalf("sip721:mint:mint0002: %q err=%v", tokID, err)
	}
}

func TestSIP721MintAbortsWithoutTokenURI(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// Mint aborts: a tokenURI-less NFT pins nothing (mint-abort rule).
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{"to": "alice"}); err == nil {
		t.Fatal("expected mint without token_uri to abort")
	}
	// Non-owner can never mint (ownerOf enforcement).
	if _, err := callSIP721ForTest(t, store, addr, "mallory", "mint", map[string]string{"to": "alice", "token_uri": "ipfs://cid"}); err == nil {
		t.Fatal("expected non-owner mint to be rejected")
	}
}

func TestSIP721TransferFromRequiresOwnerOrApproval(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{"to": "alice", "token_uri": "ipfs://cid", "mint_id": "mint0001"})

	// Non-owner, non-approved transfer is rejected.
	if _, err := callSIP721ForTest(t, store, addr, "mallory", "transfer_from", map[string]string{"from": "alice", "to": "mallory", "token_id": "1"}); err == nil {
		t.Fatal("expected unapproved transfer_from to be rejected")
	}

	// Owner transfers fine.
	if _, err := callSIP721ForTest(t, store, addr, "alice", "transfer_from", map[string]string{"from": "alice", "to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("owner transfer_from: %v", err)
	}
	owner, _ := store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "bob" {
		t.Fatalf("ownerOf[1] after transfer: %q", owner)
	}

	// Approve + approved-caller transfer.
	if _, err := callSIP721ForTest(t, store, addr, "bob", "approve", map[string]string{"to": "carol", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "carol", "transfer_from", map[string]string{"from": "bob", "to": "dave", "token_id": "1"}); err != nil {
		t.Fatalf("approved transfer_from: %v", err)
	}
	owner, _ = store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "dave" {
		t.Fatalf("ownerOf[1] after approved transfer: %q", owner)
	}
}
