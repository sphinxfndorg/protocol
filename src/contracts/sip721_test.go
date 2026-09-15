// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

type sip721MemoryStore struct{ values map[string][]byte }

func (s *sip721MemoryStore) key(address, kind, key string) string {
	return address + ":" + kind + ":" + key
}
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
	store.SetContractMeta("sc721", []byte(`{"address":"sc721","creator":"`+owner+`","runtime":"native","standard":"sip721","created_at":1}`))
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

// ── Embedded-economics enforcement (resale royalty + license fees) ───────────

// fakeLedger captures the outbound transfers the native runtime performs when
// it settles the escrowed value of a transfer_from / purchase_license.
type fakeLedger struct{ payments map[string]*big.Int }

func newFakeLedger() *fakeLedger { return &fakeLedger{payments: map[string]*big.Int{}} }

func (l *fakeLedger) transfer(to string, amount *big.Int) error {
	if l.payments[to] == nil {
		l.payments[to] = big.NewInt(0)
	}
	l.payments[to].Add(l.payments[to], amount)
	return nil
}

func testTransferCtx(value *big.Int) (*NativeCallContext, *fakeLedger) {
	ledger := newFakeLedger()
	return &NativeCallContext{Value: value, Transfer: ledger.transfer}, ledger
}

func mustSPIF(t *testing.T, raw string) string {
	t.Helper()
	norm, err := common.NormalizeSPIFAddress(raw)
	if err != nil {
		t.Fatalf("invalid SPIF address %q: %v", raw, err)
	}
	return norm
}

func TestSIP721MintRecordsTermsAndTermsOfReadsThem(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	recipient := mustSPIF(t, "F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6")

	r, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "mint_id": "mint0001",
		"royalty_bps": "500", "usage_fee": "50000000000000000", "royalty_recipient": recipient,
	})
	if err != nil {
		t.Fatalf("mint with terms: %v", err)
	}
	if r.Return["royalty_bps"] != "500" || r.Return["usage_fee"] != "50000000000000000" || r.Return["royalty_recipient"] != recipient {
		t.Fatalf("mint did not report terms: %#v", r.Return)
	}

	// terms_of surfaces every frozen term + the creator + the active licensee.
	terms, err := callSIP721ForTest(t, store, addr, "anyone", "terms_of", map[string]string{"token_id": "1"})
	if err != nil {
		t.Fatalf("terms_of: %v", err)
	}
	if terms.Return["creator"] != "owner" || terms.Return["royalty_bps"] != "500" ||
		terms.Return["royalty_recipient"] != recipient || terms.Return["usage_fee"] != "50000000000000000" ||
		terms.Return["licensee"] != "" {
		t.Fatalf("terms_of did not surface frozen terms: %#v", terms.Return)
	}
	if getSIP721Terms(store, addr, 1) == nil || getSIP721Terms(store, addr, 1).RoyaltyBPS != 500 {
		t.Fatal("terms not persisted in contract storage")
	}
}

func TestSIP721MintRejectsInvalidTerms(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// royalty_bps out of range is rejected at mint.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "10001",
	}); err == nil || !strings.Contains(err.Error(), "royalty_bps") {
		t.Fatalf("expected royalty_bps bound rejection, got %v", err)
	}
	// non-decimal usage_fee is rejected.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "usage_fee": "abc",
	}); err == nil || !strings.Contains(err.Error(), "usage_fee") {
		t.Fatalf("expected usage_fee rejection, got %v", err)
	}
	// malformed royalty_recipient is rejected.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_recipient": "not-an-address",
	}); err == nil || !strings.Contains(err.Error(), "royalty_recipient") {
		t.Fatalf("expected royalty_recipient rejection, got %v", err)
	}
}
func TestSIP721TransferFromSplitsResaleRoyalty(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// Creator sets a 5% resale royalty; recipient is the collection owner
	// (mint caller) since no override is provided.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "mint_id": "mint0001", "royalty_bps": "500",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Approved-buyer sale: alice (owner) approves bob; bob pays 2 SPX.
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve buyer: %v", err)
	}
	salePrice := new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)) // 2 SPX
	ctx, ledger := testTransferCtx(salePrice)
	r, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx)
	if err != nil {
		t.Fatalf("buyer-initiated sale: %v", err)
	}

	// royalty = 5% × 2e18 = 1e17 → creator ("owner"); proceeds = 1.9e18 → seller ("alice").
	wantRoyalty := big.NewInt(1e17)
	wantProceeds := new(big.Int).Sub(salePrice, wantRoyalty)
	if ledger.payments["owner"] == nil || ledger.payments["owner"].Cmp(wantRoyalty) != 0 {
		t.Fatalf("royalty to creator = %v, want %s", ledger.payments["owner"], wantRoyalty)
	}
	if ledger.payments["alice"] == nil || ledger.payments["alice"].Cmp(wantProceeds) != 0 {
		t.Fatalf("proceeds to seller = %v, want %s", ledger.payments["alice"], wantProceeds)
	}
	// payout total must equal the escrowed sale price — the contract nets zero.
	sum := new(big.Int).Add(ledger.payments["owner"], ledger.payments["alice"])
	if sum.Cmp(salePrice) != 0 {
		t.Fatalf("payouts do not balance escrow: sum=%s price=%s", sum, salePrice)
	}
	if r.Return["royalty_amount"] != wantRoyalty.String() || r.Return["proceeds_amount"] != wantProceeds.String() {
		t.Fatalf("execution result did not report settlement: %#v", r.Return)
	}

	owner, _ := store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "bob" {
		t.Fatalf("ownerOf[1] after approved sale: %q", owner)
	}
}

func TestSIP721TransferFromRoyaltyFlooredWhenSettlingAtDust(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// 50% royalty, 1 nSPX sale against a 0.1 SPX floor.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "5000",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve buyer: %v", err)
	}
	floor := big.NewInt(1e17)
	ctx, ledger := testTransferCtx(big.NewInt(1))
	ctx.PriceFloor = floor

	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx); err != nil {
		t.Fatalf("dust sale: %v", err)
	}

	// floor basis: royalty = 50% × max(1, 1e17) = 5e16, capped at the 1 nSPX escrow.
	if got := ledger.payments["owner"]; got == nil || got.String() != "1" {
		t.Fatalf("floored royalty = %v, want 1 (capped at escrow)", got)
	}
	// seller gets nothing under the cap — the escrow still balances exactly.
	// Zero-value legs are skipped (the kernel transfer hook rejects
	// non-positive amounts), so "zero" is the ABSENCE of a payment, not a 0
	// entry. Royalty (1) + proceeds (0, skipped) still sum to the price (1).
	if got, ok := ledger.payments["alice"]; ok && got.Sign() != 0 {
		t.Fatalf("seller proceeds should be absent/zero when the royalty cap consumed the escrow, got %v", got)
	}
}
func TestSIP721LegacyTransferWithoutTermsPassesValueToSeller(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// Legacy token: no terms at all. A value-carrying transfer must pass the
	// entire escrow to the seller — the previous "value sticks in the
	// contract" behavior would have stranded sale proceeds.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve buyer: %v", err)
	}
	salePrice := new(big.Int).Mul(big.NewInt(3), big.NewInt(1e18))
	ctx, ledger := testTransferCtx(salePrice)
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx); err != nil {
		t.Fatalf("legacy sale: %v", err)
	}
	if ledger.payments["alice"] == nil || ledger.payments["alice"].Cmp(salePrice) != 0 {
		t.Fatalf("legacy seller should receive the full value, got %v", ledger.payments["alice"])
	}
	if len(ledger.payments) != 1 {
		t.Fatalf("legacy sale must not mint any royalty payment, got %#v", ledger.payments)
	}
}

func TestSIP721PurchaseLicenseEnforcesExactFeeAndSingleIssue(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	fee := big.NewInt(5e16)

	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "usage_fee": fee.String(),
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Wrong value carried → rejected before any payment or entitlement.
	ctx, _ := testTransferCtx(new(big.Int).Add(fee, big.NewInt(1)))
	if _, err := callSIP721WithContext(store, addr, "carol", &CallSpec{Method: "purchase_license", Args: map[string]string{"token_id": "1"}}, ctx); err == nil {
		t.Fatal("purchase_license with wrong fee must be rejected")
	}

	// Exact fee → the creator is paid and the license is issued.
	ctx, ledger := testTransferCtx(fee)
	r, err := callSIP721WithContext(store, addr, "carol", &CallSpec{Method: "purchase_license", Args: map[string]string{"token_id": "1"}}, ctx)
	if err != nil {
		t.Fatalf("purchase_license: %v", err)
	}
	if r.Return["licensee"] != "carol" || r.Return["fee"] != fee.String() {
		t.Fatalf("purchase_license result: %#v", r.Return)
	}
	if ledger.payments["owner"] == nil || ledger.payments["owner"].Cmp(fee) != 0 {
		t.Fatalf("creator must receive the usage fee, got %v", ledger.payments["owner"])
	}
	if getSIP721Licensee(store, addr, 1) != "carol" {
		t.Fatalf("license not recorded for carol")
	}

	// Single-issue: a second licensee is rejected until a revoke.
	ctx2, _ := testTransferCtx(fee)
	if _, err := callSIP721WithContext(store, addr, "dave", &CallSpec{Method: "purchase_license", Args: map[string]string{"token_id": "1"}}, ctx2); err == nil {
		t.Fatal("second license on a single-issue token must be rejected")
	}

	// Only the creator / collection owner may revoke.
	if _, err := callSIP721ForTest(t, store, addr, "mallory", "revoke_license", map[string]string{"token_id": "1"}); err == nil {
		t.Fatal("non-creator revoke must be rejected")
	}
	if _, err := callSIP721ForTest(t, store, addr, "owner", "revoke_license", map[string]string{"token_id": "1"}); err != nil {
		t.Fatalf("creator revoke: %v", err)
	}
	if getSIP721Licensee(store, addr, 1) != "" {
		t.Fatal("license must be cleared after revoke")
	}

	// Re-license after revoke succeeds.
	ctx3, _ := testTransferCtx(fee)
	if _, err := callSIP721WithContext(store, addr, "dave", &CallSpec{Method: "purchase_license", Args: map[string]string{"token_id": "1"}}, ctx3); err != nil {
		t.Fatalf("re-license after revoke: %v", err)
	}
	if getSIP721Licensee(store, addr, 1) != "dave" {
		t.Fatalf("re-license not recorded for dave")
	}
}

// Gap 1: royalty_bps bounds. bps is attacker/creator-set at mint time, so the
// on-chain ceiling (<= 10000) must hold at mint AND at settlement (a corrupted
// terms record must fail closed), and bps == 0 must behave as "no royalty".
func TestSIP721RoyaltyBPSBounds(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	// bps > 10000 rejected at mint.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "10001",
	}); err == nil {
		t.Fatal("mint with royalty_bps 10001 must be rejected")
	}

	// bps == 10000 (100%) accepted: seller gets nothing, creator takes all.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "10000",
	}); err != nil {
		t.Fatalf("mint with royalty_bps 10000: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	price := big.NewInt(1e18)
	ctx, ledger := testTransferCtx(price)
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx); err != nil {
		t.Fatalf("full royalty sale: %v", err)
	}
	if ledger.payments["owner"] == nil || ledger.payments["owner"].Cmp(price) != 0 {
		t.Fatalf("full royalty: creator should take the whole price, got %v", ledger.payments["owner"])
	}
	if got, ok := ledger.payments["alice"]; ok && got.Sign() != 0 {
		t.Fatalf("full royalty: seller proceeds must be absent/zero, got %v", got)
	}
}

// Gap 1 (cont.): bps == 0 is explicitly "no royalty" — identical to legacy
// no-terms pass-through, never "terms present but unpaid".
func TestSIP721ZeroBPSPassesFullValueToSeller(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "0",
	}); err != nil {
		t.Fatalf("mint with royalty_bps 0: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	price := big.NewInt(1e18)
	ctx, ledger := testTransferCtx(price)
	r, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx)
	if err != nil {
		t.Fatalf("0-bps sale: %v", err)
	}
	if ledger.payments["alice"] == nil || ledger.payments["alice"].Cmp(price) != 0 {
		t.Fatalf("0-bps sale: seller should receive full value, got %v", ledger.payments["alice"])
	}
	if len(ledger.payments) != 1 {
		t.Fatalf("0-bps sale must not mint any royalty payment, got %#v", ledger.payments)
	}
	if r.Return["royalty_amount"] != "0" {
		t.Fatalf("0-bps sale should report zero royalty, got %#v", r.Return)
	}
}

// Gap 1 (cont.): corrupted storage with bps > 10000 must fail closed at
// settlement, never drain more than the sale value.
func TestSIP721CorruptTermsFailClosedAtSettlement(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")

	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "500",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	store.SetContractStorage(addr, sip721TokenTermsKey(1), []byte(`{"creator":"owner","royalty_bps":20000,"royalty_recipient":"owner"}`))
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	ctx, _ := testTransferCtx(big.NewInt(1e18))
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx); err == nil || !strings.Contains(err.Error(), "royalty_bps") {
		t.Fatalf("settlement with corrupt bps must fail closed, got %v", err)
	}
	owner, _ := store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "alice" {
		t.Fatalf("failed settlement must not move the token, owner=%q", owner)
	}
}

// Gap 2: mid-split failure aborts the whole call — the contract store buffers
// writes and the executor discards them with the block on error, so the
// royalty leg can never strand alone. Fail the proceeds leg and confirm the
// token does not move and the error names the leg.
func TestSIP721SplitIsAtomicWhenProceedsLegFails(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "500",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	ctx := &NativeCallContext{Value: big.NewInt(1e18), Transfer: func(to string, amount *big.Int) error {
		if to == "alice" {
			return errors.New("simulated proceeds-leg failure")
		}
		return nil
	}}
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx); err == nil || !strings.Contains(err.Error(), "proceeds") {
		t.Fatalf("proceeds-leg failure must abort with a proceeds error, got %v", err)
	}
	owner, _ := store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "alice" {
		t.Fatalf("aborted split must not move the token, owner=%q", owner)
	}
}

// Gap 2 (cont.): recipient == seller collapses both legs onto one address.
// RoyaltyRecipient must be SPIF-normalized, so use a real SPIF address for
// both the seller-owned token holder and the recipient.
func TestSIP721RoyaltyRecipientSelfCollapsesToOnePayee(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	self := mustSPIF(t, "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1")
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": self, "token_uri": "ipfs://cid",
		"royalty_bps": "500", "royalty_recipient": self,
	}); err != nil {
		t.Fatalf("mint with self recipient: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, self, "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	price := big.NewInt(1e18)
	ctx, ledger := testTransferCtx(price)
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": self, "to": "bob", "token_id": "1",
	}}, ctx); err != nil {
		t.Fatalf("self-recipient sale: %v", err)
	}
	// Both legs land on self: royalty (5%) + proceeds (95%) == full price in
	// a single payee entry — never double-counted, never stranded.
	if ledger.payments[self] == nil || ledger.payments[self].Cmp(price) != 0 {
		t.Fatalf("self-recipient should net the full price, got %v", ledger.payments[self])
	}
	if len(ledger.payments) != 1 {
		t.Fatalf("self-recipient sale must have exactly one payee, got %#v", ledger.payments)
	}
}

// Gap 5: legacy no-terms tokens transferred after the new code is live take
// the pass-through-full-value path and can never partially match a terms
// struct (zero-value RoyaltyBPS must read as "no terms", not "terms with a
// recipient"). A legacy token persists NO terms record (nil), not a zero
// struct; an empty-JSON corruption still decodes to 0-bps pass-through.
func TestSIP721LegacyTokenNeverMatchesTerms(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid",
	}); err != nil {
		t.Fatalf("legacy mint: %v", err)
	}
	if getSIP721Terms(store, addr, 1) != nil {
		t.Fatal("legacy token must persist NO terms record (nil)")
	}
	if _, err := callSIP721ForTest(t, store, addr, "anyone", "terms_of", map[string]string{"token_id": "1"}); err == nil {
		t.Fatal("terms_of on a legacy token must fail")
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	price := big.NewInt(1e18)
	ctx, ledger := testTransferCtx(price)
	r, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx)
	if err != nil {
		t.Fatalf("legacy sale: %v", err)
	}
	if ledger.payments["alice"] == nil || ledger.payments["alice"].Cmp(price) != 0 {
		t.Fatalf("legacy seller should receive full value, got %v", ledger.payments["alice"])
	}
	if r.Return["royalty_amount"] != "0" {
		t.Fatalf("legacy sale should report zero royalty, got %#v", r.Return)
	}
	store.SetContractStorage(addr, sip721TokenTermsKey(1), []byte(`{}`))
	if terms := getSIP721Terms(store, addr, 1); terms == nil || terms.RoyaltyBPS != 0 {
		t.Fatalf("empty terms JSON must decode to 0-bps pass-through, got %#v", terms)
	}
}

// Marketplace layer: list price, buy, escrow release — so the royalty split
// is exercised by a real sale flow, not just direct transfer_from calls in
// tests. buy settles via the SAME settleSIP721Sale path as transfer_from, so
// royalties are identical; wrong-value buys are rejected; stale listings
// (seller moved the token out via direct transfer) can never sell.
func TestSIP721ListBuySettlesRoyaltyThroughMarketplace(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "500",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	price := new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18))
	if _, err := callSIP721ForTest(t, store, addr, "alice", "list", map[string]string{"token_id": "1", "price": price.String()}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "mallory", "list", map[string]string{"token_id": "1", "price": price.String()}); err == nil {
		t.Fatal("list by non-owner must be rejected")
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "list", map[string]string{"token_id": "1", "price": "0"}); err == nil {
		t.Fatal("list with zero price must be rejected")
	}
	listing, err := callSIP721ForTest(t, store, addr, "anyone", "listing_of", map[string]string{"token_id": "1"})
	if err != nil || listing.Return["price"] != price.String() || listing.Return["seller"] != "alice" {
		t.Fatalf("listing_of: %#v err=%v", listing, err)
	}
	wrongCtx, _ := testTransferCtx(new(big.Int).Add(price, big.NewInt(1)))
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, wrongCtx); err == nil {
		t.Fatal("buy with wrong value must be rejected")
	}
	ctx, ledger := testTransferCtx(price)
	r, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, ctx)
	if err != nil {
		t.Fatalf("buy: %v", err)
	}
	wantRoyalty := big.NewInt(1e17)
	if ledger.payments["owner"] == nil || ledger.payments["owner"].Cmp(wantRoyalty) != 0 {
		t.Fatalf("buy royalty = %v, want %s", ledger.payments["owner"], wantRoyalty)
	}
	if ledger.payments["alice"] == nil || ledger.payments["alice"].Cmp(new(big.Int).Sub(price, wantRoyalty)) != 0 {
		t.Fatalf("buy proceeds = %v, want %s", ledger.payments["alice"], new(big.Int).Sub(price, wantRoyalty))
	}
	if r.Return["to"] != "bob" || r.Return["from"] != "alice" {
		t.Fatalf("buy result misreports parties: %#v", r.Return)
	}
	owner, _ := store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "bob" {
		t.Fatalf("ownerOf after buy: %q", owner)
	}
	if getSIP721Listing(store, addr, 1) != nil {
		t.Fatal("listing must clear after buy")
	}
	if _, err := callSIP721WithContext(store, addr, "carol", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, ctx); err == nil {
		t.Fatal("buy without a listing must be rejected")
	}
	if _, err := callSIP721ForTest(t, store, addr, "bob", "list", map[string]string{"token_id": "1", "price": price.String()}); err != nil {
		t.Fatalf("relist: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "mallory", "cancel", map[string]string{"token_id": "1"}); err == nil {
		t.Fatal("cancel by non-seller must be rejected")
	}
	if _, err := callSIP721ForTest(t, store, addr, "bob", "cancel", map[string]string{"token_id": "1"}); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := callSIP721WithContext(store, addr, "carol", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, ctx); err == nil {
		t.Fatal("buy after cancel must be rejected")
	}
	if _, err := callSIP721ForTest(t, store, addr, "bob", "list", map[string]string{"token_id": "1", "price": price.String()}); err != nil {
		t.Fatalf("relist2: %v", err)
	}
	ctxDirect, _ := testTransferCtx(nil)
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "bob", "to": "carol", "token_id": "1",
	}}, ctxDirect); err != nil {
		t.Fatalf("direct transfer: %v", err)
	}
	if getSIP721Listing(store, addr, 1) != nil {
		t.Fatal("direct transfer_from must clear the listing")
	}
	ctxStale, _ := testTransferCtx(price)
	if _, err := callSIP721WithContext(store, addr, "dave", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, ctxStale); err == nil {
		t.Fatal("buy against a stale listing must be rejected")
	}
}

// Rounding remainder: royalty = floor(bps * base / 10000); the remainder
// floors to the SELLER via proceeds = price - royalty. Royalty + proceeds
// must equal the escrow exactly for a non-clean-division case, proving no
// dust leaks (neither dropped nor double-counted).
func TestSIP721RoyaltyRoundingRemainderGoesToSeller(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	// 250 bps on 10001 nSPX: floor(250*10001/10000) = floor(250.025) = 250,
	// proceeds = 10001 - 250 = 9751. A single nSPX of dust floors to seller.
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "250",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := callSIP721ForTest(t, store, addr, "alice", "approve", map[string]string{"to": "bob", "token_id": "1"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	price := big.NewInt(10001)
	ctx, ledger := testTransferCtx(price)
	r, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "transfer_from", Args: map[string]string{
		"from": "alice", "to": "bob", "token_id": "1",
	}}, ctx)
	if err != nil {
		t.Fatalf("sale: %v", err)
	}
	if ledger.payments["owner"] == nil || ledger.payments["owner"].Cmp(big.NewInt(250)) != 0 {
		t.Fatalf("royalty = %v, want 250 (floor of 250.025)", ledger.payments["owner"])
	}
	if ledger.payments["alice"] == nil || ledger.payments["alice"].Cmp(big.NewInt(9751)) != 0 {
		t.Fatalf("proceeds = %v, want 9751 (remainder floors to seller)", ledger.payments["alice"])
	}
	got := new(big.Int).Add(ledger.payments["owner"], ledger.payments["alice"])
	if got.Cmp(price) != 0 {
		t.Fatalf("royalty + proceeds = %v, want exactly the %v escrow", got, price)
	}
	if r.Return["royalty_amount"] != "250" || r.Return["proceeds_amount"] != "9751" {
		t.Fatalf("receipt misreports split: %#v", r.Return)
	}
}

// Listing price update: list IS the update path — re-listing overwrites the
// price in place, atomically, within the single list tx. No cancel-then-list
// window exists in which the old price stays live and buyable; only the
// current owner may overwrite; buy at the stale price is rejected after the
// overwrite and buy at the new price succeeds.
func TestSIP721RelistOverwritesPriceAtomically(t *testing.T) {
	store := newSIP721TestStore()
	addr := deploySIP721ForTest(store, "owner")
	if _, err := callSIP721ForTest(t, store, addr, "owner", "mint", map[string]string{
		"to": "alice", "token_uri": "ipfs://cid", "royalty_bps": "500",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	oldPrice := big.NewInt(1e18)
	newPrice := big.NewInt(2e18)
	if _, err := callSIP721ForTest(t, store, addr, "alice", "list", map[string]string{"token_id": "1", "price": oldPrice.String()}); err != nil {
		t.Fatalf("list old: %v", err)
	}
	// Overwrite in place — same seller, new price, single tx.
	r, err := callSIP721ForTest(t, store, addr, "alice", "list", map[string]string{"token_id": "1", "price": newPrice.String()})
	if err != nil {
		t.Fatalf("relist: %v", err)
	}
	if r.Return["price"] != newPrice.String() {
		t.Fatalf("relist receipt should carry the new price, got %#v", r.Return)
	}
	listing, err := callSIP721ForTest(t, store, addr, "anyone", "listing_of", map[string]string{"token_id": "1"})
	if err != nil || listing.Return["price"] != newPrice.String() || listing.Return["seller"] != "alice" {
		t.Fatalf("listing_of after relist: %#v err=%v", listing, err)
	}
	// Old price is dead: a buy carrying it is rejected.
	staleCtx, _ := testTransferCtx(oldPrice)
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, staleCtx); err == nil {
		t.Fatal("buy at the stale overwritten price must be rejected")
	}
	// Non-owner cannot overwrite someone else's listing.
	if _, err := callSIP721ForTest(t, store, addr, "mallory", "list", map[string]string{"token_id": "1", "price": oldPrice.String()}); err == nil {
		t.Fatal("relist by non-owner must be rejected")
	}
	// New price works end to end.
	ctx, ledger := testTransferCtx(newPrice)
	if _, err := callSIP721WithContext(store, addr, "bob", &CallSpec{Method: "buy", Args: map[string]string{"token_id": "1"}}, ctx); err != nil {
		t.Fatalf("buy at new price: %v", err)
	}
	wantRoyalty := big.NewInt(1e17) // 5% of 2 SPX
	if ledger.payments["owner"] == nil || ledger.payments["owner"].Cmp(wantRoyalty) != 0 {
		t.Fatalf("buy royalty = %v, want %s", ledger.payments["owner"], wantRoyalty)
	}
	owner, _ := store.GetContractStorage(addr, sip721TokenOwnerKey(1))
	if string(owner) != "bob" {
		t.Fatalf("ownerOf after buy: %q", owner)
	}
}
