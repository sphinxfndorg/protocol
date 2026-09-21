// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"encoding/json"
	"strings"
	"testing"
)

// The stub reproduces the node's storage layout (contracts/sip721.go,
// contracts/sip20.go) and fails any key it does not hold, the way the node
// answers a missing slot.
const (
	stubCollection = "SPIF 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111"
	stubCaller     = "SPIF 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222 2222"
	stubSeller     = "SPIF 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333 3333"
	stubCreator    = "SPIF 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444 4444"
	stubTermsJSON  = `{"creator":"` + stubCreator + `","royalty_bps":500,"royalty_recipient":"","usage_fee_nspx":"25"}`
)

func sip721ReadOpts(client *stubClient) *CallOpts {
	client.standard = "sip721"
	return &CallOpts{Client: client, NodeAddr: stubNodeAddr, From: stubCaller}
}

func sip20ReadOpts(client *stubClient) *CallOpts {
	client.standard = "sip20"
	return &CallOpts{Client: client, NodeAddr: stubNodeAddr, From: stubCaller}
}

// assertStorageRead checks the binding asked the node for the storage slot the
// node's own method implementation reads, which is what proves the right ABI
// method ran (the method itself executes against those slots).
func assertStorageRead(t *testing.T, client *stubClient, want string) {
	t.Helper()
	for _, call := range client.calls {
		if call.method != "getcontractstorage" || len(call.params) < 2 {
			continue
		}
		if key, _ := call.params[1].(string); key == want {
			return
		}
	}
	t.Fatalf("storage slot %q was never read; calls = %#v", want, client.calls)
}

func TestOwnerOfHappyPath(t *testing.T) {
	client := &stubClient{storage: map[string]string{"sip721:token:4:owner": stubSeller}}

	owner, err := SIP721Contract{Address: stubCollection}.OwnerOf(sip721ReadOpts(client), 4)
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if owner != stubSeller {
		t.Fatalf("owner = %q, want %q", owner, stubSeller)
	}
	assertStorageRead(t, client, "sip721:token:4:owner")
}

func TestOwnerOfSurfacesNodeNotFound(t *testing.T) {
	_, err := SIP721Contract{Address: stubCollection}.OwnerOf(sip721ReadOpts(&stubClient{}), 9)
	if err == nil || !strings.Contains(err.Error(), "token 9 does not exist") {
		t.Fatalf("err = %v, want the node's token-not-found error", err)
	}
}

func TestTokenURIHappyPathAndNotFound(t *testing.T) {
	client := &stubClient{storage: map[string]string{"sip721:token:4:uri": "ipfs://QmStub"}}

	uri, err := SIP721Contract{Address: stubCollection}.TokenURI(sip721ReadOpts(client), 4)
	if err != nil {
		t.Fatalf("TokenURI: %v", err)
	}
	if uri != "ipfs://QmStub" {
		t.Fatalf("uri = %q", uri)
	}
	assertStorageRead(t, client, "sip721:token:4:uri")

	_, err = SIP721Contract{Address: stubCollection}.TokenURI(sip721ReadOpts(&stubClient{}), 4)
	if err == nil || !strings.Contains(err.Error(), "token 4 does not exist") {
		t.Fatalf("err = %v, want the node's token-not-found error", err)
	}
}

func TestTokenIDOfMintHappyPathAndNotFound(t *testing.T) {
	client := &stubClient{storage: map[string]string{"sip721:mint:mint-abc": "7"}}

	tokenID, err := SIP721Contract{Address: stubCollection}.TokenIDOfMint(sip721ReadOpts(client), "mint-abc")
	if err != nil {
		t.Fatalf("TokenIDOfMint: %v", err)
	}
	if tokenID != 7 {
		t.Fatalf("tokenID = %d, want 7", tokenID)
	}
	assertStorageRead(t, client, "sip721:mint:mint-abc")

	_, err = SIP721Contract{Address: stubCollection}.TokenIDOfMint(sip721ReadOpts(&stubClient{}), "mint-abc")
	if err == nil || !strings.Contains(err.Error(), "mint_id mint-abc not anchored on this contract") {
		t.Fatalf("err = %v, want the node's mint_id-not-anchored error", err)
	}
}

func TestTokenIDOfMintRejectsGarbageTokenID(t *testing.T) {
	client := &stubClient{storage: map[string]string{"sip721:mint:mint-abc": "not-a-number"}}

	_, err := SIP721Contract{Address: stubCollection}.TokenIDOfMint(sip721ReadOpts(client), "mint-abc")
	if err == nil || !strings.Contains(err.Error(), "invalid token_id") {
		t.Fatalf("err = %v, want a conversion error", err)
	}
}

func TestTermsOfHappyPathAndNotFound(t *testing.T) {
	client := &stubClient{storage: map[string]string{
		"sip721:token:4:terms":    stubTermsJSON,
		"sip721:token:4:licensee": stubSeller,
	}}

	terms, err := SIP721Contract{Address: stubCollection}.TermsOf(sip721ReadOpts(client), 4)
	if err != nil {
		t.Fatalf("TermsOf: %v", err)
	}
	if terms.TokenID != 4 || terms.RoyaltyBPS != 500 || terms.UsageFeeNSPX != "25" || terms.Licensee != stubSeller {
		t.Fatalf("terms = %#v", terms)
	}
	// royalty_recipient is unset on this token, so the node falls back to the
	// creator — the binding reports what the node reported, not "".
	if terms.Creator != stubCreator || terms.RoyaltyRecipient != stubCreator {
		t.Fatalf("terms = %#v, want royalty_recipient defaulted to creator", terms)
	}

	_, err = SIP721Contract{Address: stubCollection}.TermsOf(sip721ReadOpts(&stubClient{}), 4)
	if err == nil || !strings.Contains(err.Error(), "token 4 has no embedded terms") {
		t.Fatalf("err = %v, want the node's no-terms error", err)
	}
}

func TestListingOfHappyPathAndNotListed(t *testing.T) {
	listingJSON, err := json.Marshal(struct {
		Seller string `json:"seller"`
		Price  string `json:"price_nspx"`
	}{Seller: stubSeller, Price: "1200"})
	if err != nil {
		t.Fatalf("marshal listing: %v", err)
	}
	client := &stubClient{storage: map[string]string{
		"sip721:token:4:owner":   stubSeller,
		"sip721:token:4:listing": string(listingJSON),
	}}

	seller, price, err := SIP721Contract{Address: stubCollection}.ListingOf(sip721ReadOpts(client), 4)
	if err != nil {
		t.Fatalf("ListingOf: %v", err)
	}
	if seller != stubSeller || price != "1200" {
		t.Fatalf("seller/price = %q/%q", seller, price)
	}
	assertStorageRead(t, client, "sip721:token:4:listing")

	unlisted := &stubClient{storage: map[string]string{"sip721:token:4:owner": stubSeller}}
	_, _, err = SIP721Contract{Address: stubCollection}.ListingOf(sip721ReadOpts(unlisted), 4)
	if err == nil || !strings.Contains(err.Error(), "token 4 is not listed") {
		t.Fatalf("err = %v, want the node's not-listed error", err)
	}
}

func TestBalanceOfHappyPathAndMalformed(t *testing.T) {
	balanceKey := "sip20:balance:" + stubCaller
	client := &stubClient{storage: map[string]string{balanceKey: "5000000000000000000"}}

	balance, err := SIP20Contract{Address: stubCollection}.BalanceOf(sip20ReadOpts(client), stubCaller)
	if err != nil {
		t.Fatalf("BalanceOf: %v", err)
	}
	if balance.String() != "5000000000000000000" {
		t.Fatalf("balance = %s", balance)
	}
	assertStorageRead(t, client, balanceKey)

	malformed := &stubClient{storage: map[string]string{balanceKey: "1e18"}}
	// The node itself folds a malformed stored balance to zero
	// (contracts.getSIP20Balance), so the malformed case is asserted on the
	// binding's decoder: a bad wire value must never come back as 0.
	if _, err := (SIP20Contract{Address: stubCollection}).BalanceOf(sip20ReadOpts(malformed), stubCaller); err != nil {
		t.Fatalf("err = %v, want the node's own zero fold to be passed through", err)
	}
	if _, err := resultDecimal(map[string]string{"balance": "1e18"}, "balance_of", "balance"); err == nil || !strings.Contains(err.Error(), "invalid balance") {
		t.Fatalf("err = %v, want a malformed-balance error, not a zero balance", err)
	}
}

// A node that answers without the field the binding needs is a protocol-level
// surprise: the read must fail loudly instead of returning a zero value.
func TestReadResultsRequireTheirFields(t *testing.T) {
	if _, err := resultKey(map[string]string{}, "owner_of", "owner"); err == nil || !strings.Contains(err.Error(), `node response missing "owner"`) {
		t.Fatalf("err = %v, want a missing-key error", err)
	}
	if _, err := resultUint64(map[string]string{"token_id": "7x"}, "token_id_of_mint", "token_id"); err == nil || !strings.Contains(err.Error(), "invalid token_id") {
		t.Fatalf("err = %v, want an invalid-token_id error", err)
	}
	if _, err := resultUint64(map[string]string{}, "terms_of", "royalty_bps"); err == nil || !strings.Contains(err.Error(), `missing "royalty_bps"`) {
		t.Fatalf("err = %v, want a missing-royalty_bps error", err)
	}
	if _, err := resultDecimal(map[string]string{}, "balance_of", "balance"); err == nil || !strings.Contains(err.Error(), `missing "balance"`) {
		t.Fatalf("err = %v, want a missing-balance error", err)
	}
}

// info reads the same slots the node's own handler does: sip721:info for the
// metadata, plus the live next_token_id counter, which is the only
// authoritative "next token" answer.
func TestSIP721InfoHappyPath(t *testing.T) {
	client := &stubClient{storage: map[string]string{"sip721:info": `{"name":"Collection","symbol":"COLL","owner":"` + stubCreator + `","next_token_id":5}`}}

	info, err := SIP721Contract{Address: stubCollection}.Info(sip721ReadOpts(client))
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info != (SIP721Info{Name: "Collection", Symbol: "COLL", Owner: stubCreator, NextTokenID: 5}) {
		t.Fatalf("info = %#v", info)
	}
	assertStorageRead(t, client, "sip721:info")
}

func TestSIP20InfoHappyPath(t *testing.T) {
	owner := stubCreator
	client := &stubClient{storage: map[string]string{
		"sip20:info":         `{"name":"Token","symbol":"TOK","decimals":18,"owner":"` + owner + `"}`,
		"sip20:total_supply": "21000000000000000000000000",
	}}

	info, err := SIP20Contract{Address: stubCollection}.Info(sip20ReadOpts(client))
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "Token" || info.Symbol != "TOK" || info.Decimals != 18 || info.Owner != owner {
		t.Fatalf("info = %#v", info)
	}
	// A supply above int64 must survive the decimal-string wire format.
	if info.TotalSupply.String() != "21000000000000000000000000" {
		t.Fatalf("total supply = %s", info.TotalSupply)
	}
	assertStorageRead(t, client, "sip20:info")
	assertStorageRead(t, client, "sip20:total_supply")
}

// An address the node has no contract at answers no info slot at all
// (getSIP721Info / getSIP20Info surface the store error), so Info must fail
// loudly rather than hand back a zero-valued metadata struct.
func TestInfoOnUnknownContractIsAnError(t *testing.T) {
	if _, err := (SIP721Contract{Address: stubCollection}).Info(sip721ReadOpts(&stubClient{})); err == nil {
		t.Fatal("SIP721 Info on an unknown contract = no error, want a load failure")
	}
	if _, err := (SIP20Contract{Address: stubCollection}).Info(sip20ReadOpts(&stubClient{})); err == nil {
		t.Fatal("SIP20 Info on an unknown contract = no error, want a load failure")
	}
}

// An owner the token has never seen is a legitimate zero on this node
// (getSIP20Balance treats a missing slot as zero), so the binding must not
// invent an error there — only a malformed value is an error.
func TestBalanceOfUnknownOwnerIsZero(t *testing.T) {
	balance, err := SIP20Contract{Address: stubCollection}.BalanceOf(sip20ReadOpts(&stubClient{}), stubCaller)
	if err != nil {
		t.Fatalf("BalanceOf: %v", err)
	}
	if balance.Sign() != 0 {
		t.Fatalf("balance = %s, want 0", balance)
	}
}
