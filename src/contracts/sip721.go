// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SIP721Info struct {
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	Owner       string `json:"owner"`
	NextTokenID uint64 `json:"next_token_id"`
}

func sip721InfoKey() string { return "sip721:info" }
func sip721TokenOwnerKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:owner", tokenID)
}
func sip721TokenURIKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:uri", tokenID)
}
func sip721TokenMintKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:mint", tokenID)
}
func sip721MintTokenKey(mintID string) string { return "sip721:mint:" + mintID }
func sip721ApprovalKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:approval:%d", tokenID)
}
func sip721TokenTermsKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:terms", tokenID)
}
func sip721TokenLicenseeKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:licensee", tokenID)
}
func sip721TokenListingKey(tokenID uint64) string {
	return fmt.Sprintf("sip721:token:%d:listing", tokenID)
}

// SIP721Listing is the minimal marketplace record: the seller's asking price
// in nSPX (decimal string so arbitrary magnitudes survive JSON). Stored per
// token, set by list, cleared by buy / cancel / any direct transfer_from.
type SIP721Listing struct {
	Seller string `json:"seller"`
	Price  string `json:"price_nspx"`
}

// SIP721TokenTerms are the embedded-economics terms frozen at mint time and
// enforced by the native runtime at consensus:
//
//   - RoyaltyBPS: resale royalty on transfer_from. Every sale splits the value
//     carried by the buying transaction (tx.Amount): royalty_bps/10000 goes to
//     the creator forever, the rest to the seller.
//   - UsageFeeNSPX: per licensed-access micro-fee paid to the creator via
//     purchase_license (a kernel-enforced payment + entitlement record — the
//     license receipt, not a bytes-gate over off-chain IPFS reads).
//
// Terms are IMMUTABLE. A post-mint set_terms would let the current owner
// rewrite the economics of a token someone already bought or listed, which is
// exactly the capture vector ERC-721 royalties are notorious for. The only
// mutable record is the single active licensee (revocable by the creator).
type SIP721TokenTerms struct {
	Creator          string `json:"creator"`                     // mint caller; default royalty/usage recipient
	RoyaltyBPS       uint64 `json:"royalty_bps"`                 // 0..10000 basis points of the sale value
	RoyaltyRecipient string `json:"royalty_recipient,omitempty"` // "" = Creator
	UsageFeeNSPX     string `json:"usage_fee_nspx,omitempty"`    // per licensed-access fee in nSPX; "" = no licenses
}

func initSIP721(store Store, address, sender string, spec *DeploySpec) error {
	owner := strings.TrimSpace(spec.Owner)
	if owner == "" {
		owner = sender
	}
	info := &SIP721Info{
		Name:        strings.TrimSpace(spec.Name),
		Symbol:      strings.ToUpper(strings.TrimSpace(spec.Symbol)),
		Owner:       owner,
		NextTokenID: 1,
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return err
	}
	store.SetContractStorage(address, sip721InfoKey(), infoJSON)
	return nil
}
