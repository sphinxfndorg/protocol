// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
)

func mintSIP721(store Store, address, caller, to, tokenURI, mintID string, terms *SIP721TokenTerms) (uint64, error) {
	info, err := getSIP721Info(store, address)
	if err != nil {
		return 0, err
	}
	if caller != info.Owner {
		return 0, errors.New("mint requires collection owner")
	}
	tokenID := info.NextTokenID
	if tokenID == 0 {
		tokenID = 1
	}
	info.NextTokenID = tokenID + 1
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return 0, err
	}
	store.SetContractStorage(address, sip721InfoKey(), infoJSON)
	store.SetContractStorage(address, sip721TokenOwnerKey(tokenID), []byte(to))
	store.SetContractStorage(address, sip721TokenURIKey(tokenID), []byte(tokenURI))
	if terms != nil {
		// Freeze the embedded economics at mint. Creator is the mint caller
		// (already authenticated as the collection owner above) and becomes the
		// default payout recipient for royalties and license fees.
		terms.Creator = caller
		if terms.RoyaltyRecipient == "" {
			terms.RoyaltyRecipient = caller
		}
		termsJSON, err := json.Marshal(terms)
		if err != nil {
			return 0, err
		}
		store.SetContractStorage(address, sip721TokenTermsKey(tokenID), termsJSON)
	}
	if mintID != "" {
		if existing, err := store.GetContractStorage(address, sip721MintTokenKey(mintID)); err == nil && len(existing) > 0 {
			return 0, fmt.Errorf("mint_id %s already anchored as token %s", mintID, string(existing))
		}
		store.SetContractStorage(address, sip721TokenMintKey(tokenID), []byte(mintID))
		store.SetContractStorage(address, sip721MintTokenKey(mintID), []byte(strconv.FormatUint(tokenID, 10)))
	}
	return tokenID, nil
}

// transferSIP721 moves a token and, when the transaction carried value, settles
// it: the sale price (tx.Amount, escrowed at the contract address by the
// executor) is split into the creator's resale royalty and the seller's
// proceeds. The split is enforced here — deterministically, at every node — not
// by any wallet or marketplace. royalty is returned for the execution result
// (nil when no value or no royalty terms apply).
//
// Caller authorization mirrors ERC-721: the owner, or the address the owner
// approved. A buyer-initiated sale is the approved flow: the seller calls
// approve(buyer, tokenId), the buyer then signs transfer_from carrying the
// price — the buyer is the payer, the escrow settles creator + seller, and the
// token lands with the buyer. There is deliberately NO "caller == to" payer
// exemption: allowing an unapproved address to escrow value for someone else's
// token would let anyone force-purchase any listed metadata at 1 nSPX.
func transferSIP721(store Store, address, caller, from, to string, tokenID uint64, salePrice, priceFloor *big.Int, transfer func(string, *big.Int) error) (royalty *big.Int, recipient string, err error) {
	royalty = big.NewInt(0)
	owner := getSIP721Owner(store, address, tokenID)
	if owner == "" {
		return royalty, "", fmt.Errorf("token %d does not exist", tokenID)
	}
	if owner != from {
		return royalty, "", fmt.Errorf("transfer_from: token %d owned by %s, not %s", tokenID, owner, from)
	}
	if caller != owner {
		approved, _ := store.GetContractStorage(address, sip721ApprovalKey(tokenID))
		if string(approved) != caller {
			return royalty, "", fmt.Errorf("transfer_from: caller %s is neither owner nor approved", caller)
		}
	}

// ── Resale royalty enforcement ──────────────────────────────────────────
	// The executor already moved the buyer's tx.Amount into this contract's
	// escrow before this call ran, so the payout total exactly equals the sale
	// price and the contract nets zero — the value only ever reaches the
	// creator and the seller.
	settled, settledRecipient, settleErr := settleSIP721Sale(store, address, from, tokenID, salePrice, priceFloor, transfer)
	if settleErr != nil {
		return settled, settledRecipient, settleErr
	}
	royalty = settled
	recipient = settledRecipient

	store.SetContractStorage(address, sip721TokenOwnerKey(tokenID), []byte(to))
	store.SetContractStorage(address, sip721ApprovalKey(tokenID), []byte{})
	clearSIP721Listing(store, address, tokenID)
	return royalty, recipient, nil
}

// settleSIP721Sale splits an escrowed sale price into the creator's resale
// royalty and the seller's proceeds. It is the single settlement path shared
// by direct transfer_from sales and marketplace buy calls, so both flows pay
// identical royalties. Ownership movement and authorization stay with the
// caller: transfer_from enforces owner/approved, buy enforces the listing.
// Ownership is NOT moved here.
func settleSIP721Sale(store Store, address, seller string, tokenID uint64, salePrice, priceFloor *big.Int, transfer func(string, *big.Int) error) (royalty *big.Int, recipient string, err error) {
	royalty = big.NewInt(0)
	proceeds := new(big.Int)
	if salePrice != nil && salePrice.Sign() > 0 {
		terms := getSIP721Terms(store, address, tokenID)
		// Defense in depth: mint-time parsing already rejects bps > 10000 at
		// every admission path, but storage is the trust boundary — a
		// corrupted terms record must fail closed, never mint a >100% royalty.
		if terms != nil && terms.RoyaltyBPS > 10000 {
			return royalty, "", fmt.Errorf("token %d has invalid royalty_bps %d (max 10000)", tokenID, terms.RoyaltyBPS)
		}
		if terms != nil && terms.RoyaltyBPS > 0 {
			base := salePrice
			if priceFloor != nil && priceFloor.Cmp(base) > 0 {
				base = priceFloor // floor makes dust-price settlement pay real royalties
			}
			// Rounding: royalty is floor(bps * base / 10000); any remainder
			// floors to the SELLER via proceeds = salePrice - royalty below.
			// Royalty + proceeds therefore always equals the escrow exactly —
			// dust is never dropped, never double-counted, and total supply
			// is untouched (pure redistribution of the escrowed price).
			royalty.Mul(base, big.NewInt(int64(terms.RoyaltyBPS)))
			royalty.Div(royalty, big.NewInt(10000))
			if royalty.Cmp(salePrice) > 0 {
				royalty.Set(salePrice) // cap at the escrow so royalty+proceeds never exceed the price
			}
			recipient = terms.RoyaltyRecipient
			if recipient == "" {
				recipient = terms.Creator
			}
			if recipient == "" {
				return royalty, "", fmt.Errorf("token %d has no royalty recipient", tokenID)
			}
			proceeds.Sub(salePrice, royalty)
			if transfer != nil {
				// Skip zero-value legs: the kernel transfer hook rejects
				// non-positive amounts, and a dust sale at a small bps can
				// legally round the royalty (or a 100% royalty the proceeds)
				// down to zero. Royalty + proceeds still sum to the price.
				if royalty.Sign() > 0 {
					if err := transfer(recipient, royalty); err != nil {
						return royalty, recipient, fmt.Errorf("royalty: %w", err)
					}
				}
				if proceeds.Sign() > 0 {
					if err := transfer(seller, proceeds); err != nil {
						return royalty, recipient, fmt.Errorf("proceeds: %w", err)
					}
				}
			}
		} else {
			// Legacy token (no terms) or explicit 0-bps terms: whoever sold it
			// keeps the full value. Both paths are identical by design — 0%
			// means "no royalty", never "terms present but unpaid".
			proceeds.Set(salePrice)
			if transfer != nil {
				if err := transfer(seller, proceeds); err != nil {
					return royalty, recipient, fmt.Errorf("proceeds: %w", err)
				}
			}
		}
	}
	return royalty, recipient, nil
}

func approveSIP721(store Store, address, caller, approved string, tokenID uint64) error {
	owner := getSIP721Owner(store, address, tokenID)
	if owner == "" {
		return fmt.Errorf("token %d does not exist", tokenID)
	}
	if caller != owner {
		return errors.New("approve requires token owner")
	}
	store.SetContractStorage(address, sip721ApprovalKey(tokenID), []byte(approved))
	return nil
}

func getSIP721Owner(store Store, address string, tokenID uint64) string {
	data, err := store.GetContractStorage(address, sip721TokenOwnerKey(tokenID))
	if err != nil || len(data) == 0 {
		return ""
	}
	return string(data)
}

func getSIP721Terms(store Store, address string, tokenID uint64) *SIP721TokenTerms {
	data, err := store.GetContractStorage(address, sip721TokenTermsKey(tokenID))
	if err != nil || len(data) == 0 {
		return nil
	}
	var terms SIP721TokenTerms
	if err := json.Unmarshal(data, &terms); err != nil {
		return nil
	}
	return &terms
}

// getSIP721Licensee returns the single active licensee of a token
// ("" = unlicensed).
func getSIP721Licensee(store Store, address string, tokenID uint64) string {
	data, err := store.GetContractStorage(address, sip721TokenLicenseeKey(tokenID))
	if err != nil || len(data) == 0 {
		return ""
	}
	return string(data)
}

// setSIP721Licensee grants the single active license to licensee. Single-issue
// by design: one dataset, one licensed party at a time — the simplest auditable
// model for the "an AI firm paid to train on this" case.
func setSIP721Licensee(store Store, address string, tokenID uint64, licensee string) error {
	if existing := getSIP721Licensee(store, address, tokenID); existing != "" {
		return fmt.Errorf("token %d already licensed to %s (single-issue; revoke before re-licensing)", tokenID, existing)
	}
	store.SetContractStorage(address, sip721TokenLicenseeKey(tokenID), []byte(licensee))
	return nil
}

func clearSIP721Licensee(store Store, address string, tokenID uint64) {
	store.SetContractStorage(address, sip721TokenLicenseeKey(tokenID), []byte{})
}

// ── Minimal marketplace / listing layer ───────────────────────────────────
// The royalty split above was previously only reachable through direct
// transfer_from calls in tests — payment plumbing with nothing to plumb.
// list / buy / cancel exercise it through a real sale flow:
//
//	list:   the owner posts an asking price (nSPX, positive decimal).
//	buy:    the buyer signs a buy carrying exactly the asking price; the
//	         runtime settles escrow → royalty + seller proceeds via the same
//	         settleSIP721Sale path as transfer_from, then moves the token.
//	cancel: the owner (or collection owner) withdraws the listing.
//
// A listing is advisory consensus state, not custody: it never moves the
// token, and any direct transfer_from clears it, so a stale listing can never
// sell a token the seller no longer owns. Re-listing overwrites the price in
// place, atomically, within the single list tx — there is no update_price
// method because list IS the update path: no cancel-then-list window exists
// in which the old price stays live and buyable (each tx applies or aborts
// whole, and only the current owner may overwrite).
func setSIP721Listing(store Store, address string, tokenID uint64, listing *SIP721Listing) error {
	listingJSON, err := json.Marshal(listing)
	if err != nil {
		return err
	}
	store.SetContractStorage(address, sip721TokenListingKey(tokenID), listingJSON)
	return nil
}

func getSIP721Listing(store Store, address string, tokenID uint64) *SIP721Listing {
	data, err := store.GetContractStorage(address, sip721TokenListingKey(tokenID))
	if err != nil || len(data) == 0 {
		return nil
	}
	var listing SIP721Listing
	if err := json.Unmarshal(data, &listing); err != nil {
		return nil
	}
	if listing.Seller == "" || listing.Price == "" {
		return nil
	}
	return &listing
}

func clearSIP721Listing(store Store, address string, tokenID uint64) {
	store.SetContractStorage(address, sip721TokenListingKey(tokenID), []byte{})
}

func getSIP721Info(store Store, address string) (*SIP721Info, error) {
	data, err := store.GetContractStorage(address, sip721InfoKey())
	if err != nil {
		return nil, err
	}
	var info SIP721Info
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func parseSIP721TokenID(value string) (uint64, error) {
	v := ""
	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\n' {
			continue
		}
		v += string(r)
	}
	if v == "" {
		return 0, errors.New("missing token_id")
	}
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid token_id: %s", value)
	}
	return id, nil
}
