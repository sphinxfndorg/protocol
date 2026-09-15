// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
)

func callSIP721(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	return callSIP721WithContext(store, address, caller, call, nil)
}

// callSIP721WithContext executes a SIP-721 call with the kernel's value
// context when present. Only the consensus entry point (core's
// executeContractTransaction) supplies one; read-only callers that never move
// balance pass nil.
func callSIP721WithContext(store Store, address, caller string, call *CallSpec, ctx *NativeCallContext) (*ExecutionResult, error) {
	switch call.Method {
	case "mint":
		to := strings.TrimSpace(call.Args["to"])
		tokenURI := strings.TrimSpace(call.Args["token_uri"])
		if tokenURI == "" {
			tokenURI = strings.TrimSpace(call.Args["uri"])
		}
		mintID := strings.TrimSpace(call.Args["mint_id"])
		if to == "" {
			return nil, errors.New("missing mint recipient")
		}
		if tokenURI == "" {
			return nil, errors.New("missing token_uri: mint requires a real IPFS tokenURI")
		}
		terms, err := parseSIP721MintTerms(call.Args)
		if err != nil {
			return nil, err
		}
		tokenID, err := mintSIP721(store, address, caller, to, tokenURI, mintID, terms)
		if err != nil {
			return nil, err
		}
		ret := map[string]string{
			"method":    "mint",
			"to":        to,
			"token_id":  strconv.FormatUint(tokenID, 10),
			"token_uri": tokenURI,
			"mint_id":   mintID,
		}
		if terms != nil {
			ret["royalty_bps"] = strconv.FormatUint(terms.RoyaltyBPS, 10)
			if terms.RoyaltyRecipient != "" {
				ret["royalty_recipient"] = terms.RoyaltyRecipient
			}
			if terms.UsageFeeNSPX != "" {
				ret["usage_fee"] = terms.UsageFeeNSPX
			}
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: ret}, nil
	case "transfer_from":
		from := strings.TrimSpace(call.Args["from"])
		to := strings.TrimSpace(call.Args["to"])
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if from == "" || to == "" {
			return nil, errors.New("missing transfer_from addresses")
		}
		var salePrice, priceFloor *big.Int
		var transfer func(string, *big.Int) error
		if ctx != nil {
			salePrice = ctx.Value
			priceFloor = ctx.PriceFloor
			transfer = ctx.Transfer
		}
		royalty, recipient, err := transferSIP721(store, address, caller, from, to, tokenID, salePrice, priceFloor, transfer)
		if err != nil {
			return nil, err
		}
		ret := map[string]string{
			"method":   "transfer_from",
			"from":     from,
			"to":       to,
			"token_id": strconv.FormatUint(tokenID, 10),
		}
		if salePrice != nil && salePrice.Sign() > 0 {
			ret["sale_value"] = salePrice.String()
			ret["royalty_amount"] = royalty.String()
			ret["proceeds_amount"] = new(big.Int).Sub(salePrice, royalty).String()
			if royalty.Sign() > 0 {
				ret["royalty_recipient"] = recipient
			}
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: ret}, nil
	case "approve":
		approved := strings.TrimSpace(call.Args["to"])
		if approved == "" {
			approved = strings.TrimSpace(call.Args["approved"])
		}
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if approved == "" {
			return nil, errors.New("missing approve address")
		}
		if err := approveSIP721(store, address, caller, approved, tokenID); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "approve",
			"approved": approved,
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "owner_of":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		owner := getSIP721Owner(store, address, tokenID)
		if owner == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "owner_of",
			"owner":    owner,
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "token_uri":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		uri, err := store.GetContractStorage(address, sip721TokenURIKey(tokenID))
		if err != nil || len(uri) == 0 {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":    "token_uri",
			"token_uri": string(uri),
			"token_id":  strconv.FormatUint(tokenID, 10),
		}}, nil
	case "token_id_of_mint":
		mintID := strings.TrimSpace(call.Args["mint_id"])
		if mintID == "" {
			return nil, errors.New("missing mint_id")
		}
		raw, err := store.GetContractStorage(address, sip721MintTokenKey(mintID))
		if err != nil || len(raw) == 0 {
			return nil, fmt.Errorf("mint_id %s not anchored on this contract", mintID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "token_id_of_mint",
			"mint_id":  mintID,
			"token_id": string(raw),
		}}, nil
	case "purchase_license":
		// Single-issue licensing: one dataset, one active licensee.
		//
		// Same-block revoke/purchase ordering is deterministic: block txs are
		// caller-sorted and nonce-ordered, applyTransactions executes TxsList
		// strictly sequentially, and every write is buffered in StateDB until
		// Commit. So a revoke and a purchase for the same licensee never
		// interleave — whichever runs first wins the slot and the second
		// aborts ("already licensed" / "no active license"), rolling back
		// atomically with the block's other writes.
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		licensee := strings.TrimSpace(call.Args["licensee"])
		if licensee == "" {
			licensee = caller
		}
		if getSIP721Owner(store, address, tokenID) == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		terms := getSIP721Terms(store, address, tokenID)
		if terms == nil || terms.UsageFeeNSPX == "" {
			return nil, fmt.Errorf("token %d has no license terms; the creator set no usage fee", tokenID)
		}
		fee, err := parseAmount(terms.UsageFeeNSPX)
		if err != nil {
			return nil, fmt.Errorf("token %d has an invalid stored usage_fee: %w", tokenID, err)
		}
		// ── License fee enforcement ─────────────────────────────────────────
		// The licensee signs a transaction carrying exactly the posted fee; the
		// executor escrows it at the contract, and this runtime forwards it to
		// the creator and records the entitlement. This is enforcement of
		// payment + issuance — the license RECEIPT. Physical reads of the pinned
		// bytes are governed off-chain by the terms embedded in the anchored
		// document (the kernel cannot observe IPFS reads).
		if ctx == nil || ctx.Value == nil || ctx.Value.Cmp(fee) != 0 {
			carried := "none"
			if ctx != nil && ctx.Value != nil {
				carried = ctx.Value.String()
			}
			return nil, fmt.Errorf("purchase_license requires exactly %s nSPX, tx carried %s", fee.String(), carried)
		}
		recipient := terms.RoyaltyRecipient
		if recipient == "" {
			recipient = terms.Creator
		}
		// ctx.Transfer is non-nil here: ctx != nil was verified above, and
		// the native executor always supplies a non-nil Transfer hook for
		// value-carrying txs (the early return on ctx == nil / ctx.Value == nil
		// above guarantees we only reach this path for escrow-backed calls).
		if err := ctx.Transfer(recipient, fee); err != nil {
			return nil, fmt.Errorf("license fee transfer: %w", err)
		}
		if err := setSIP721Licensee(store, address, tokenID, licensee); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":    "purchase_license",
			"token_id":  strconv.FormatUint(tokenID, 10),
			"licensee":  licensee,
			"fee":       fee.String(),
			"recipient": recipient,
		}}, nil
	case "revoke_license":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if getSIP721Owner(store, address, tokenID) == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		info, err := getSIP721Info(store, address)
		if err != nil {
			return nil, err
		}
		terms := getSIP721Terms(store, address, tokenID)
		if terms == nil {
			return nil, fmt.Errorf("token %d has no license terms", tokenID)
		}
		if caller != info.Owner && caller != terms.Creator {
			return nil, errors.New("revoke_license requires the collection owner or the token creator")
		}
		if getSIP721Licensee(store, address, tokenID) == "" {
			return nil, fmt.Errorf("token %d has no active license", tokenID)
		}
		clearSIP721Licensee(store, address, tokenID)
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "revoke_license",
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "list":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		rawPrice := strings.TrimSpace(call.Args["price"])
		if rawPrice == "" {
			rawPrice = strings.TrimSpace(call.Args["price_nspx"])
		}
		price, err := parseAmount(rawPrice)
		if err != nil || price.Sign() <= 0 {
			return nil, fmt.Errorf("invalid list price: %q (positive decimal nSPX required)", rawPrice)
		}
		owner := getSIP721Owner(store, address, tokenID)
		if owner == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		if caller != owner {
			return nil, errors.New("list requires the token owner")
		}
		if err := setSIP721Listing(store, address, tokenID, &SIP721Listing{Seller: owner, Price: price.String()}); err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "list",
			"token_id": strconv.FormatUint(tokenID, 10),
			"seller":   owner,
			"price":    price.String(),
		}}, nil
	case "buy":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		owner := getSIP721Owner(store, address, tokenID)
		if owner == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		listing := getSIP721Listing(store, address, tokenID)
		if listing == nil {
			return nil, fmt.Errorf("token %d is not listed", tokenID)
		}
		if owner != listing.Seller {
			// The seller moved the token out from under the listing (direct
			// transfer_from clears listings exactly so this can be detected).
			clearSIP721Listing(store, address, tokenID)
			return nil, fmt.Errorf("token %d listing is stale: seller %s no longer owns it", tokenID, listing.Seller)
		}
		if caller == owner {
			return nil, errors.New("buy: seller cannot buy their own listing")
		}
		ask, err := parseAmount(listing.Price)
		if err != nil || ask.Sign() <= 0 {
			return nil, fmt.Errorf("token %d has an invalid stored list price: %w", tokenID, err)
		}
		if ctx == nil || ctx.Value == nil || ctx.Value.Cmp(ask) != 0 {
			carried := "none"
			if ctx != nil && ctx.Value != nil {
				carried = ctx.Value.String()
			}
			return nil, fmt.Errorf("buy requires exactly %s nSPX, tx carried %s", ask.String(), carried)
		}
		// ctx.Transfer is non-nil here (proven immediately above).
		royalty, recipient, err := settleSIP721Sale(store, address, owner, tokenID, ask, ctx.PriceFloor, ctx.Transfer)
		if err != nil {
			return nil, err
		}
		store.SetContractStorage(address, sip721TokenOwnerKey(tokenID), []byte(caller))
		store.SetContractStorage(address, sip721ApprovalKey(tokenID), []byte{})
		clearSIP721Listing(store, address, tokenID)
		ret := map[string]string{
			"method":          "buy",
			"token_id":        strconv.FormatUint(tokenID, 10),
			"from":            owner,
			"to":              caller,
			"sale_value":      ask.String(),
			"royalty_amount":  royalty.String(),
			"proceeds_amount": new(big.Int).Sub(ask, royalty).String(),
		}
		if royalty.Sign() > 0 {
			ret["royalty_recipient"] = recipient
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: ret}, nil
	case "cancel":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if getSIP721Owner(store, address, tokenID) == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		listing := getSIP721Listing(store, address, tokenID)
		if listing == nil {
			return nil, fmt.Errorf("token %d is not listed", tokenID)
		}
		info, err := getSIP721Info(store, address)
		if err != nil {
			return nil, err
		}
		if caller != listing.Seller && caller != info.Owner {
			return nil, errors.New("cancel requires the listing seller or the collection owner")
		}
		clearSIP721Listing(store, address, tokenID)
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "cancel",
			"token_id": strconv.FormatUint(tokenID, 10),
		}}, nil
	case "listing_of":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		if getSIP721Owner(store, address, tokenID) == "" {
			return nil, fmt.Errorf("token %d does not exist", tokenID)
		}
		listing := getSIP721Listing(store, address, tokenID)
		if listing == nil {
			return nil, fmt.Errorf("token %d is not listed", tokenID)
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":   "listing_of",
			"token_id": strconv.FormatUint(tokenID, 10),
			"seller":   listing.Seller,
			"price":    listing.Price,
		}}, nil
	case "terms_of":
		tokenID, err := parseSIP721TokenID(call.Args["token_id"])
		if err != nil {
			return nil, err
		}
		terms := getSIP721Terms(store, address, tokenID)
		if terms == nil {
			return nil, fmt.Errorf("token %d has no embedded terms", tokenID)
		}
		recipient := terms.RoyaltyRecipient
		if recipient == "" {
			recipient = terms.Creator
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":            "terms_of",
			"token_id":          strconv.FormatUint(tokenID, 10),
			"creator":           terms.Creator,
			"royalty_bps":       strconv.FormatUint(terms.RoyaltyBPS, 10),
			"royalty_recipient": recipient,
			"usage_fee":         terms.UsageFeeNSPX,
			"licensee":          getSIP721Licensee(store, address, tokenID),
		}}, nil
	case "info":
		info, err := getSIP721Info(store, address)
		if err != nil {
			return nil, err
		}
		return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
			"method":        "info",
			"name":          info.Name,
			"symbol":        info.Symbol,
			"owner":         info.Owner,
			"next_token_id": strconv.FormatUint(info.NextTokenID, 10),
		}}, nil
	}
	return nil, fmt.Errorf("unsupported sip721 method: %s", call.Method)
}

// parseSIP721MintTerms decodes the optional embedded-economics arguments of a
// mint call. When none are provided the token is a legacy no-terms token
// (returns nil) — royalties and license fees simply don't apply to it.
func parseSIP721MintTerms(args map[string]string) (*SIP721TokenTerms, error) {
	rawBPS := strings.TrimSpace(args["royalty_bps"])
	rawFee := strings.TrimSpace(args["usage_fee"])
	rawRecipient := strings.TrimSpace(args["royalty_recipient"])
	if rawBPS == "" && rawFee == "" && rawRecipient == "" {
		return nil, nil
	}
	terms := &SIP721TokenTerms{}
	if rawBPS != "" {
		bps, err := strconv.ParseUint(rawBPS, 10, 64)
		if err != nil || bps > 10000 {
			return nil, fmt.Errorf("invalid royalty_bps: %q (must be 0..10000)", rawBPS)
		}
		terms.RoyaltyBPS = bps
	}
	if rawFee != "" {
		fee, err := parseAmount(rawFee)
		if err != nil || fee.Sign() <= 0 {
			return nil, fmt.Errorf("invalid usage_fee: %q (positive decimal nSPX required)", rawFee)
		}
		terms.UsageFeeNSPX = rawFee
	}
	if rawRecipient != "" {
		norm, err := common.NormalizeSPIFAddress(rawRecipient)
		if err != nil {
			return nil, fmt.Errorf("invalid royalty_recipient: %w", err)
		}
		terms.RoyaltyRecipient = norm
	}
	return terms, nil
}
