// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package abi

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// SIP721Contract is the typed binding for a deployed SIP-721 collection,
// following the abigen shape: construct it with the deployed address, then
// call typed methods that pack their own calldata and broadcast through
// TransactOpts. Callers never assemble calldata or call sendrawtransaction.
type SIP721Contract struct {
	Address string
}

// MintTerms are the optional per-token economics the mint freezes in contract
// storage. Zero values emit no terms, which is exactly the legacy
// zero-royalty, zero-fee mint.
type MintTerms struct {
	TokenURI         string
	MintID           string
	RoyaltyBPS       uint64
	UsageFeeNSPX     string
	RoyaltyRecipient string
}

func (t MintTerms) args(to string) map[string]string {
	args := map[string]string{
		"to":        strings.TrimSpace(to),
		"token_uri": strings.TrimSpace(t.TokenURI),
		"mint_id":   strings.TrimSpace(t.MintID),
	}
	if t.RoyaltyBPS > 0 {
		args["royalty_bps"] = strconv.FormatUint(t.RoyaltyBPS, 10)
	}
	if fee := strings.TrimSpace(t.UsageFeeNSPX); fee != "" {
		args["usage_fee"] = fee
	}
	if recipient := strings.TrimSpace(t.RoyaltyRecipient); recipient != "" {
		args["royalty_recipient"] = recipient
	}
	return args
}

// Transact runs any SIP-721 method (transfer_from, approve, list, buy, ...)
// through the shared Transact path.
func (c SIP721Contract) Transact(opts *TransactOpts, from, method string, args map[string]string) (string, error) {
	return transactCall(opts, SIP721ABI, c.Address, from, method, args)
}

// Mint executes mint(to, token_uri, mint_id[, royalty_bps, usage_fee,
// royalty_recipient]) and returns the broadcast txid. The contract allocates
// the tokenId at block commit, so callers read it back from contract storage
// (sip721:mint:<mint_id>) rather than guessing it.
func (c SIP721Contract) Mint(opts *TransactOpts, from, to string, terms MintTerms) (string, error) {
	return c.Transact(opts, from, "mint", terms.args(to))
}

// MintTx builds the unsigned mint transaction without broadcasting it, for
// callers that manage their own signing and submission.
func (c SIP721Contract) MintTx(options TxOptions, to string, terms MintTerms) (*types.Transaction, error) {
	return NewSIP721CallTx(options, c.Address, "mint", terms.args(to))
}

// ── Typed write methods ───────────────────────────────────────────────────
// Same shape as Mint: each packs its own calldata and broadcast through the
// shared Transact path, returning the node's txid. Ownership, approval,
// listing and license rules are enforced by every node at consensus
// (contracts.callSIP721), so these methods do not pre-check them.

// TransferFrom executes transfer_from(from, to, token_id). A sale settled this
// way splits any value carried by the transaction into the token's royalty and
// the seller's proceeds, and clears any listing on the token.
func (c SIP721Contract) TransferFrom(opts *TransactOpts, sender, from, to string, tokenID uint64) (string, error) {
	return c.Transact(opts, sender, "transfer_from", map[string]string{
		"from":     strings.TrimSpace(from),
		"to":       strings.TrimSpace(to),
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

// Approve executes approve(to, token_id): grants to the right to transfer the
// token.
func (c SIP721Contract) Approve(opts *TransactOpts, sender, to string, tokenID uint64) (string, error) {
	return c.Transact(opts, sender, "approve", map[string]string{
		"to":       strings.TrimSpace(to),
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

// List executes list(token_id, price), posting price (positive decimal nSPX)
// as the token's asking price. Re-listing is the price update path.
func (c SIP721Contract) List(opts *TransactOpts, sender string, tokenID uint64, price string) (string, error) {
	return c.Transact(opts, sender, "list", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
		"price":    strings.TrimSpace(price),
	})
}

// Buy executes buy(token_id) and returns the broadcast txid. amountNSPX is
// required rather than defaulted: the runtime escrows tx.Amount and rejects
// anything but an exact match against the stored list price, so a zero-value
// default could only ever produce a rejected transaction.
func (c SIP721Contract) Buy(opts *TransactOpts, sender string, tokenID uint64, amountNSPX string) (string, error) {
	return c.transactEscrow(opts, sender, "buy", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	}, amountNSPX)
}

// Cancel executes cancel(token_id): the owner (or collection owner) withdraws
// the listing.
func (c SIP721Contract) Cancel(opts *TransactOpts, sender string, tokenID uint64) (string, error) {
	return c.Transact(opts, sender, "cancel", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

// PurchaseLicense executes purchase_license(token_id[, licensee]), paying the
// token's usage fee to the royalty recipient and recording the entitlement.
// amountNSPX is required for the same reason as Buy: the runtime requires an
// exact match against the stored usage fee. An empty licensee means the caller
// receives it.
func (c SIP721Contract) PurchaseLicense(opts *TransactOpts, sender string, tokenID uint64, licensee, amountNSPX string) (string, error) {
	args := map[string]string{"token_id": strconv.FormatUint(tokenID, 10)}
	if licensee = strings.TrimSpace(licensee); licensee != "" {
		args["licensee"] = licensee
	}
	return c.transactEscrow(opts, sender, "purchase_license", args, amountNSPX)
}

// transactEscrow runs a value-carrying method with the caller's exact escrow
// on a COPY of opts, so the escrow never leaks into the caller's per-call
// options and a shared opts stays safe to reuse for a non-escrow method.
func (c SIP721Contract) transactEscrow(opts *TransactOpts, sender, method string, args map[string]string, amountNSPX string) (string, error) {
	escrow, err := parseEscrowAmount(amountNSPX)
	if err != nil {
		return "", err
	}
	if opts == nil {
		return "", errors.New("nil transact options")
	}
	perCall := *opts
	perCall.Amount = escrow
	return transactCall(&perCall, SIP721ABI, c.Address, sender, method, args)
}

// parseEscrowAmount reads the exact nSPX escrow a value-carrying call must
// carry. It rejects only what cannot be represented as a transaction value (a
// missing, malformed, or negative amount); whether the value matches the
// posted price is enforced by contracts.callSIP721 at consensus, which rejects
// any mismatch.
func parseEscrowAmount(amountNSPX string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(strings.TrimSpace(amountNSPX), 10)
	if !ok || value.Sign() < 0 {
		return nil, fmt.Errorf("escrow amount %q is not a valid non-negative nSPX value", amountNSPX)
	}
	return value, nil
}

// RevokeLicense executes revoke_license(token_id): the collection owner or the
// token creator clears the single active license.
func (c SIP721Contract) RevokeLicense(opts *TransactOpts, sender string, tokenID uint64) (string, error) {
	return c.Transact(opts, sender, "revoke_license", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

// TransferFromTx, ApproveTx, ListTx, BuyTx, CancelTx, PurchaseLicenseTx and
// RevokeLicenseTx build the unsigned transactions without broadcasting them,
// for callers that manage their own signing and submission.
func (c SIP721Contract) TransferFromTx(options TxOptions, from, to string, tokenID uint64) (*types.Transaction, error) {
	return NewSIP721CallTx(options, c.Address, "transfer_from", map[string]string{
		"from":     strings.TrimSpace(from),
		"to":       strings.TrimSpace(to),
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

func (c SIP721Contract) ApproveTx(options TxOptions, to string, tokenID uint64) (*types.Transaction, error) {
	return NewSIP721CallTx(options, c.Address, "approve", map[string]string{
		"to":       strings.TrimSpace(to),
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

func (c SIP721Contract) ListTx(options TxOptions, tokenID uint64, price string) (*types.Transaction, error) {
	return NewSIP721CallTx(options, c.Address, "list", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
		"price":    strings.TrimSpace(price),
	})
}

func (c SIP721Contract) BuyTx(options TxOptions, tokenID uint64, amountNSPX string) (*types.Transaction, error) {
	escrow, err := parseEscrowAmount(amountNSPX)
	if err != nil {
		return nil, err
	}
	return newCallTx(SIP721ABI, options, c.Address, "buy", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	}, escrow)
}

func (c SIP721Contract) CancelTx(options TxOptions, tokenID uint64) (*types.Transaction, error) {
	return NewSIP721CallTx(options, c.Address, "cancel", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

func (c SIP721Contract) PurchaseLicenseTx(options TxOptions, tokenID uint64, licensee, amountNSPX string) (*types.Transaction, error) {
	escrow, err := parseEscrowAmount(amountNSPX)
	if err != nil {
		return nil, err
	}
	args := map[string]string{"token_id": strconv.FormatUint(tokenID, 10)}
	if licensee = strings.TrimSpace(licensee); licensee != "" {
		args["licensee"] = licensee
	}
	return newCallTx(SIP721ABI, options, c.Address, "purchase_license", args, escrow)
}

func (c SIP721Contract) RevokeLicenseTx(options TxOptions, tokenID uint64) (*types.Transaction, error) {
	return NewSIP721CallTx(options, c.Address, "revoke_license", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
}

// ── Typed read methods ────────────────────────────────────────────────────
// Each one runs the node's own read-only method through callContract, so
// owner/terms rules are the node's, and converts the returned map into Go
// values. Node errors ("token 4 does not exist") are returned verbatim: they are
// user-facing wallet errors, not internal ones.

// SIP721Terms is the read-side view of a token's embedded economics
// (contracts.callSIP721 "terms_of"). It is deliberately separate from the
// write-side MintTerms: the node returns the frozen terms plus the token's
// current licensee, which nothing in a mint call can express.
type SIP721Terms struct {
	TokenID          uint64
	Creator          string
	RoyaltyBPS       uint64
	RoyaltyRecipient string
	UsageFeeNSPX     string
	Licensee         string
}

// OwnerOf returns the current owner of tokenID.
func (c SIP721Contract) OwnerOf(opts *CallOpts, tokenID uint64) (string, error) {
	result, err := callContract(opts, SIP721ABI, c.Address, "owner_of", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
	if err != nil {
		return "", err
	}
	return resultKey(result, "owner_of", "owner")
}

// TokenURI returns the tokenURI frozen at mint.
func (c SIP721Contract) TokenURI(opts *CallOpts, tokenID uint64) (string, error) {
	result, err := callContract(opts, SIP721ABI, c.Address, "token_uri", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
	if err != nil {
		return "", err
	}
	return resultKey(result, "token_uri", "token_uri")
}

// TokenIDOfMint resolves the tokenId the contract allocated to mintID from its
// on-chain reverse index (sip721:mint:<mint_id>).
func (c SIP721Contract) TokenIDOfMint(opts *CallOpts, mintID string) (uint64, error) {
	result, err := callContract(opts, SIP721ABI, c.Address, "token_id_of_mint", map[string]string{
		"mint_id": strings.TrimSpace(mintID),
	})
	if err != nil {
		return 0, err
	}
	return resultUint64(result, "token_id_of_mint", "token_id")
}

// TermsOf returns the embedded economics frozen at mint plus the token's
// current licensee.
func (c SIP721Contract) TermsOf(opts *CallOpts, tokenID uint64) (SIP721Terms, error) {
	result, err := callContract(opts, SIP721ABI, c.Address, "terms_of", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
	if err != nil {
		return SIP721Terms{}, err
	}
	terms := SIP721Terms{}
	if terms.TokenID, err = resultUint64(result, "terms_of", "token_id"); err != nil {
		return SIP721Terms{}, err
	}
	if terms.RoyaltyBPS, err = resultUint64(result, "terms_of", "royalty_bps"); err != nil {
		return SIP721Terms{}, err
	}
	if terms.Creator, err = resultKey(result, "terms_of", "creator"); err != nil {
		return SIP721Terms{}, err
	}
	if terms.RoyaltyRecipient, err = resultKey(result, "terms_of", "royalty_recipient"); err != nil {
		return SIP721Terms{}, err
	}
	if terms.UsageFeeNSPX, err = resultKey(result, "terms_of", "usage_fee"); err != nil {
		return SIP721Terms{}, err
	}
	if terms.Licensee, err = resultKey(result, "terms_of", "licensee"); err != nil {
		return SIP721Terms{}, err
	}
	return terms, nil
}

// ListingOf returns the active marketplace listing of tokenID: the seller and
// the asking price in nSPX. An unlisted token is an error, not empty strings —
// the node refuses "listing_of" for it ("token 4 is not listed").
func (c SIP721Contract) ListingOf(opts *CallOpts, tokenID uint64) (seller, price string, err error) {
	result, err := callContract(opts, SIP721ABI, c.Address, "listing_of", map[string]string{
		"token_id": strconv.FormatUint(tokenID, 10),
	})
	if err != nil {
		return "", "", err
	}
	if seller, err = resultKey(result, "listing_of", "seller"); err != nil {
		return "", "", err
	}
	if price, err = resultKey(result, "listing_of", "price"); err != nil {
		return "", "", err
	}
	return seller, price, nil
}

// SIP721Info is the read-side view of a collection (contracts.callSIP721
// "info"): the frozen name/symbol/owner plus the live tokenId counter, which is
// the only authoritative "next token" answer — the counter lives in contract
// storage and is advanced by the node at block commit.
type SIP721Info struct {
	Name        string
	Symbol      string
	Owner       string
	NextTokenID uint64
}

// Info returns the collection's metadata and live tokenId counter.
func (c SIP721Contract) Info(opts *CallOpts) (SIP721Info, error) {
	result, err := callContract(opts, SIP721ABI, c.Address, "info", nil)
	if err != nil {
		return SIP721Info{}, err
	}
	info := SIP721Info{}
	if info.Name, err = resultKey(result, "info", "name"); err != nil {
		return SIP721Info{}, err
	}
	if info.Symbol, err = resultKey(result, "info", "symbol"); err != nil {
		return SIP721Info{}, err
	}
	if info.Owner, err = resultKey(result, "info", "owner"); err != nil {
		return SIP721Info{}, err
	}
	if info.NextTokenID, err = resultUint64(result, "info", "next_token_id"); err != nil {
		return SIP721Info{}, err
	}
	return info, nil
}
