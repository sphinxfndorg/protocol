// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package contracts

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// Marketplace is a native contract for listing and buying tokens
type Marketplace struct{}

// initMarketplace initializes a marketplace contract's storage
func initMarketplace(store Store, address, sender string, spec *DeploySpec) error {
	store.SetContractStorage(address, "mp:next_listing_id", []byte("1"))
	return nil
}

// callMarketplace dispatches marketplace contract method calls
func callMarketplace(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	switch call.Method {
	case "list":
		return marketplaceList(store, address, caller, call)
	case "buy":
		return marketplaceBuy(store, address, caller, call)
	case "cancel":
		return marketplaceCancel(store, address, caller, call)
	default:
		return nil, fmt.Errorf("unknown marketplace method: %s", call.Method)
	}
}

// marketplaceContractRegistration provides the init/call functions for contract registration
var marketplaceContractRegistration = struct {
	Init  func(Store, string, string, *DeploySpec) error
	Call  func(Store, string, string, *CallSpec) (*ExecutionResult, error)
}{
	Init:  initMarketplace,
	Call:  callMarketplace,
}

// Ensure the registration is used
var _ = marketplaceContractRegistration

func marketplaceList(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	tokenContract := call.Args["token_contract"]
	if tokenContract == "" {
		return nil, fmt.Errorf("missing token_contract")
	}

	amountStr := call.Args["amount"]
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok || amount.Sign() <= 0 {
		return nil, fmt.Errorf("invalid amount")
	}

	priceStr := call.Args["price"]
	price, ok := new(big.Int).SetString(priceStr, 10)
	if !ok || price.Sign() <= 0 {
		return nil, fmt.Errorf("invalid price")
	}

	nextID := getNextListingID(store, address)
	listingID := nextID.Uint64()

	listing := struct {
		ID            uint64   `json:"id"`
		TokenContract string   `json:"token_contract"`
		Seller        string   `json:"seller"`
		Amount        *big.Int `json:"amount"`
		Price         *big.Int `json:"price"`
		Active        bool     `json:"active"`
	}{
		ID: listingID, TokenContract: tokenContract, Seller: caller,
		Amount: amount, Price: price, Active: true,
	}

	listingJSON, _ := json.Marshal(listing)
	store.SetContractStorage(address, fmt.Sprintf("mp:listings:%d", listingID), listingJSON)
	store.SetContractStorage(address, fmt.Sprintf("mp:seller:%s:%d", caller, listingID), []byte("true"))

	nextID.Add(nextID, big.NewInt(1))
	store.SetContractStorage(address, "mp:next_listing_id", []byte(nextID.String()))

	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
		"method": "list", "listing_id": fmt.Sprintf("%d", listingID),
		"token_contract": tokenContract, "amount": amount.String(), "price": price.String(),
	}}, nil
}

func marketplaceBuy(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	listingIDStr := call.Args["listing_id"]
	listingID, ok := new(big.Int).SetString(listingIDStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid listing_id")
	}

	listingJSON, err := store.GetContractStorage(address, fmt.Sprintf("mp:listings:%d", listingID))
	if err != nil || len(listingJSON) == 0 {
		return nil, fmt.Errorf("listing not found")
	}

	var listing struct {
		ID            uint64   `json:"id"`
		TokenContract string   `json:"token_contract"`
		Seller        string   `json:"seller"`
		Amount        *big.Int `json:"amount"`
		Price         *big.Int `json:"price"`
		Active        bool     `json:"active"`
	}
	if err := json.Unmarshal(listingJSON, &listing); err != nil || !listing.Active {
		return nil, fmt.Errorf("invalid listing")
	}

	fee := new(big.Int).Div(listing.Price, big.NewInt(100))
	if fee.Sign() == 0 {
		fee = big.NewInt(1)
	}

	tokenCall := &CallSpec{
		Method: "transfer",
		Args: map[string]string{"to": caller, "amount": listing.Amount.String()},
	}

	result, err := callSIP20(store, listing.TokenContract, listing.Seller, tokenCall)
	if err != nil || result.Status != "ok" {
		return nil, fmt.Errorf("transfer failed")
	}

	listing.Active = false
	listingJSON, _ = json.Marshal(listing)
	store.SetContractStorage(address, fmt.Sprintf("mp:listings:%d", listingID), listingJSON)

	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
		"method": "buy", "listing_id": fmt.Sprintf("%d", listingID),
		"token_contract": listing.TokenContract, "amount": listing.Amount.String(),
		"fee": fee.String(), "total_paid": listing.Price.String(),
	}}, nil
}

func marketplaceCancel(store Store, address, caller string, call *CallSpec) (*ExecutionResult, error) {
	listingIDStr := call.Args["listing_id"]
	listingID, ok := new(big.Int).SetString(listingIDStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid listing_id")
	}

	listingJSON, err := store.GetContractStorage(address, fmt.Sprintf("mp:listings:%d", listingID))
	if err != nil || len(listingJSON) == 0 {
		return nil, fmt.Errorf("listing not found")
	}

	var listing struct {
		ID            uint64   `json:"id"`
		TokenContract string   `json:"token_contract"`
		Seller        string   `json:"seller"`
		Amount        *big.Int `json:"amount"`
		Price         *big.Int `json:"price"`
		Active        bool     `json:"active"`
	}
	if err := json.Unmarshal(listingJSON, &listing); err != nil {
		return nil, err
	}

	if caller != listing.Seller {
		return nil, fmt.Errorf("only seller can cancel")
	}
	if !listing.Active {
		return nil, fmt.Errorf("already inactive")
	}

	listing.Active = false
	listingJSON, _ = json.Marshal(listing)
	store.SetContractStorage(address, fmt.Sprintf("mp:listings:%d", listingID), listingJSON)
	store.SetContractStorage(address, fmt.Sprintf("mp:seller:%s:%d", caller, listingID), []byte{})

	return &ExecutionResult{ContractAddress: address, Status: "ok", Return: map[string]string{
		"method": "cancel", "listing_id": fmt.Sprintf("%d", listingID),
	}}, nil
}

func getNextListingID(store Store, marketplaceAddress string) *big.Int {
	value, _ := store.GetContractStorage(marketplaceAddress, "mp:next_listing_id")
	if len(value) == 0 {
		return big.NewInt(1)
	}
	id, _ := new(big.Int).SetString(string(value), 10)
	return id
}