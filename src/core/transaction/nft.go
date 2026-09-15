// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/nft.go
package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
)

func BuildNFTAnchorReturnData(mintID, subject, cid, cidHashHex string, timestamp int64) ([]byte, error) {
	return BuildNFTAnchorReturnDataWithTerms(mintID, subject, cid, cidHashHex, 0, "", "", timestamp)
}

// BuildNFTAnchorReturnDataWithTerms builds an NFT anchor payload carrying the
// embedded economics (resale royalty in basis points, per-licensed-access fee
// in nSPX, and an optional payout override). These terms commit the creator's
// intended value model at mint time; the SIP-721 runtime enforces them on
// every transfer_from / purchase_license.
func BuildNFTAnchorReturnDataWithTerms(mintID, subject, cid, cidHashHex string, royaltyBPS uint64, usageFeeNSPX, royaltyRecipient string, timestamp int64) ([]byte, error) {
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	payload := &NFTAnchorPayload{
		Type:             NFTAnchorType,
		Version:          NFTAnchorVersion,
		MintID:           strings.TrimSpace(mintID),
		Subject:          strings.TrimSpace(subject),
		CID:              strings.TrimSpace(cid),
		CIDHashHex:       strings.TrimSpace(cidHashHex),
		Timestamp:        timestamp,
		RoyaltyBPS:       royaltyBPS,
		UsageFeeNSPX:     strings.TrimSpace(usageFeeNSPX),
		RoyaltyRecipient: strings.TrimSpace(royaltyRecipient),
	}
	if err := ValidateNFTAnchorPayload(payload); err != nil {
		return nil, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal NFT anchor payload: %w", err)
	}
	if len(data) > MaxReturnDataSize {
		return nil, fmt.Errorf("NFT anchor payload exceeds maximum size of %d bytes", MaxReturnDataSize)
	}
	return data, nil
}

func ParseNFTAnchorReturnData(data []byte) (*NFTAnchorPayload, error) {
	if len(data) == 0 {
		return nil, errors.New("empty NFT anchor payload")
	}
	if len(data) > MaxReturnDataSize {
		return nil, fmt.Errorf("NFT anchor payload exceeds maximum size of %d bytes", MaxReturnDataSize)
	}
	var payload NFTAnchorPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("invalid NFT anchor payload: %w", err)
	}
	if err := ValidateNFTAnchorPayload(&payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func ValidateNFTAnchorPayload(payload *NFTAnchorPayload) error {
	if payload == nil {
		return errors.New("nil NFT anchor payload")
	}
	if payload.Type != "" && payload.Type != NFTAnchorType {
		return fmt.Errorf("unexpected NFT anchor type: %q", payload.Type)
	}
	if payload.Version != NFTAnchorVersion {
		return fmt.Errorf("unsupported NFT anchor version: %d", payload.Version)
	}
	if payload.MintID == "" {
		return errors.New("missing mint_id")
	}
	if payload.CID == "" {
		return errors.New("missing cid")
	}
	if payload.CIDHashHex == "" {
		return errors.New("missing cid_hash_hex")
	}
	if payload.Timestamp < 0 {
		return errors.New("invalid timestamp")
	}
	if payload.RoyaltyBPS > 10000 {
		return fmt.Errorf("royalty_bps out of range: %d (max 10000)", payload.RoyaltyBPS)
	}
	if payload.UsageFeeNSPX != "" {
		if fee, ok := new(big.Int).SetString(payload.UsageFeeNSPX, 10); !ok || fee.Sign() <= 0 {
			return fmt.Errorf("invalid usage_fee: %q (positive decimal nSPX required)", payload.UsageFeeNSPX)
		}
	}
	if payload.RoyaltyRecipient != "" {
		if _, err := common.NormalizeSPIFAddress(payload.RoyaltyRecipient); err != nil {
			return fmt.Errorf("invalid royalty_recipient: %w", err)
		}
	}
	return nil
}

func IsNFTAnchorReturnData(data []byte) bool {
	_, err := ParseNFTAnchorReturnData(data)
	return err == nil
}
