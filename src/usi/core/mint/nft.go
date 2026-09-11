// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"fmt"
)

// BuildNFTMetadata creates the ERC-721 compatible metadata JSON document.
// This is the equivalent of Ethereum's tokenURI metadata — a JSON document
// that describes the NFT (name, description, image, attributes).
//
// The image field is set to ipfs://<mediaCID> so marketplaces can render
// the NFT using the actual media stored on IPFS.
//
// Parameters:
//   - name: NFT name/title
//   - description: NFT description
//   - mediaCID: IPFS CID of the actual media (set as image field)
//   - attributes: ERC-721 trait attributes
//   - minterPK: minter's public key (hex)
//   - orgCode: organization code
//   - subject: asset identifier
//   - mintID: deterministic mint ID
//   - blockHeight: chain height at mint time
func BuildNFTMetadata(name, description, mediaCID string, attributes []NFTAttribute,
	minterPK, orgCode, subject, mintID string, blockHeight uint64) *NFTMetadata {

	meta := &NFTMetadata{
		Name:        name,
		Description: description,
		Image:       "ipfs://" + mediaCID,
		Attributes:  attributes,
		MintID:      mintID,
		MinterPublicKey: minterPK,
		OrgCode:     orgCode,
		Subject:     subject,
		BlockHeight: blockHeight,
	}

	return meta
}

// IPFSUploader is the minimal upload surface needed to pin bytes to IPFS.
// Both *storage.Client and the mint package's internal *ipfsClient satisfy
// it, so callers outside this package (e.g. src/usi/gui, which holds a
// *storage.Client) can pass their client directly without needing access to
// the unexported ipfsClient wrapper type.
type IPFSUploader interface {
	AddBytesToIPFS(data []byte, filename string) (string, error)
}

// UploadNFTMetadata uploads the NFT metadata JSON to IPFS and returns the CID.
// The returned CID is what becomes the tokenURI (ipfs://<cid>).
//
// This mirrors Ethereum's flow:
//   1. Build metadata JSON
//   2. Upload to IPFS → get metadata CID
//   3. tokenURI = ipfs://<metadataCID>
func UploadNFTMetadata(metadata *NFTMetadata, uploader IPFSUploader) (cid string, tokenURI string, err error) {
	if metadata == nil {
		return "", "", fmt.Errorf("nil metadata")
	}
	if uploader == nil {
		return "", "", fmt.Errorf("nil IPFS uploader")
	}

	// Marshal metadata JSON
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal NFT metadata: %w", err)
	}

	// Upload to IPFS
	cid, err = uploader.AddBytesToIPFS(data, "metadata.json")
	if err != nil {
		return "", "", fmt.Errorf("upload NFT metadata to IPFS: %w", err)
	}

	// Construct tokenURI (ERC-721 standard format)
	tokenURI = "ipfs://" + cid

	return cid, tokenURI, nil
}

// UploadMedia uploads the actual media/payload bytes to IPFS and returns the CID.
// This CID is what gets embedded in the NFT metadata's "image" field.
func UploadMedia(payload []byte, filename string, uploader IPFSUploader) (cid string, mediaURI string, err error) {
	if len(payload) == 0 {
		return "", "", fmt.Errorf("empty payload")
	}
	if uploader == nil {
		return "", "", fmt.Errorf("nil IPFS uploader")
	}

	cid, err = uploader.AddBytesToIPFS(payload, filename)
	if err != nil {
		return "", "", fmt.Errorf("upload media to IPFS: %w", err)
	}

	mediaURI = "ipfs://" + cid
	return cid, mediaURI, nil
}
