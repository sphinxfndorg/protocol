// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SaveReceipt writes receipt JSON to disk.
// If outPath is empty, it writes next to current working directory.
func SaveReceipt(receipt *MintReceipt, outPath string) (string, error) {
	if receipt == nil {
		return "", errors.New("nil receipt")
	}
	if outPath == "" {
		outPath = fmt.Sprintf("mint_%s.usimint.json", receipt.MintID)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil && filepath.Dir(outPath) != "." {
		return "", err
	}

	data, err := jsonMarshalReceipt(receipt)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return "", err
	}
	return outPath, nil
}

// LoadReceipt reads receipt JSON from disk.
func LoadReceipt(path string) (*MintReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r MintReceipt
	if err := jsonUnmarshalReceipt(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Minimal JSON wrappers.
func jsonMarshalReceipt(r *MintReceipt) ([]byte, error)      { return json.Marshal(r) }
func jsonUnmarshalReceipt(data []byte, r *MintReceipt) error { return json.Unmarshal(data, r) }

// SaveAnchorTag writes the anchor tag JSON to disk, next to the receipt file.
// If outPath is empty, it derives from receipt's MintID.
// SaveAnchorTag writes the anchor tag JSON to disk, next to the receipt file.
// If outPath is empty, it derives from tag's MintID.
func SaveAnchorTag(tag *AnchorTag, outPath string) (string, error) {
	if tag == nil {
		return "", errors.New("nil tag")
	}
	if outPath == "" {
		outPath = fmt.Sprintf("anchor_%s.json", tag.MintID)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil && filepath.Dir(outPath) != "." {
		return "", err
	}
	data, err := json.MarshalIndent(tag, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return "", err
	}
	return outPath, nil
}

// LoadAnchorTag reads an anchor tag from disk.
func LoadAnchorTag(path string) (*AnchorTag, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DeserializeAnchorTag(data)
}
