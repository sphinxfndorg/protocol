// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/network/serialize.go
package network

import (
	"encoding/json"
	"fmt"
)

// serializeNodeData converts node data to JSON bytes
func serializeNodeData(nodeData map[string]interface{}) ([]byte, error) {
	data, err := json.Marshal(nodeData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node data: %w", err)
	}
	return data, nil
}

// deserializeNodeData converts JSON bytes back to node data
func deserializeNodeData(data []byte) (map[string]interface{}, error) {
	var nodeData map[string]interface{}
	if err := json.Unmarshal(data, &nodeData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node data: %w", err)
	}
	return nodeData, nil
}
