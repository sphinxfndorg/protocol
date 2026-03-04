// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
