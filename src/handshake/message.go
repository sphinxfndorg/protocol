// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/message.go
package security

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/sphinxfndorg/protocol/src/consensus"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/network"
)

// ValidateMessage ensures the message conforms to expected structure and type rules.
func (m *Message) ValidateMessage() error {
	// Check if the message type is not empty
	if m.Type == "" {
		return errors.New("message type is empty")
	}

	// Handle validation logic based on the message type
	switch m.Type {
	case "transaction":
		// Data is json.RawMessage, need to unmarshal first
		var tx types.Transaction
		if err := json.Unmarshal(m.Data, &tx); err != nil {
			return errors.New("invalid transaction data: cannot unmarshal")
		}
		if tx.Sender == "" || tx.Receiver == "" || tx.Amount.Cmp(big.NewInt(0)) <= 0 {
			return errors.New("invalid transaction data")
		}

	case "block":
		// Check if Data can be unmarshaled as Block
		var block types.Block
		if err := json.Unmarshal(m.Data, &block); err != nil {
			return errors.New("invalid block data")
		}

	case "jsonrpc":
		// Check if Data is a map and contains correct JSON-RPC version
		var data map[string]interface{}
		if err := json.Unmarshal(m.Data, &data); err != nil {
			return errors.New("invalid JSON-RPC data")
		}
		if data["jsonrpc"] != "2.0" {
			return errors.New("invalid JSON-RPC version")
		}

	case "rpc":
		if len(m.Data) == 0 {
			return errors.New("invalid RPC data: empty payload")
		}

	case "ping", "pong":
		// Validate that Data is a string (node ID)
		var nodeID string
		if err := json.Unmarshal(m.Data, &nodeID); err != nil {
			return errors.New("invalid ping/pong data: must be node ID string")
		}
		if nodeID == "" {
			return errors.New("invalid ping/pong data: empty node ID")
		}

	case "peer_info":
		// Validate that Data is of type PeerInfo
		var peerInfo network.PeerInfo
		if err := json.Unmarshal(m.Data, &peerInfo); err != nil {
			return errors.New("invalid peer_info data")
		}

	case "version":
		// Validate that Data is a map with required fields
		var data map[string]interface{}
		if err := json.Unmarshal(m.Data, &data); err != nil {
			return errors.New("invalid version data")
		}
		if _, ok := data["version"].(string); !ok {
			return errors.New("invalid version data: missing or invalid version")
		}
		if _, ok := data["node_id"].(string); !ok {
			return errors.New("invalid version data: missing or invalid node_id")
		}
		if _, ok := data["chain_id"].(string); !ok {
			return errors.New("invalid version data: missing or invalid chain_id")
		}
		if _, ok := data["block_height"].(float64); !ok {
			return errors.New("invalid version data: missing or invalid block_height")
		}
		if _, ok := data["nonce"].(string); !ok {
			return errors.New("invalid version data: missing or invalid nonce")
		}

	case "verack":
		// Validate that Data is a string (node ID)
		var nodeID string
		if err := json.Unmarshal(m.Data, &nodeID); err != nil {
			return errors.New("invalid verack data: must be node ID string")
		}
		if nodeID == "" {
			return errors.New("invalid verack data: empty node ID")
		}

	case "proposal":
		var proposal consensus.Proposal
		if err := json.Unmarshal(m.Data, &proposal); err != nil {
			return errors.New("invalid proposal data")
		}

	case "prepare", "vote":
		var vote consensus.Vote
		if err := json.Unmarshal(m.Data, &vote); err != nil {
			return errors.New("invalid vote data")
		}

	case "timeout":
		var timeout consensus.TimeoutMsg
		if err := json.Unmarshal(m.Data, &timeout); err != nil {
			return errors.New("invalid timeout data")
		}

	case "checkpoint", "randao_sync":
		if len(m.Data) == 0 {
			return errors.New("invalid consensus data: empty payload")
		}

	default:
		// Unknown message types are not allowed
		return errors.New("unknown message type")
	}

	return nil
}

// Encode serializes the Message struct to JSON bytes.
func (m *Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeMessage takes a JSON byte slice and returns a validated Message object.
func DecodeMessage(data []byte) (*Message, error) {
	var msg Message

	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}

	if err := msg.ValidateMessage(); err != nil {
		return nil, err
	}

	return &msg, nil
}
