// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/client.go
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	types "github.com/sphinxorg/protocol/src/core/transaction"
	security "github.com/sphinxorg/protocol/src/handshake"
)

// SubmitTransaction sends a transaction via HTTP.
func SubmitTransaction(address string, tx types.Transaction) error {
	// Marshal the transaction to JSON first
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}

	msg := &security.Message{
		Type: "transaction",
		Data: txData, // Use marshaled bytes
	}

	data, err := msg.Encode()
	if err != nil {
		return err
	}

	resp, err := http.Post("http://"+address+"/transaction", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("transaction submission failed with status: %s", resp.Status)
	}

	return nil
}
