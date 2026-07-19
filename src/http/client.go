// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/http/client.go
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// httpClient is a reusable HTTP client with a 30-second timeout.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

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

	resp, err := httpClient.Post("http://"+address+"/transaction", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Drain body to allow connection reuse
	io.Copy(io.Discard, resp.Body)

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("transaction submission failed with status: %s", resp.Status)
	}

	return nil
}
