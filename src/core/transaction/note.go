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

// go/src/core/transaction/note.go
package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/sphinxorg/protocol/src/common"
)

// NewNote creates a new Note instance using centralized time service
func NewNote(to, from string, fee float64, storage, key string) (*Note, error) {
	// Step 1: Validate the sender's and receiver's wallet addresses to ensure they are correctly formatted.
	if err := validateAddress(to); err != nil {
		return nil, err
	}

	if err := validateAddress(from); err != nil {
		return nil, err
	}

	// Step 2: Create a new Note struct with centralized time service
	// CRITICAL FIX: Use current timestamp, not 0
	currentTimestamp := common.GetCurrentTimestamp()
	if currentTimestamp == 0 {
		// Fallback to system time if time service returns 0
		currentTimestamp = time.Now().Unix()
	}

	note := &Note{
		To:        to,               // Set the recipient's address
		From:      from,             // Set the sender's address
		Fee:       fee,              // Set the transaction fee
		Storage:   storage,          // Set the storage information
		Timestamp: currentTimestamp, // Use centralized time service
	}

	// Step 3: Generate a Message Authentication Code (MAC) for the note
	mac, err := generateMAC(note, key)
	if err != nil {
		return nil, err
	}

	// Step 4: Assign the generated MAC to the Note struct.
	note.MAC = mac

	return note, nil
}

// generateMAC generates a Message Authentication Code (MAC) for a given Note using a secret key.
// The MAC ensures the integrity and authenticity of the Note's data.
func generateMAC(note *Note, key string) (string, error) {
	// Step 1: Construct a message string by concatenating the key with the Note's fields.
	// The message format: key + To + From + Fee + Storage + Timestamp.
	message := key +
		note.To + // Recipient's address
		note.From + // Sender's address
		fmt.Sprintf("%f", note.Fee) + // Fee (converted to a string)
		note.Storage + // Storage metadata
		fmt.Sprintf("%d", note.Timestamp) // Timestamp (converted to a string)

	// Step 2: Convert the constructed message into a byte slice.
	messageBytes := []byte(message)

	// Step 3: Compute the hash of the message using the SphinxHash function.
	hash := common.SpxHash(messageBytes)

	// Step 4: Encode the hash into a hexadecimal string to make it human-readable.
	mac := hex.EncodeToString(hash)

	// Step 5: Return the generated MAC.
	return mac, nil
}

// GetFormattedTimestamps for Transaction using centralized service
func (tx *Transaction) GetFormattedTimestamps() (localTime, utcTime string) {
	return common.FormatTimestamp(tx.Timestamp)
}

// ToTxs converts the current Note instance into a Transaction instance.
func (n *Note) ToTxs(nonce uint64, gasLimit, gasPrice *big.Int) *Transaction {
	// Use AmountNSPX if provided (exact big.Int), otherwise fall back to Fee (float64).
	// AmountNSPX must be used for genesis distribution where amounts are ~10^25 nSPX
	// and cannot be represented precisely as float64.
	var amount *big.Int
	if n.AmountNSPX != nil && n.AmountNSPX.Sign() > 0 {
		amount = new(big.Int).Set(n.AmountNSPX)
	} else {
		amount = big.NewInt(int64(n.Fee))
	}

	timestamp := n.Timestamp
	if timestamp == 0 {
		timestamp = common.GetCurrentTimestamp()
		if timestamp == 0 {
			timestamp = time.Now().Unix()
		}
	}

	tx := &Transaction{
		Sender:     n.From,
		Receiver:   n.To,
		Amount:     amount,
		GasLimit:   gasLimit,
		GasPrice:   gasPrice,
		Timestamp:  timestamp,
		Nonce:      nonce,
		Signature:  []byte{},
		ReturnData: n.ReturnData, // Include OP_RETURN data
	}
	tx.ID = tx.Hash()
	return tx
}

// Hash computes the transaction ID using SphinxHash.
func (tx *Transaction) Hash() string {
	data, _ := json.Marshal(tx)
	hash := common.SpxHash(data)
	return hex.EncodeToString(hash)
}

// HasReturnData checks if transaction contains OP_RETURN data
func (tx *Transaction) HasReturnData() bool {
	return len(tx.ReturnData) > 0
}

// GetReturnDataAsString returns OP_RETURN data as string if printable
func (tx *Transaction) GetReturnDataAsString() string {
	if !tx.HasReturnData() {
		return ""
	}
	// Check if data contains only printable ASCII characters
	for _, b := range tx.ReturnData {
		if b < 32 || b > 126 {
			return hex.EncodeToString(tx.ReturnData)
		}
	}
	return string(tx.ReturnData)
}
