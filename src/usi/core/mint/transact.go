// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/mint/transact.go
//
// Wiring for abi.Transact: the node transport and the SPHINCS+ signer that
// abi requires but must not import itself.
package mint

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	kbackend "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sbackend "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/rpc"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
)

// nodeRPC adapts rpc.CallRPC to abi.RPCClient, so the shared abi.Transact path
// reaches the node without abi importing src/rpc (which would drag the node
// runtime back into every client that only wants to build a transaction).
type nodeRPC struct{}

func (nodeRPC) CallRPC(nodeAddr, method string, params interface{}, ttlSeconds uint16) (json.RawMessage, error) {
	if ttlSeconds == 0 {
		ttlSeconds = abi.DefaultTransactTTL
	}
	return rpc.CallRPC(nodeAddr, method, params, ttlSeconds)
}

// KeyFileSigner implements abi.Signer with a locally held credential. The
// string is forwarded verbatim to keys.LoadKeyFromDisk, which is what the
// previous inline signing path did: the CLI passes --key, the GUI passes the
// session passphrase. The key is loaded, used, and zeroed per signature, so no
// long-lived secret sits between a collection mint and its receipt anchor.
type KeyFileSigner struct {
	KeyFile string
}

func (s KeyFileSigner) SignTransaction(tx *types.Transaction) error {
	if strings.TrimSpace(s.KeyFile) == "" {
		return fmt.Errorf("key file required")
	}
	kp, skBytes, err := keys.LoadKeyFromDisk(s.KeyFile)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()
	return signTransactionLocallyInMint(tx, skBytes, kp.PublicKey)
}

// transactOpts builds the shared abi.TransactOpts for one mint broadcast. The
// nonce is supplied by the caller because this flow claims it from the shared
// process-local reservation (Nonces) to keep a collection mint and its receipt
// anchor from claiming the same committed nonce.
func transactOpts(nodeAddr, keyFile string, chainID, nonce uint64) *abi.TransactOpts {
	return &abi.TransactOpts{
		Client:   nodeRPC{},
		Signer:   KeyFileSigner{KeyFile: keyFile},
		NodeAddr: nodeAddr,
		ChainID:  chainID,
		Nonce:    &nonce,
	}
}

// callOpts builds the read-side abi.CallOpts for the same node transport, for
// confirmation queries (abi.GetTransactionReceipt / abi.WaitMined) that share
// the transaction path's client.
func callOpts(nodeAddr string) *abi.CallOpts {
	return &abi.CallOpts{Client: nodeRPC{}, NodeAddr: nodeAddr}
}

// signTransactionLocallyInMint signs a transaction using the node's canonical
// SPHINCS+ transaction authentication path (STHINCSManager.SignTransactionAuth),
// the same call cli/utils/client.go, core.SignTransaction and the USI wallet
// use. It is kept in this package so MintAndAnchor's collection step carries
// no dependency on the GUI.
func signTransactionLocallyInMint(tx *types.Transaction, skBytes, pkBytes []byte) error {
	if tx == nil {
		return fmt.Errorf("nil transaction")
	}
	if tx.ID == "" {
		tx.ID = tx.Hash()
	}

	km, err := kbackend.NewKeyManager()
	if err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}
	privateKey, publicKey, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize key pair: %w", err)
	}

	sphincsParams := km.GetSPHINCSParameters()
	if sphincsParams == nil || sphincsParams.Params == nil {
		return fmt.Errorf("SPHINCS+ parameters not initialized")
	}

	signingMgr := sbackend.NewSTHINCSManager(nil, km, sphincsParams)
	bundle, err := signingMgr.SignTransactionAuth([]byte(tx.ID), privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to sign transaction auth bundle: %w", err)
	}

	tx.Signature = bundle.Signature
	tx.SignatureHash = bundle.SignatureHash
	tx.PublicKey = bundle.PublicKey
	tx.AuthTimestamp = bundle.Timestamp
	tx.AuthNonce = bundle.Nonce
	tx.MerkleRootHash = bundle.MerkleRootHash
	tx.Commitment = bundle.Commitment
	tx.Proof = bundle.Proof

	return nil
}
