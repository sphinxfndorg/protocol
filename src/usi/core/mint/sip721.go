// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"errors"

	"github.com/sphinxfndorg/protocol/src/contracts"
)

// collectionStore adapts *storage.Client-style contract reads to the
// contracts.Store surface so the SIP-721 reader can run against live node
// state via getcontractstorage. Writes are never performed through this
// adapter — mint/transfer/approve execute in consensus via sendrawtransaction.
type collectionStore struct {
	client *ContractStorageReader
	addr   string
}

func (s *collectionStore) ContractExists(address string) bool { return true }
func (s *collectionStore) SetContractCode(address string, code []byte) {}
func (s *collectionStore) GetContractCode(address string) ([]byte, error) {
	return nil, errors.New("code read not supported")
}
func (s *collectionStore) SetContractMeta(address string, meta []byte) {}
func (s *collectionStore) GetContractMeta(address string) ([]byte, error) {
	return nil, errors.New("meta read not supported")
}
func (s *collectionStore) SetContractStorage(address, key string, value []byte) {}
func (s *collectionStore) GetContractStorage(address, key string) ([]byte, error) {
	return s.client.GetStorage(address, key)
}

var _ contracts.Store = (*collectionStore)(nil)
