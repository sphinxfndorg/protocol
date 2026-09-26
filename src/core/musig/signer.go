// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"fmt"

	params "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
)

func SignCustodyMessage(msg []byte, localSK []byte, localPK []byte) ([]byte, error) {
	if len(msg) == 0 {
		return nil, fmt.Errorf("empty message")
	}
	if len(localSK) == 0 || len(localPK) == 0 {
		return nil, fmt.Errorf("missing key material")
	}
	km, err := key.NewKeyManager()
	if err != nil {
		return nil, err
	}
	sk, _, err := km.DeserializeKeyPair(localSK, localPK)
	if err != nil {
		return nil, err
	}
	sp, err := params.NewSTHINCSParameters()
	if err != nil {
		return nil, err
	}
	sig, err := sthincs.Spx_sign(sp.Params, msg, sk)
	if err != nil {
		return nil, err
	}
	return sig.SerializeSignature()
}
