// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"encoding/binary"

	"github.com/sphinxfndorg/protocol/src/common"
)

func CustodyReleaseMessage(domain string, chainID uint64, escrow, recipient string, amount []byte, nonce uint64, expiry uint64) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x00)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], chainID)
	buf = append(buf, tmp[:]...)
	buf = append(buf, []byte(escrow)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(recipient)...)
	buf = append(buf, 0x00)
	buf = append(buf, amount...)
	buf = append(buf, 0x00)
	binary.BigEndian.PutUint64(tmp[:], nonce)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], expiry)
	buf = append(buf, tmp[:]...)
	return common.SpxHash(buf)
}

func DevModuleReleaseMessage(domain string, chainID uint64, escrow, recipient string, moduleID uint64, expiry uint64) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x00)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], chainID)
	buf = append(buf, tmp[:]...)
	buf = append(buf, []byte(escrow)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(recipient)...)
	buf = append(buf, 0x00)
	binary.BigEndian.PutUint64(tmp[:], moduleID)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], expiry)
	buf = append(buf, tmp[:]...)
	return common.SpxHash(buf)
}
