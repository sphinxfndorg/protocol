// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/gas.go
package types

import "math/big"

// GetGasFee returns GasLimit × GasPrice in nSPX.
// Returns zero if either field is nil.
func (tx *Transaction) GetGasFee() *big.Int {
	if tx.GasLimit == nil || tx.GasPrice == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(tx.GasLimit, tx.GasPrice)
}
