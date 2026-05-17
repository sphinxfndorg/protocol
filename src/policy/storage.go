// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/policy/storage.go
package policy

import (
	"math/big"
)

// CalculateStorageCost calculates the cost for storing data
func (p *PolicyParameters) CalculateStorageCost(bytes uint64, months float64) *StoragePricing {
	// Convert months to days (approximate)
	days := uint64(months * 30)

	// Calculate cost per month
	costPerMonth := new(big.Int).Mul(
		p.PinRatePerGBMonth,
		new(big.Int).SetUint64(bytes),
	)
	// Divide by 1GB (1e9) since PinRate is per GB
	costPerMonth = new(big.Int).Div(costPerMonth, big.NewInt(1e9))

	// Calculate total cost
	totalCost := new(big.Int).Mul(costPerMonth, new(big.Int).SetUint64(uint64(months)))

	return &StoragePricing{
		Bytes:        bytes,
		DurationDays: days,
		CostPerMonth: costPerMonth,
		TotalCost:    totalCost,
	}
}

// CalculatePinningCost calculates the cost for pinning data (long-term storage)
func (p *PolicyParameters) CalculatePinningCost(bytes uint64, months uint64) *big.Int {
	// PinRate * (bytes / GB) * months
	// Convert bytes to GB (1 GB = 1e9 bytes)
	gb := new(big.Float).SetUint64(bytes)
	gb.Quo(gb, big.NewFloat(1e9))

	// Multiply by months
	monthsFloat := new(big.Float).SetUint64(months)
	gb.Mul(gb, monthsFloat)

	// Multiply by PinRate (0.01 SPX)
	rate := new(big.Float).SetFloat64(0.01)
	gb.Mul(gb, rate)

	// Convert to nSPX (1 SPX = 1e18 nSPX)
	nspx := new(big.Float).Mul(gb, new(big.Float).SetFloat64(1e18))

	result, _ := nspx.Int(nil)
	return result
}
