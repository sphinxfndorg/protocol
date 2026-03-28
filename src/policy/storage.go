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
