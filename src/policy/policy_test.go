package policy

import (
	"math/big"
	"testing"
)

func TestCalculateTxFee(t *testing.T) {
	p := NewPolicyParameters()

	txSize := uint64(1024)
	ops := uint64(1000)

	fee := p.CalculateTxFee(txSize, ops)
	expected := big.NewInt(5061441000)

	if fee.Cmp(expected) != 0 {
		t.Errorf("Expected %v, got %v", expected, fee)
	}

	// Test conversion to SPX
	// 5,061,441,000 nSPX = 5.061441e-9 SPX
	feeSPX := p.CalculateTxFeeInSPX(txSize, ops)
	expectedSPX := 5.061441e-9 // 0.000000005061441 SPX

	t.Logf("Fee in SPX: %.15f", feeSPX)
	t.Logf("Expected SPX: %.15f", expectedSPX)

	// Allow small floating point error
	if feeSPX < expectedSPX-1e-15 || feeSPX > expectedSPX+1e-15 {
		t.Errorf("Expected SPX %e, got %e", expectedSPX, feeSPX)
	}
}

func TestCalculateSigFee(t *testing.T) {
	p := NewPolicyParameters()

	metadataSize := uint64(512)
	numHashes := uint64(10)

	fee := p.CalculateSigFee(metadataSize, numHashes)

	// Expected: B_st * (M * R) + α * H + β
	// = 200000 * (512 * 3) + 10000 * 10 + 200000
	// = 200000 * 1536 + 100000 + 200000
	// = 307,200,000 + 300,000 = 307,500,000 nSPX
	expected := big.NewInt(307500000)

	if fee.Cmp(expected) != 0 {
		t.Errorf("Expected %v, got %v", expected, fee)
	}
}

func TestCalculateContractFee(t *testing.T) {
	p := NewPolicyParameters()

	opCount := uint64(5000)
	storageBytes := uint64(1024)

	fee := p.CalculateContractFee(opCount, storageBytes)

	// Expected: B_cmp * C + B_st * S_contract
	// = 5,000,000 * 5000 + 200,000 * 1024
	// = 25,000,000,000 + 204,800,000 = 25,204,800,000 nSPX
	expected := big.NewInt(25204800000)

	if fee.Cmp(expected) != 0 {
		t.Errorf("Expected %v, got %v", expected, fee)
	}
}

func TestCalculateIPFSFee(t *testing.T) {
	p := NewPolicyParameters()

	// Test with 1GB for 1 month
	dataSize := uint64(1073741824) // 1 GB = 1024^3
	months := uint64(1)

	feeSPX := p.CalculateIPFSFee(dataSize, months)
	expectedSPX := 0.01 // 0.01 SPX

	if feeSPX != expectedSPX {
		t.Errorf("Expected SPX %f, got %f", expectedSPX, feeSPX)
	}

	feeNSPX := p.CalculateIPFSFeeInNSPX(dataSize, months)
	expectedNSPX := big.NewInt(10000000000000000) // 0.01 * 1e18 = 1e16

	if feeNSPX.Cmp(expectedNSPX) != 0 {
		t.Errorf("Expected nSPX %v, got %v", expectedNSPX, feeNSPX)
	}
}

func TestCalculateAnnualInflation(t *testing.T) {
	p := NewPolicyParameters()

	// Year 1: 5%
	year1 := p.CalculateAnnualInflation(1)
	// Allow small floating point error
	if year1 < 0.049999 || year1 > 0.050001 {
		t.Errorf("Year 1 inflation expected 0.05, got %f", year1)
	}

	// Year 2: 5% * 0.8^1 = 4%
	year2 := p.CalculateAnnualInflation(2)
	expectedYear2 := 0.04
	if year2 < expectedYear2-0.000001 || year2 > expectedYear2+0.000001 {
		t.Errorf("Year 2 inflation expected %f, got %f", expectedYear2, year2)
	}

	// Year 3: 5% * 0.8^2 = 3.2%
	year3 := p.CalculateAnnualInflation(3)
	expectedYear3 := 0.032
	if year3 < expectedYear3-0.000001 || year3 > expectedYear3+0.000001 {
		t.Errorf("Year 3 inflation expected %f, got %f", expectedYear3, year3)
	}
}

func TestDistributeFees(t *testing.T) {
	p := NewPolicyParameters()

	totalFees := big.NewInt(1000000000000000000) // 1 SPX in nSPX

	distribution := p.DistributeFees(totalFees)

	// Validators: 60% = 0.6 SPX = 6e17 nSPX
	expectedValidators := big.NewInt(600000000000000000)
	if distribution.Validators.Cmp(expectedValidators) != 0 {
		t.Errorf("Validators expected %v, got %v", expectedValidators, distribution.Validators)
	}

	// Stakers: 25% = 0.25 SPX = 2.5e17 nSPX
	expectedStakers := big.NewInt(250000000000000000)
	if distribution.Stakers.Cmp(expectedStakers) != 0 {
		t.Errorf("Stakers expected %v, got %v", expectedStakers, distribution.Stakers)
	}

	// Treasury: 10% = 0.1 SPX = 1e17 nSPX
	expectedTreasury := big.NewInt(100000000000000000)
	if distribution.Treasury.Cmp(expectedTreasury) != 0 {
		t.Errorf("Treasury expected %v, got %v", expectedTreasury, distribution.Treasury)
	}

	// Burned: 5% = 0.05 SPX = 5e16 nSPX
	expectedBurned := big.NewInt(50000000000000000)
	if distribution.Burned.Cmp(expectedBurned) != 0 {
		t.Errorf("Burned expected %v, got %v", expectedBurned, distribution.Burned)
	}
}

func TestDynamicBaseRate(t *testing.T) {
	p := NewPolicyParameters()

	currentRate := big.NewInt(20000)

	// Test with utilization = target (0.7)
	utilization := 0.7
	newRate := p.CalculateDynamicBaseRate(currentRate, utilization)
	expected := big.NewInt(20000)
	if newRate.Cmp(expected) != 0 {
		t.Errorf("Expected %v, got %v", expected, newRate)
	}

	// Test with high utilization (0.9)
	utilization = 0.9
	newRate = p.CalculateDynamicBaseRate(currentRate, utilization)
	expected = big.NewInt(20400)
	// Allow for rounding differences
	if newRate.Cmp(expected) != 0 {
		t.Errorf("Expected %v, got %v", expected, newRate)
	}

	// Test with low utilization (0.5)
	utilization = 0.5
	newRate = p.CalculateDynamicBaseRate(currentRate, utilization)
	expected = big.NewInt(19600)
	// Allow for rounding differences
	if newRate.Cmp(expected) != 0 && newRate.Cmp(big.NewInt(19599)) != 0 {
		t.Errorf("Expected %v, got %v", expected, newRate)
	}
}

func TestConversion(t *testing.T) {
	p := NewPolicyParameters()

	// Test nSPX to SPX
	nspx := big.NewInt(1000000000000000000) // 1 SPX
	spx := p.ConvertNSPXToSPX(nspx)
	if spx != 1.0 {
		t.Errorf("Expected 1.0 SPX, got %f", spx)
	}

	// Test SPX to nSPX
	spxValue := 1.0
	nspxValue := p.ConvertSPXToNSPX(spxValue)
	expectedNSPX := big.NewInt(1000000000000000000)
	if nspxValue.Cmp(expectedNSPX) != 0 {
		t.Errorf("Expected %v, got %v", expectedNSPX, nspxValue)
	}

	// Test small value
	smallNSPX := big.NewInt(1000000000000000) // 0.001 SPX
	smallSPX := p.ConvertNSPXToSPX(smallNSPX)
	if smallSPX != 0.001 {
		t.Errorf("Expected 0.001 SPX, got %f", smallSPX)
	}
}

func TestBlocksPerYear(t *testing.T) {
	p := NewPolicyParameters()

	blocksPerYear := p.GetBlocksPerYear()
	expected := uint64(2628000) // 31,536,000 / 12

	if blocksPerYear != expected {
		t.Errorf("Expected %d blocks/year, got %d", expected, blocksPerYear)
	}
}

func TestEpochsPerYear(t *testing.T) {
	p := NewPolicyParameters()

	epochsPerYear := p.GetEpochsPerYear()
	expected := uint64(876000) // 2,628,000 / 3

	if epochsPerYear != expected {
		t.Errorf("Expected %d epochs/year, got %d", expected, epochsPerYear)
	}
}

func TestCalculateAPY(t *testing.T) {
	p := NewPolicyParameters()

	totalStake := new(big.Int)
	totalStake.SetString("700000000000000000000", 10) // 700 SPX (70% of 1000 SPX)
	totalSupply := new(big.Int)
	totalSupply.SetString("1000000000000000000000", 10) // 1000 SPX
	year := uint64(1)
	currentStakeRatio := 0.7

	apy := p.CalculateAPY(totalStake, totalSupply, year, currentStakeRatio)

	// Annual minting: 1000 * 0.05 = 50 SPX
	// Staking rewards: 50 * 0.8 = 40 SPX
	// APY: 40 / 700 = 0.05714 (5.714%)
	expectedAPY := 0.05714285714285714

	if apy != expectedAPY {
		t.Errorf("Expected APY %f, got %f", expectedAPY, apy)
	}
}
