// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/rpc_gas_test.go
package gui

import (
	"math/big"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	"github.com/sphinxfndorg/protocol/src/contracts"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// TestSIP721DeployGasLimitIncludesBaseTransactionGas guards the regression that
// made "Deploy New Collection" fail on-chain with:
//
//	deploy failed: RPC error: RPC error (-3262): gas limit below policy
//	minimum: offered 107050, required 128050
//
// core.Blockchain.RequiredTransactionGas charges the BASE TRANSACTION GAS on
// top of the contract-deploy quote, so a client that quotes only
// QuoteContractGas is always short by BaseTransactionGas (21,000) and the node
// rejects the broadcast at admission. The GUI takes its gasLimit from
// abi.NewSIP721DeployTx now, so this asserts the shared quote rather than a
// GUI-local copy of it.
func TestSIP721DeployGasLimitIncludesBaseTransactionGas(t *testing.T) {
	p := policy.GetDefaultPolicyParams()
	if p.MinimumGasPrice == nil || p.MinimumGasPrice.Sign() <= 0 {
		t.Fatal("policy MinimumGasPrice must be positive")
	}

	const rawOwner = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
	deployTx, err := abi.NewSIP721DeployTx(abi.TxOptions{ChainID: 7331, Sender: rawOwner},
		contracts.DeploySpec{Name: "Collection", Symbol: "COLL", Owner: rawOwner})
	if err != nil {
		t.Fatalf("NewSIP721DeployTx: %v", err)
	}
	codeBytes := uint64(len(deployTx.Code))

	base := p.QuoteTransactionGas(0)
	contractOnly := p.QuoteContractGas(true, codeBytes, 0, 0)

	// The contract-only quote is exactly what used to be sent; the quoted
	// limit must now be strictly above it.
	if contractOnly.GasLimit.Cmp(deployTx.GasLimit) >= 0 {
		t.Fatalf("deploy gas limit must exceed the contract-only quote: contract=%s got=%s",
			contractOnly.GasLimit, deployTx.GasLimit)
	}

	// It must be precisely the node's required sum.
	want := new(big.Int).Add(base.GasLimit, contractOnly.GasLimit)
	if deployTx.GasLimit.Cmp(want) != 0 {
		t.Fatalf("deploy gas limit mismatch: got %s want %s (base %s + contract %s)",
			deployTx.GasLimit, want, base.GasLimit, contractOnly.GasLimit)
	}

	// Explicit numeric expectation straight from the policy schedule, for the
	// 141-byte deploy spec in the failing report:
	// 21000 + 100000 + 141*50 = 128050. A silent change to any of the three
	// parameters is caught here.
	const reportedCodeBytes = 141
	explicit := new(big.Int).SetUint64(p.BaseTransactionGas + p.ContractDeployGas)
	explicit.Add(explicit, new(big.Int).Mul(
		new(big.Int).SetUint64(reportedCodeBytes),
		new(big.Int).SetUint64(p.ContractCodeGasByte),
	))
	if explicit.Uint64() != 128050 {
		t.Fatalf("expected 128050 gas for a %d-byte deploy spec, got %s", reportedCodeBytes, explicit)
	}

	// The gas price offered alongside it must be the node's floor.
	if deployTx.GasPrice.Cmp(p.MinimumGasPrice) != 0 {
		t.Fatalf("deploy gas price = %s, want the policy minimum %s", deployTx.GasPrice, p.MinimumGasPrice)
	}
}

// TestSameIdentityMatchesStorageAndDisplayForms covers the marketplace's
// owner/seller/licensee comparisons: contract storage returns canonical raw
// UPPERCASE hex while the session holds the "SPIF XXXX XXXX …" display form, so
// a plain == never matched and a minter could never list their own token.
func TestSameIdentityMatchesStorageAndDisplayForms(t *testing.T) {
	const raw = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"

	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"raw vs display prefix", raw, "SPIF " + raw, true},
		{"display vs raw", "SPIF " + raw, raw, true},
		{"grouped display", "SPIF AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD EEFF 0011 2233 4455 6677 8899", raw, true},
		{"lowercase raw", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", raw, true},
		{"different identities", raw, "BBBBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899", false},
		{"empty storage value", "", raw, false},
		{"empty session", raw, "", false},
		{"both empty", "", "", false},
		{"non-address exact match", "genesis", "GENESIS", true},
		{"non-address mismatch", "genesis", "treasury", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameIdentity(tc.a, tc.b); got != tc.want {
				t.Fatalf("sameIdentity(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestSIP721CallTxGasIncludesBaseTransactionGas guards the same two-component
// contract on the contract-call path: the shared abi builder that CallSIP721
// now dispatches through must offer base transaction gas + contract-call gas,
// exactly like core.Blockchain.RequiredTransactionGas — and an escrow-carrying
// buy must quote identically, because value is not gas.
func TestSIP721CallTxGasIncludesBaseTransactionGas(t *testing.T) {
	p := policy.GetDefaultPolicyParams()

	const sender = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
	const collection = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF"

	tx, err := abi.NewSIP721CallTx(abi.TxOptions{ChainID: 7331, Sender: sender}, collection, "buy",
		map[string]string{"token_id": "1"})
	if err != nil {
		t.Fatalf("NewSIP721CallTx: %v", err)
	}

	base := p.QuoteTransactionGas(0)
	if tx.GasLimit.Cmp(base.GasLimit) <= 0 {
		t.Fatalf("call gas limit must exceed base transaction gas: got %s base %s", tx.GasLimit, base.GasLimit)
	}

	want := new(big.Int).Add(base.GasLimit,
		p.QuoteContractGas(false, 0, uint64(len(tx.CallData)), 0).GasLimit)
	if tx.GasLimit.Cmp(want) != 0 {
		t.Fatalf("call gas limit mismatch: got %s want %s", tx.GasLimit, want)
	}
	if tx.GasPrice == nil || tx.GasPrice.Cmp(p.MinimumGasPrice) != 0 {
		t.Fatalf("call gas price must be the policy minimum: got %v want %s", tx.GasPrice, p.MinimumGasPrice)
	}
	if tx.Amount == nil || tx.Amount.Sign() != 0 {
		t.Fatalf("the raw call builder carries no escrow: got %v, want 0", tx.Amount)
	}

	// The escrow-carrying typed builder must quote identically.
	escrowTx, err := (abi.SIP721Contract{Address: collection}).BuyTx(
		abi.TxOptions{ChainID: 7331, Sender: sender}, 1, "1200")
	if err != nil {
		t.Fatalf("BuyTx: %v", err)
	}
	if escrowTx.GasLimit.Cmp(tx.GasLimit) != 0 || escrowTx.GasPrice.Cmp(tx.GasPrice) != 0 {
		t.Fatalf("escrow changed the gas quote: %s/%s vs %s/%s",
			escrowTx.GasLimit, escrowTx.GasPrice, tx.GasLimit, tx.GasPrice)
	}
	if escrowTx.Amount == nil || escrowTx.Amount.String() != "1200" {
		t.Fatalf("BuyTx escrow = %v, want 1200", escrowTx.Amount)
	}
}

// TestTransferPriorityTiersScaleFeeLinearly locks in the 1x/2x/5x tier math:
// fee(tier) must equal multiplier × fee(standard) at the same memo size, the
// gas limit must be identical across tiers (only price moves), and the custom
// path must match its multiplier exactly. This sits in the cheap,
// clearly-differentiated part of calculatePriority's curve (~1 point per
// 1 gSPX, capped at +100), so 1/2/5 gSPX never bunch near the flat top.
func TestTransferPriorityTiersScaleFeeLinearly(t *testing.T) {
	const memoLen = 11 // "hello world" footprint: 21000 + 11*100 = 22100 gas
	std := QuoteTransferGas(memoLen, PriorityStandard, 0)
	med := QuoteTransferGas(memoLen, PriorityMedium, 0)
	high := QuoteTransferGas(memoLen, PriorityHigh, 0)
	custom3 := QuoteTransferGas(memoLen, PriorityCustom, 3)

	// Gas limit is memo-derived and tier-independent.
	for name, q := range map[string]*policy.GasQuote{"medium": med, "high": high, "custom3": custom3} {
		if q.GasLimit.Cmp(std.GasLimit) != 0 {
			t.Fatalf("%s gas limit must equal standard's: got %s want %s", name, q.GasLimit, std.GasLimit)
		}
	}
	if std.GasLimit.Uint64() != 22100 {
		t.Fatalf("expected 22100 gas for an 11-byte memo, got %s", std.GasLimit)
	}

	// Fee scales exactly with the multiplier: 1x/2x/5x/3x.
	check := func(name string, q *policy.GasQuote, mult uint64) {
		wantPrice := new(big.Int).Mul(policy.GetDefaultPolicyParams().MinimumGasPrice, new(big.Int).SetUint64(mult))
		if q.GasPrice.Cmp(wantPrice) != 0 {
			t.Fatalf("%s gas price: got %s want %s", name, q.GasPrice, wantPrice)
		}
		wantFee := new(big.Int).Mul(std.GasFee, new(big.Int).SetUint64(mult))
		if q.GasFee.Cmp(wantFee) != 0 {
			t.Fatalf("%s fee must be %dx standard: got %s want %s", name, mult, q.GasFee, wantFee)
		}
	}
	check("medium", med, 2)
	check("high", high, 5)
	check("custom3", custom3, 3)

	// Tier labels stay honest: High promises "faster under congestion",
	// never "fastest" — a static multiplier cannot outbid an unobserved mempool.
	if got := PriorityHigh.Label(); got == PriorityStandard.Label() {
		t.Fatalf("high and standard labels must differ, both %q", got)
	}
	for _, s := range []string{PriorityStandard.Label(), PriorityMedium.Label(), PriorityHigh.Label(), PriorityCustom.Label()} {
		if strings.Contains(strings.ToLower(s), "fastest") {
			t.Fatalf("tier label %q must not promise \"fastest\"", s)
		}
	}
	if got := priorityTierLabel(PriorityCustom, 7); got != "Custom (7x)" {
		t.Fatalf("custom tier label must carry its multiplier, got %q", got)
	}
	if got := priorityFromLabel("bogus label"); got != PriorityStandard {
		t.Fatalf("unknown label must fall back to Standard, got %v", got)
	}
}

// TestValidateCustomMultiplierClamp covers the fee-selector guard rails:
// below 1x the node would reject the tx (price < MinimumGasPrice), so it is
// an error; above 100x is allowed but flagged so the UI can warn before
// broadcasting a likely fat-finger.
func TestValidateCustomMultiplierClamp(t *testing.T) {
	if _, err := ValidateCustomMultiplier(0); err == nil {
		t.Fatal("multiplier 0 must be rejected (below node minimum)")
	}
	for _, mult := range []uint64{1, 2, 5, 100} {
		if warn, err := ValidateCustomMultiplier(mult); err != nil || warn {
			t.Fatalf("multiplier %d must pass cleanly, got warn=%v err=%v", mult, warn, err)
		}
	}
	if warn, err := ValidateCustomMultiplier(101); err != nil || !warn {
		t.Fatalf("multiplier 101 must warn but not fail, got warn=%v err=%v", warn, err)
	}
}

// TestGasPriceRenderedInGSPXNotSPX locks in the fix for the Send screen's fee
// line that read "0 SPX/gas" for every tier. Gas prices are denominated in
// gSPX (Giga SPX): policy.MinimumGasPrice is 1,000,000,000 nSPX = 1 gSPX =
// 10^-9 SPX, and the CLI's flag is literally "Gas price in gSPX" (default 1).
// Rendering that through formatSPXAmount — which prints at most six decimal
// places — collapsed the minimum and every tier (2x, 5x) to a flat "0".
func TestGasPriceRenderedInGSPXNotSPX(t *testing.T) {
	p := policy.GetDefaultPolicyParams()

	// The unit anchor this whole fix rests on: one gSPX in nSPX, and the
	// policy minimum being exactly one of them.
	if nSPXPerGSPX.Cmp(new(big.Float).SetInt64(1_000_000_000)) != 0 {
		t.Fatalf("nSPXPerGSPX must be 1e9, got %s", nSPXPerGSPX.Text('f', -1))
	}
	if got := p.MinimumGasPrice.Uint64(); got != 1_000_000_000 {
		t.Fatalf("policy minimum gas price must be 1 gSPX (1e9 nSPX), got %d", got)
	}

	// Every tier must render legibly in gSPX — never the "0" the SPX
	// conversion produced.
	for _, tc := range []struct {
		mult uint64
		want string
	}{
		{1, "1"},
		{2, "2"},
		{3, "3"},
		{5, "5"},
		{100, "100"},
	} {
		price := new(big.Int).Mul(p.MinimumGasPrice, new(big.Int).SetUint64(tc.mult))
		got := formatGasPriceAmount(price)
		if got != tc.want {
			t.Fatalf("formatGasPriceAmount(%dx minimum) = %q, want %q", tc.mult, got, tc.want)
		}
		if got == "0" {
			t.Fatalf("%dx minimum must not render as \"0\" — that is the reported bug", tc.mult)
		}
		// The unit tag must name the unit the number is actually in.
		if strings.Contains(gasPriceUnitLabel, "SPX/gas") && !strings.HasPrefix(gasPriceUnitLabel, "gSPX") {
			t.Fatalf("gas price unit must be gSPX/gas, got %q", gasPriceUnitLabel)
		}
	}

	// A fractional gas price (mint anchors raise the price until the gas fee
	// reaches the mint fee, so it is not always a whole gSPX) must keep its
	// precision instead of being rounded away.
	if got := formatGasPriceAmount(big.NewInt(1_500_000_000)); got != "1.5" {
		t.Fatalf("1.5 gSPX must render as \"1.5\", got %q", got)
	}
	if got := formatGasPriceAmount(big.NewInt(2_250_000_000)); got != "2.25" {
		t.Fatalf("2.25 gSPX must render as \"2.25\", got %q", got)
	}

	// nil is inert, never a panic.
	if got := formatGasPriceAmount(nil); got != "0" {
		t.Fatalf("nil gas price must render \"0\", got %q", got)
	}

	// The regression, stated directly: the same value that read "0 SPX/gas"
	// under the old SPX conversion now reads "1 gSPX/gas".
	oldSPX := new(big.Float).Quo(new(big.Float).SetInt(p.MinimumGasPrice), big.NewFloat(1e18))
	if formatSPXAmount(oldSPX) != "0" {
		t.Fatalf("precondition: the SPX conversion must collapse the minimum to 0 (got %q)", formatSPXAmount(oldSPX))
	}
	if formatGasPriceAmount(p.MinimumGasPrice) != "1" {
		t.Fatalf("the gSPX conversion must render the minimum as 1, got %q", formatGasPriceAmount(p.MinimumGasPrice))
	}
}

// TestTransferStatusPopupFeeRowsRenderGasPriceInGSPX locks in the exact rows
// the send flow's "Transfer Status" pop-up shows in its "Transaction Fee"
// section — the panel that used to read "0 SPX/gas" for every tier.
//
// transferFeeRows is the single pure function that produces those four rows, so
// what a user reads off that panel is assertable here instead of being
// assembled (and mis-denominated) inline inside a background worker goroutine.
func TestTransferStatusPopupFeeRowsRenderGasPriceInGSPX(t *testing.T) {
	p := policy.GetDefaultPolicyParams()

	// One representative send: an 11-byte memo at the High (5x) tier, which
	// quotes 21000 + 11*100 = 22100 gas at 5 gSPX/gas.
	quote := QuoteTransferGas(11, PriorityHigh, 0)
	tierLabel := priorityTierLabel(PriorityHigh, 0)
	rows := transferFeeRows("SPX", quote.GasFee, quote.GasLimit.Uint64(), quote.GasPrice, tierLabel)

	// ── Gas price: denominated in gSPX, never a bare SPX figure ──────────
	// The policy minimum is 1 gSPX = 10^-9 SPX, so an SPX rendering of this
	// row printed "0" for the minimum and every tier derived from it.
	if !strings.HasSuffix(rows.GasPriceText, gasPriceUnitLabel) {
		t.Fatalf("gas price row must be labelled %q, got %q", gasPriceUnitLabel, rows.GasPriceText)
	}
	if strings.Contains(rows.GasPriceText, " SPX") {
		t.Fatalf("gas price row must not be denominated in SPX: %q", rows.GasPriceText)
	}
	if want := "5 " + gasPriceUnitLabel; rows.GasPriceText != want {
		t.Fatalf("High tier must render its 5x price as %q, got %q", want, rows.GasPriceText)
	}

	// ── The other three rows ─────────────────────────────────────────────
	if want := "22100 gas units"; rows.GasLimitText != want {
		t.Fatalf("gas limit row = %q, want %q", rows.GasLimitText, want)
	}
	if rows.PriorityText != tierLabel {
		t.Fatalf("priority row = %q, want %q", rows.PriorityText, tierLabel)
	}
	if !strings.HasSuffix(rows.GasFeeText, " SPX") {
		t.Fatalf("gas fee row must be denominated in SPX, got %q", rows.GasFeeText)
	}
	// The fee amount itself must stay a real, positive amount — the panel must
	// not have collapsed it to "0 SPX" alongside the price bug.
	feeAmount := strings.TrimSuffix(rows.GasFeeText, " SPX")
	fee, _, ferr := big.ParseFloat(feeAmount, 10, 256, big.ToNearestEven)
	if ferr != nil {
		t.Fatalf("gas fee row %q is not a parseable amount: %v", rows.GasFeeText, ferr)
	}
	if fee.Sign() <= 0 {
		t.Fatalf("a real send must show a positive gas fee, got %q", rows.GasFeeText)
	}

	// Resolved rows must be readable, not left muted/placeholder.
	if rows.GasPriceColor == colFaint || rows.GasFeeColor == colFaint || rows.GasLimitColor == colFaint {
		t.Fatal("resolved fee rows must not keep the placeholder colour")
	}

	// ── Every tier, and every custom multiplier, stays legible ───────────
	tiers := []struct {
		name  string
		quote *policy.GasQuote
		want  string
	}{
		{"standard", QuoteTransferGas(11, PriorityStandard, 0), "1 " + gasPriceUnitLabel},
		{"medium", QuoteTransferGas(11, PriorityMedium, 0), "2 " + gasPriceUnitLabel},
		{"high", quote, "5 " + gasPriceUnitLabel},
		{"custom 100x", QuoteTransferGas(11, PriorityCustom, 100), "100 " + gasPriceUnitLabel},
	}
	for _, tc := range tiers {
		t.Run(tc.name, func(t *testing.T) {
			got := transferFeeRows("SPX", tc.quote.GasFee, tc.quote.GasLimit.Uint64(), tc.quote.GasPrice, tc.name).GasPriceText
			if got != tc.want {
				t.Fatalf("gas price row = %q, want %q", got, tc.want)
			}
			if strings.HasPrefix(got, "0 ") {
				t.Fatalf("tier %s must not render as a zero price (%q) — that is the reported bug", tc.name, got)
			}
		})
	}

	// ── The regression, stated directly ─────────────────────────────────
	// The same value read "0 SPX/gas" under the SPX conversion and "1
	// gSPX/gas" under the gSPX one.
	oldSPX := new(big.Float).SetPrec(256).Quo(new(big.Float).SetPrec(256).SetInt(p.MinimumGasPrice), big.NewFloat(1e18))
	if formatSPXAmount(oldSPX) != "0" {
		t.Fatalf("precondition: the SPX conversion must collapse the minimum to 0 (got %q)", formatSPXAmount(oldSPX))
	}
	if got := transferFeeRows(chainSymbolSPX, nil, 0, p.MinimumGasPrice, "").GasPriceText; got != "1 "+gasPriceUnitLabel {
		t.Fatalf("the minimum gas price must render as %q, got %q", "1 "+gasPriceUnitLabel, got)
	}

	// ── Unresolved rows are a sentinel, never a zero ────────────────────
	// "not known yet" must never be mistaken for "zero priced".
	unresolved := transferFeeRows("SPX", nil, 0, nil, "")
	for name, got := range map[string]string{
		"gas fee":   unresolved.GasFeeText,
		"gas limit": unresolved.GasLimitText,
		"gas price": unresolved.GasPriceText,
		"priority":  unresolved.PriorityText,
	} {
		if got != feeRowPlaceholder {
			t.Fatalf("%s row must stay the placeholder %q until known, got %q", name, feeRowPlaceholder, got)
		}
		if strings.Contains(got, "0") {
			t.Fatalf("%s row must not read as a zero value, got %q", name, got)
		}
	}
	if unresolved.GasPriceColor != colFaint || unresolved.GasFeeColor != colFaint {
		t.Fatal("unresolved fee rows must keep the muted placeholder colour")
	}

	// A zero (but known) gas price is still a real value, not a placeholder:
	// the sentinel distinguishes "unknown" from "0", so neither can masquerade
	// as the other.
	zeroPrice := transferFeeRows("SPX", nil, 0, big.NewInt(0), "")
	if zeroPrice.GasPriceText != feeRowPlaceholder {
		t.Fatalf("a non-positive gas price is not a price and must stay %q, got %q", feeRowPlaceholder, zeroPrice.GasPriceText)
	}
}

// chainSymbolSPX keeps the pop-up fee-row assertions tied to the chain's own
// symbol constant rather than a stray literal.
const chainSymbolSPX = "SPX"

// TestStartupBeaconStatesBuildAndGasDenomination locks in the two log lines Run
// prints before it touches a key or an RPC endpoint.
//
// They exist to close the one gap that made the "gas price always shows
// 0 SPX/gas" report hard to settle: a wrong value on screen and a stale binary
// on disk look identical from inside the UI. buildBeaconLine says which build
// is running (module, revision, dirty flag, toolchain) and gasUnitBeaconLine
// says — through the very same formatters the panel uses — that the policy
// minimum is 1 gSPX/gas, which the old 6-decimal SPX rendering rounded to "0".
func TestStartupBeaconStatesBuildAndGasDenomination(t *testing.T) {
	p := policy.GetDefaultPolicyParams()
	if p == nil || p.MinimumGasPrice == nil {
		t.Fatal("policy must expose a positive MinimumGasPrice")
	}

	buildLine := buildBeaconLine()
	if !strings.HasPrefix(buildLine, "build: ") {
		t.Fatalf("build beacon must identify the running build, got %q", buildLine)
	}
	if !strings.Contains(buildLine, "go=") {
		t.Fatalf("build beacon must name the toolchain, got %q", buildLine)
	}

	// Printed with -v so the actual startup output is visible in the test log:
	// these two lines are literally what Run puts on the terminal.
	t.Logf("[USI-GUI] %s", buildLine)

	gasLine := gasUnitBeaconLine()
	t.Logf("[USI-GUI] %s", gasLine)
	want := formatGasPriceAmount(p.MinimumGasPrice) + " " + gasPriceUnitLabel
	if !strings.Contains(gasLine, want) {
		t.Fatalf("gas beacon must state the minimum as %q, got %q", want, gasLine)
	}
	if !strings.Contains(gasLine, p.MinimumGasPrice.String()) {
		t.Fatalf("gas beacon must state the raw nSPX value %s, got %q", p.MinimumGasPrice, gasLine)
	}

	// It must name the gSPX unit — and must never present an SPX gas unit as
	// the one in use, which is the exact wording of the reported bug.
	if !strings.Contains(gasLine, gasPriceUnitLabel) {
		t.Fatalf("gas beacon must name the %s unit, got %q", gasPriceUnitLabel, gasLine)
	}
	if strings.Contains(gasLine, "0 SPX/gas") {
		t.Fatalf("gas beacon must not claim a zero-priced SPX gas unit, got %q", gasLine)
	}

	// The beacon must spell out the rounding that caused the bug, so the log
	// alone explains why the old panel read 0.
	oldSPX := new(big.Float).SetPrec(256).Quo(
		new(big.Float).SetPrec(256).SetInt(p.MinimumGasPrice),
		big.NewFloat(1e18),
	)
	if !strings.Contains(gasLine, "\""+formatSPXAmount(oldSPX)+"\"") {
		t.Fatalf("gas beacon must show the SPX rendering (%q) that caused the bug, got %q",
			formatSPXAmount(oldSPX), gasLine)
	}
}
