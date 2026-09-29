// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// consensus/validators.go
package consensus

// MinValidators is the BFT safety floor: a genesis file that lists fewer than
// this many validators is rejected. It is a GENESIS SANITY RULE, not a runtime
// wait condition — consensus never waits for a node count to be reached, and
// no start-up path may block on it. Membership itself comes exclusively from
// chain state (the genesis file, then on-chain Stake/Unstake transactions).
const MinValidators = 3
