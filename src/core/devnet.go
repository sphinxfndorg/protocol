// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/devnet_custody.go
//
// Devnet auto-custody: zero-command provisioning of BOTH custody policies the
// node knows about — the genesis vault (which authorizes block 0's
// distributions) and the CGE escrow (whose address block 0 funds) — so a
// devnet node started with no policy files present just works end to end with
// real M-of-N custody underneath.
//
// ★ DEVNET ONLY, FAIL-CLOSED. Nothing here runs unless the resolved network is
// devnet (chain 73310). On testnet/mainnet the function returns immediately and
// today's behaviour is untouched: a missing policy means an unsigned genesis
// and a disabled spend watcher, exactly as before. That gate is the whole point
// of the feature — it is convenience for a throwaway chain, and it must never
// be able to arm itself on a chain that carries value.
//
// ★ WHAT "AUTO" COSTS. Every witness is a real STHINCS signature (~7s each on
// this parameter set) and block 0 needs a threshold set for each allocation
// slice, so the node that SIGNS block 0 pays ~3 minutes once. That cost is why
// the producer persists the witness set to config/: witnesses are public data
// (they ride in block 0 anyway), so peer nodes rebuild a byte-identical block 0
// from them instantly and never need a custodian key. Secret keys stay under
// data/custody/devnet-auto/ and are never distributed.
//
// ★ WHY EVERY NODE MUST REBUILD BLOCK 0 IDENTICALLY. core.getCachedGenesisBlock
// computes genesis once per process and every node uses that hash in key
// exchange to reject mismatched peers. A witness-bearing block 0 is therefore
// only usable when every devnet node can reproduce it byte-for-byte. Signing is
// deterministic here (the production parameter set sets RANDOMIZE=false, so the
// same key signing the same message yields the same signature bytes), which is
// what makes replaying persisted witnesses reproduce the producer's hash.
package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
)

// DevnetChainID is the chain ID every devnet parameter set resolves to
// (SphinxChainParameters.IsDevnet). The auto-custody gate is expressed against
// this, not against a display name, so it cannot be fooled by a renamed chain.
const DevnetChainID uint64 = 73310

const (
	// DefaultDevnetVaultPolicyPath / DefaultDevnetEscrowPolicyPath are the same
	// auto-loaded config paths a real ceremony writes. Auto-custody therefore
	// produces artifacts the rest of the node already understands.
	//
	// ★ LEGACY SHARED-ROOT DEFAULTS. When DevnetCustodyOptions.DataDir is set —
	// which the CLI and bind.StartNode always do — withDefaults() IGNORES these
	// and scopes every path under the node's own datadir instead. These survive
	// only for tests and the same-process harness, which leave DataDir empty.
	DefaultDevnetVaultPolicyPath  = defaultGenesisMultisigPath
	DefaultDevnetEscrowPolicyPath = defaultEscrowMultisigPath

	// DefaultDevnetWitnessPath holds the pre-signed block-0 witness set. It is
	// public data relayed to peer nodes so they need no custodian keys.
	DefaultDevnetWitnessPath = "config/devnet_genesis_witnesses.json"

	// Per-node relative paths used when DataDir is set. Custody private keys
	// live under <datadir>/custody/devnet-auto (NOT data/custody — that prefix
	// is the ceremony/manual `multisig devnet` namespace, and reusing it would
	// let an operator mistake auto-generated throwaways for ceremony keys).
	// Public policies + witness book live under <datadir>/config.
	//
	// ★ TODO(ceremony-loader): the ceremony-side loader must enforce this
	// separation in the OTHER direction — refuse to load a devnet-auto path
	// (any path containing a "devnet-auto" element) as if it were a ceremony
	// artifact. The split here only pays off if the loader treats devnet-auto
	// material as ineligible for ceremony use; otherwise an operator can still
	// point ceremony tooling at a throwaway set.
	//
	// RETIRE-WHEN: see core/ceremony_loader_pending_test.go — the standalone
	// file holding the test that must pass once that loader exists. That file
	// is deliberately separate so the debt is visible in the package listing
	// and greppable:
	//
	//	grep -rn 'RETIRE-WHEN' src/core/
	//
	// TODO(ceremony-loader): attach the ticket that tracks building the loader;
	// the pending test file carries the same unlinked placeholder.
	vaultPolicySubdir      = "config/genesis_multisig.json"
	escrowPolicySubdir     = "config/escrow_multisig.json"
	witnessSubdir          = "config/devnet_genesis_witnesses.json"
	custodyProposalsSubdir = "config/spend_proposals"
	vaultKeysSubdir        = "custody/devnet-auto/vault"
	escrowKeysSubdir       = "custody/devnet-auto/escrow"

	// DefaultDevnetAutoKeysRoot deliberately differs from the ceremony key
	// paths (data/custody/vault, data/custody/escrow) so nobody may later
	// mistake an auto-generated throwaway key for a ceremony key. LEGACY
	// shared-root default — see above; per-node runs scope under DataDir.
	DefaultDevnetAutoKeysRoot  = "data/custody/devnet-auto"
	DefaultDevnetVaultKeysDir  = DefaultDevnetAutoKeysRoot + "/vault"
	DefaultDevnetEscrowKeysDir = DefaultDevnetAutoKeysRoot + "/escrow"

	// DefaultDevnetCustodians / DefaultDevnetThreshold match
	// `multisig devnet --role ...` (3 custodians, threshold 2) so auto and
	// manual provisioning describe the same shape of policy.
	DefaultDevnetCustodians = 3
	DefaultDevnetThreshold  = 2

	// devnetWitnessValidity is the witness horizon on a genesis distribution.
	// It must satisfy musig's [24h, 5y] window measured from the block-0
	// timestamp, and it is bounded, not open-ended, so the persisted witnesses
	// cannot be replayed onto a future chain state.
	devnetWitnessValidity = 30 * 24 * time.Hour
)

// DevnetCustodyOptions configures AutoProvisionDevnetCustody. Zero values take
// the defaults above; tests override the paths so nothing touches the real
// repository config/ or data/ trees.
type DevnetCustodyOptions struct {
	// NetworkType is the resolved network selector ("devnet"/"testnet"/"mainnet").
	NetworkType string

	// BootstrapNode is true only for the node that creates genesis locally
	// (bind.StartNode passes seeds == ""). Only this node may GENERATE the
	// custody set; every other devnet node only loads it. This is what stops N
	// terminals from each minting a competing policy.
	BootstrapNode bool

	// DataDir scopes every default custody/config path to one node. Fully
	// per-node layout: dataDir/config/*.json and dataDir/custody/.... The
	// node never reads the shared repo root, so distributing a devnet is an
	// explicit copy of node1's PUBLIC bundle
	// (genesis_multisig.json, escrow_multisig.json,
	// devnet_genesis_witnesses.json) into each peer's <datadir>/config —
	// the same shape the real ceremony-artifact distribution will take.
	// Empty means the legacy shared-root layout (used by tests and the
	// same-process harness).
	DataDir string

	ChainID          uint64
	GenesisTimestamp int64

	VaultPolicyPath  string
	EscrowPolicyPath string
	WitnessPath      string
	VaultKeysDir     string
	EscrowKeysDir    string

	Custodians int
	Threshold  int
}

// perNodePath scopes a bare relative path under one node's datadir. Empty
// datadir returns the path unchanged (legacy shared-root layout for tests and
// the same-process harness). Single choke point for the rule: relative
// custody/config paths are interpreted per-node whenever the caller supplies
// a datadir, and never fall back to the shared repo root on their own.
func perNodePath(datadir, rel string) string {
	if datadir == "" {
		return rel
	}
	return filepath.Join(datadir, rel)
}

func (o DevnetCustodyOptions) withDefaults() DevnetCustodyOptions {
	scope := func(rel string) string { return perNodePath(o.DataDir, rel) }
	if o.ChainID == 0 {
		o.ChainID = DevnetChainID
	}
	if o.GenesisTimestamp == 0 {
		o.GenesisTimestamp = CanonicalGenesisTimestamp
	}
	// Default paths live UNDER the node's own datadir when set — never the
	// shared repo root. The subdir constants are the single source of truth;
	// the exported Default* constants above are the legacy shared-root values
	// tests assert against.
	if o.VaultPolicyPath == "" {
		o.VaultPolicyPath = scope(vaultPolicySubdir)
	}
	if o.EscrowPolicyPath == "" {
		o.EscrowPolicyPath = scope(escrowPolicySubdir)
	}
	if o.WitnessPath == "" {
		o.WitnessPath = scope(witnessSubdir)
	}
	if o.VaultKeysDir == "" {
		o.VaultKeysDir = scope(vaultKeysSubdir)
	}
	if o.EscrowKeysDir == "" {
		o.EscrowKeysDir = scope(escrowKeysSubdir)
	}
	if o.Custodians <= 0 {
		o.Custodians = DefaultDevnetCustodians
	}
	if o.Threshold <= 0 || o.Threshold > o.Custodians {
		o.Threshold = DefaultDevnetThreshold
	}
	return o
}

// CustodyProposalsDirForDataDir returns the spend-proposals inbox for one
// node's datadir (<datadir>/config/spend_proposals); empty datadir keeps the
// legacy shared-root layout. Same per-node rule as the custody defaults: in
// the fully per-node layout every operator-scoped artifact lives under the
// node's own datadir — never the shared repo root.
func CustodyProposalsDirForDataDir(datadir string) string {
	return perNodePath(datadir, custodyProposalsSubdir)
}

// EscrowPolicyPathForDataDir returns the escrow policy path for one node's
// datadir (<datadir>/config/escrow_multisig.json); empty datadir keeps the
// legacy shared-root layout.
func EscrowPolicyPathForDataDir(datadir string) string {
	return perNodePath(datadir, escrowPolicySubdir)
}

// VaultPolicyPathForDataDir / WitnessPathForDataDir: same per-node scoping for
// the genesis vault policy and the persisted block-0 witness book.
func VaultPolicyPathForDataDir(datadir string) string {
	return perNodePath(datadir, vaultPolicySubdir)
}

func WitnessPathForDataDir(datadir string) string {
	return perNodePath(datadir, witnessSubdir)
}

// VaultKeysDirForDataDir / EscrowKeysDirForDataDir: same per-node scoping for
// the devnet-auto custodian key dirs (<datadir>/custody/devnet-auto/...).
func VaultKeysDirForDataDir(datadir string) string {
	return perNodePath(datadir, vaultKeysSubdir)
}

func EscrowKeysDirForDataDir(datadir string) string {
	return perNodePath(datadir, escrowKeysSubdir)
}

type DevnetCustodyResult struct {
	// Enabled is false when auto-custody did not engage (not devnet, test
	// binary, or nothing provisioned yet on a late joiner).
	Enabled bool

	// GeneratedKeys is true when THIS process generated the policies/keys.
	GeneratedKeys bool

	// SigningNode is true when this process must sign block 0 (the producer).
	SigningNode bool

	// ReplayNode is true when pre-signed witnesses were loaded instead.
	ReplayNode bool

	VaultAddress  string
	EscrowAddress string
	WitnessPath   string
}

// DevnetAutoCustodyRequested reports whether networkType selects the devnet
// phase. Deliberately strict: anything that is not exactly "devnet" (including
// empty/unknown values) fails closed to "no".
func DevnetAutoCustodyRequested(networkType string) bool {
	return strings.EqualFold(strings.TrimSpace(networkType), string(PhaseDevnet))
}

// devnetGenesisWitnessBook is the persisted block-0 authorization set: one
// witness per distribution slice, keyed by the slice's nonce (the running
// transaction index allocationsToTxList assigns), plus the binding facts a
// replaying node must agree on before it can rebuild the same block.
type devnetGenesisWitnessBook struct {
	Version       int                                 `json:"version"`
	ChainID       uint64                              `json:"chain_id"`
	VaultAddress  string                              `json:"vault_address"`
	EscrowAddress string                              `json:"escrow_address"`
	Expiry        uint64                              `json:"expiry"`
	Witnesses     map[string]multisig.MultiSigWitness `json:"witnesses"`
}

type devnetCustodianKey struct {
	sk []byte
	pk []byte
}

const devnetKeyFileMode = 0o600

// devnetAutoCustodySkipped reports whether this process must never touch the
// repository's config/ and data/ custody paths. In a `go test` binary that is
// true, for the same reason core's policy auto-load is skipped there (see
// policyAutoLoadDisabled): a developer who has run the devnet flow once would
// otherwise change every test's genesis hash from the files on disk.
//
// It is a variable so a test can exercise the real provisioning logic — the
// same seam pattern as bind.startNodeFn — while production always reads the
// test-binary guard.
var devnetAutoCustodySkipped = policyAutoLoadDisabled

// devnetCustodyMu guards devnetCustodyApplied.
var (
	devnetCustodyMu      sync.Mutex
	devnetCustodyApplied *DevnetCustodyResult
)

// GenesisBlockAlreadyBuilt reports whether the process-global cached genesis
// block has already been computed. Anything that changes the genesis vault or
// escrow address (i.e. auto-provisioning) is only safe BEFORE this turns true,
// because the block's distributions — and therefore its hash — were fixed by
// the vault address at build time.
func GenesisBlockAlreadyBuilt() bool {
	return genesisCached != nil
}

// GenesisCustodyOrderingViolation reports the order-of-operations failure that
// would otherwise be discovered much later as an unrelated-looking
// "insufficient balance" while executing block 0:
//
// an authorizer is armed, yet the cached genesis block was built WITHOUT
// witnesses — so it was built from the legacy vault address, before
// provisioning changed it. The distributions are then paid from an account
// nothing funded, and mintBlockReward reports "no allocations to fund vault".
//
// It returns nil whenever the ordering is fine (no authorizer armed yet, or no
// block built yet, or the built block really does carry witnesses).
func GenesisCustodyOrderingViolation() error {
	auth, _ := getGenesisDistributionAuthorizer()
	if auth == nil || genesisCached == nil {
		return nil
	}
	for _, tx := range genesisCached.Body.TxsList {
		if tx != nil && tx.MultiSigWitness != nil {
			return nil // built through the custody path: ordering was correct
		}
	}
	return fmt.Errorf("genesis block %s was already built WITHOUT custody witnesses before the custody policies were provisioned — it was built from vault %s, so block 0 would pay its distributions from an unfunded account. Provision custody (core.AutoProvisionDevnetCustody) before anything calls core.GetGenesisHash()",
		genesisCached.GetHash(), genesisCached.Body.TxsList[0].Sender)
}

// devnetCustodyBundlePresent reports whether this node's own datadir holds
// custody material it could replay from. Either policy counts: a node with the
// vault policy but not yet the escrow policy is a partial copy, and the
// per-policy checks that follow produce a precise message naming whichever is
// missing. This predicate exists to catch the ALL-ABSENT case, which is the one
// that would otherwise silently diverge from the network.
func devnetCustodyBundlePresent(opts DevnetCustodyOptions) bool {
	return fileExists(opts.VaultPolicyPath) || fileExists(opts.EscrowPolicyPath)
}

// devnetLateJoinerMissingBundleError is the refusal for a devnet node started
// with --seeds whose own datadir holds no custody bundle. It is deliberately
// verbose and copy-pasteable: the failure it replaces is a node that starts,
// builds a different block 0, and is then rejected by every peer at key
// exchange with no hint as to why.
func devnetLateJoinerMissingBundleError(opts DevnetCustodyOptions) error {
	cfgDir := filepath.Dir(opts.EscrowPolicyPath)
	if cfgDir == "" || cfgDir == "." {
		cfgDir = filepath.Dir(opts.VaultPolicyPath)
	}
	return fmt.Errorf(`devnet late joiner has no custody bundle in its own datadir: neither %s nor %s exists.

A node started with --seeds cannot mint custody material — it must REPLAY the
bootstrap node's block 0. Without the bundle it would build a different genesis
(legacy vault, unsigned, no witnesses), and every peer would reject it at key
exchange because the genesis hashes differ. Refusing to start instead.

Fix, in order:
  1. Start the FIRST validator (no --seeds) alone and let it finish signing.
     Wait for: "persisted N genesis witnesses to .../devnet_genesis_witnesses.json"
  2. Copy ONLY the public bundle from that node's datadir into this one:
       mkdir -p %s
       cp <bootstrap-datadir>/config/genesis_multisig.json \
          <bootstrap-datadir>/config/escrow_multisig.json \
          <bootstrap-datadir>/config/devnet_genesis_witnesses.json %s/
  3. Start this node again.

Never copy the custody/ directory: a replaying node needs no custodian keys.`,
		opts.VaultPolicyPath, opts.EscrowPolicyPath, cfgDir, cfgDir)
}

// AutoProvisionDevnetCustody provisions (or loads) devnet custody and, when
// this node is the producer, registers the block-0 authorizer and the witness
// sink with core. It returns a non-nil error only for failures a devnet
// operator must fix — never for the "not devnet" / "test binary" no-op paths.
func AutoProvisionDevnetCustody(opts DevnetCustodyOptions) (*DevnetCustodyResult, error) {
	opts = opts.withDefaults()
	res := &DevnetCustodyResult{WitnessPath: opts.WitnessPath}

	if !DevnetAutoCustodyRequested(opts.NetworkType) {
		return res, nil // not devnet: today's behaviour is untouched
	}
	if devnetAutoCustodySkipped() {
		return res, nil // `go test` binary: never touch the repo's config/data
	}
	res.Enabled = true

	// ★ FAIL CLOSED ON AN UNREPRODUCIBLE BLOCK 0.
	//
	// A node started with --seeds is a late joiner: it cannot mint custody
	// material (that would be a competing genesis), so its ONLY way to agree
	// with the network is to replay the bootstrap node's block 0. With the
	// per-node layout there is no shared root to fall back to, so "no bundle in
	// my own datadir" does not mean "fall back to legacy" — it means this node
	// would build a DIFFERENT genesis (legacy vault, unsigned, no witnesses)
	// and then be rejected by every peer at key exchange.
	//
	// That is the worst possible shape of failure: it presents as "nodes cannot
	// connect to each other", arbitrarily far from the actual cause. The guard
	// in createGenesisBlock cannot catch it either, because each node's genesis
	// is internally self-consistent — only the HASHES disagree.
	//
	// So refuse here, with the copy command, rather than let the node start.
	if !opts.BootstrapNode && !devnetCustodyBundlePresent(opts) {
		return res, devnetLateJoinerMissingBundleError(opts)
	}

	// Idempotent within a process. The CLI provisions before deriving VDF
	// parameters from the genesis hash, and bind.StartNode provisions again as a
	// safety net for hosts that call it directly — the second call must NOT
	// re-arm block 0 (which could swap a signing authorizer for a replay one, or
	// regenerate material mid-build).
	devnetCustodyMu.Lock()
	if cached := devnetCustodyApplied; cached != nil {
		clone := *cached
		devnetCustodyMu.Unlock()
		return &clone, nil
	}
	devnetCustodyMu.Unlock()

	if err := ensureDevnetEscrowPolicy(opts, res); err != nil {
		return res, err
	}
	if err := ensureDevnetVaultPolicy(opts, res); err != nil {
		return res, err
	}
	devnetCustodyMu.Lock()
	devnetCustodyApplied = res
	devnetCustodyMu.Unlock()
	return res, nil
}

// ensureDevnetEscrowPolicy generates the escrow policy on the producer node if
// none exists, then loads it. No signing is involved: the escrow policy only
// decides WHERE block 0 sends the locked remainder, and every node that loads
// the same public policy derives the same address.
func ensureDevnetEscrowPolicy(opts DevnetCustodyOptions, res *DevnetCustodyResult) error {
	if !fileExists(opts.EscrowPolicyPath) {
		if !opts.BootstrapNode {
			logger.Error("DEVNET AUTO-CUSTODY: %s is absent and this node is a late joiner (--seeds set) — refusing to generate a competing escrow policy. Start the first validator (no --seeds) once so it writes the shared policy, then restart this node.", opts.EscrowPolicyPath)
			return nil
		}
		if err := generateDevnetCustodySet(opts.EscrowKeysDir, opts.EscrowPolicyPath, "sphinx-escrow-v1", opts); err != nil {
			return err
		}
		res.GeneratedKeys = true
		logger.Error("DEVNET AUTO-CUSTODY: CGE escrow policy + all %d custodian keys generated by this process (%s, policy %s). This is devnet convenience, NOT real M-of-N security. Never use auto-provisioned keys for testnet or mainnet.", opts.Custodians, opts.EscrowKeysDir, opts.EscrowPolicyPath)
		logger.Error("DEVNET AUTO-CUSTODY: distribute the PUBLIC bundle to every peer datadir before they start (cp %s %s <peer-datadir>/config/) — never the keys.", opts.EscrowPolicyPath, filepath.Base(opts.EscrowPolicyPath))
	}

	addr, err := LoadEscrowPolicy(opts.EscrowPolicyPath)
	if err != nil {
		return fmt.Errorf("devnet auto-custody: load escrow policy %s: %w", opts.EscrowPolicyPath, err)
	}
	res.EscrowAddress = addr
	logger.Info("DEVNET AUTO-CUSTODY: escrow address %s (block 0 funds it; CGE releases stay UNGATED until enforcement is enabled)", addr)
	return nil
}

// ensureDevnetVaultPolicy makes the genesis vault a custody address and wires
// the authorizer that lets block 0 satisfy guardGenesisAuthorization.
func ensureDevnetVaultPolicy(opts DevnetCustodyOptions, res *DevnetCustodyResult) error {
	autoKeysPresent := dirHasEntries(opts.VaultKeysDir)

	if !fileExists(opts.VaultPolicyPath) {
		if !opts.BootstrapNode {
			logger.Error("DEVNET AUTO-CUSTODY: %s is absent and this node is a late joiner (--seeds set) — refusing to generate a competing genesis vault policy. Start the first validator (no --seeds) once so it writes the shared policy plus the pre-signed genesis witnesses, then restart this node.", opts.VaultPolicyPath)
			return nil
		}
		if err := generateDevnetCustodySet(opts.VaultKeysDir, opts.VaultPolicyPath, "sphinx-vault-v1", opts); err != nil {
			return err
		}
		autoKeysPresent = true
		res.GeneratedKeys = true
		logger.Error("DEVNET AUTO-CUSTODY: genesis vault policy + all %d custodian keys generated by this process (%s, policy %s). This is devnet convenience, NOT real M-of-N security. Never use auto-provisioned keys for testnet or mainnet.", opts.Custodians, opts.VaultKeysDir, opts.VaultPolicyPath)
		logger.Error("DEVNET AUTO-CUSTODY: distribute the PUBLIC bundle (genesis_multisig.json, escrow_multisig.json, devnet_genesis_witnesses.json) from %s to every peer <datadir>/config/ before they start — never the keys.", filepath.Dir(opts.VaultPolicyPath))
		logger.Error("DEVNET AUTO-CUSTODY: this node signs block 0's distribution slices (%d-of-%d each) — expect minutes of STHINCS signing before genesis exists. The resulting witnesses are persisted to %s so other devnet nodes need no custodian keys.", opts.Threshold, opts.Custodians, opts.WitnessPath)
	}

	addr, err := LoadGenesisVaultPolicy(opts.VaultPolicyPath)
	if err != nil {
		return fmt.Errorf("devnet auto-custody: load genesis vault policy %s: %w", opts.VaultPolicyPath, err)
	}
	res.VaultAddress = addr

	if !autoKeysPresent && !fileExists(opts.WitnessPath) {
		// A policy with no devnet-auto keys is a REAL ceremony policy. Block 0
		// then has to come from the ceremony's own build tooling; leave the
		// authorizer unset so global.go keeps logging its unsigned-genesis
		// ERROR rather than silently signing with keys we do not have.
		logger.Warn("DEVNET AUTO-CUSTODY: vault policy %s is not auto-provisioned (no keys at %s) — leaving block-0 authorization to the ceremony. Block 0 will be built UNSIGNED unless a witness set is supplied.", opts.VaultPolicyPath, opts.VaultKeysDir)
		if !opts.BootstrapNode {
			// The common real cause: a HALF-DONE copy. The policies were
			// copied but %s was not — usually because the bootstrap node had
			// not finished signing when the copy ran. Without the witnesses
			// this node builds an unsigned block 0 from a policy-owned vault,
			// which the genesis guard then refuses with a much more cryptic
			// message ("failed transaction authorization"). Name it here.
			logger.Error("DEVNET AUTO-CUSTODY: this node is a late joiner and %s is missing — that is almost always a half-done copy. Wait for the first validator to log \"persisted N genesis witnesses\", then re-copy it (see the missing-bundle instructions in %s).", opts.WitnessPath, "core/devnet.go")
		}
		return nil
	}

	if fileExists(opts.WitnessPath) {
		book, err := loadDevnetWitnessBook(opts.WitnessPath)
		if err != nil {
			return err
		}
		if err := book.validateAgainst(opts, addr); err != nil {
			return err
		}
		policy, err := multisig.LoadPolicy(opts.VaultPolicyPath)
		if err != nil {
			return fmt.Errorf("devnet auto-custody: load vault policy for witness replay: %w", err)
		}
		SetGenesisDistributionAuthorizer(book.authorizer(policy, opts.GenesisTimestamp), book.ChainID)
		res.ReplayNode = true
		logger.Warn("DEVNET AUTO-CUSTODY: loaded the pre-signed genesis witness set from %s (chain %d, vault %s) — this node rebuilds block 0 identically WITHOUT holding any custodian key.", opts.WitnessPath, book.ChainID, book.VaultAddress)
		return nil
	}

	keys, err := loadDevnetCustodianKeys(opts.VaultKeysDir)
	if err != nil {
		return err
	}
	policy, err := multisig.LoadPolicy(opts.VaultPolicyPath)
	if err != nil {
		return fmt.Errorf("devnet auto-custody: load vault policy for signing: %w", err)
	}
	if len(keys) < int(policy.Threshold) {
		return fmt.Errorf("devnet auto-custody: %d custodian key(s) at %s but threshold is %d — cannot sign block 0", len(keys), opts.VaultKeysDir, policy.Threshold)
	}
	signer := &devnetCustodySigner{
		policy:  policy,
		address: addr,
		chainID: opts.ChainID,
		expiry:  uint64(opts.GenesisTimestamp) + uint64(devnetWitnessValidity/time.Second),
		keys:    keys,
	}
	SetGenesisDistributionAuthorizer(signer.authorizer(), opts.ChainID)
	SetGenesisWitnessSink(witnessSink(opts, addr))
	res.SigningNode = true
	logger.Error("DEVNET AUTO-CUSTODY: this node signs block 0 with the generated custodian keys kept at %s and persists the witness set to %s. These keys are devnet throwaways — never reuse them for testnet or mainnet.", opts.VaultKeysDir, opts.WitnessPath)
	return nil
}

// devnetCustodySigner produces threshold witnesses over the canonical spend
// message for a genesis distribution slice.
type devnetCustodySigner struct {
	policy  *multisig.MultiPartyPolicy
	address string
	chainID uint64
	expiry  uint64
	keys    []devnetCustodianKey
}

// authorizer is the GenesisDistributionAuthorizer installed for block 0. It
// signs with the first Threshold custodians, using multisig.SpendMessage — the
// same encoder multisig.CheckSpendWitness uses on the validating side — so
// signer and verifier cannot drift.
func (s *devnetCustodySigner) authorizer() GenesisDistributionAuthorizer {
	return func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
		sigs := make(map[int][]byte, s.policy.Threshold)
		for i := 0; i < int(s.policy.Threshold) && i < len(s.keys); i++ {
			msg := multisig.SpendMessage(s.policy, s.chainID, s.address, receiver, amount, nonce, s.expiry)
			sig, err := multisig.SignCustodyMessage(msg, s.keys[i].sk, s.keys[i].pk)
			if err != nil {
				logger.Error("DEVNET AUTO-CUSTODY: custodian %d failed to sign genesis slice %d (%s): %v", i, nonce, receiver, err)
				return nil
			}
			sigs[i] = sig
		}
		if len(sigs) < int(s.policy.Threshold) {
			return nil
		}
		return &multisig.MultiSigWitness{Policy: *s.policy, Sigs: sigs, Expiry: s.expiry}
	}
}

// witnessSink persists the witnesses block 0 was actually built with. They are
// the same bytes that ride in the block, so publishing them leaks nothing —
// and it is what lets a peer node reproduce the identical hash without keys.
func witnessSink(opts DevnetCustodyOptions, vaultAddr string) func(*types.Block) error {
	return func(block *types.Block) error {
		if block == nil || block.Header == nil {
			return fmt.Errorf("nil genesis block")
		}
		book := devnetGenesisWitnessBook{
			Version:       1,
			ChainID:       opts.ChainID,
			VaultAddress:  vaultAddr,
			EscrowAddress: GetCGEEscrowAddress(),
			Expiry:        uint64(opts.GenesisTimestamp) + uint64(devnetWitnessValidity/time.Second),
			Witnesses:     map[string]multisig.MultiSigWitness{},
		}
		for _, tx := range block.Body.TxsList {
			if tx == nil || tx.MultiSigWitness == nil {
				continue
			}
			book.Witnesses[strconv.FormatUint(tx.Nonce, 10)] = *tx.MultiSigWitness
		}
		if len(book.Witnesses) == 0 {
			return fmt.Errorf("built genesis block carries no custody witnesses")
		}
		if dir := filepath.Dir(opts.WitnessPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create witness dir: %w", err)
			}
		}
		data, err := json.MarshalIndent(book, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal witness book: %w", err)
		}
		if err := os.WriteFile(opts.WitnessPath, append(data, '\n'), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", opts.WitnessPath, err)
		}
		logger.Info("DEVNET AUTO-CUSTODY: persisted %d genesis witnesses to %s (hash %s)", len(book.Witnesses), opts.WitnessPath, block.GetHash())
		return nil
	}
}

func loadDevnetWitnessBook(path string) (*devnetGenesisWitnessBook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("devnet auto-custody: read witness set %s: %w", path, err)
	}
	var book devnetGenesisWitnessBook
	if err := json.Unmarshal(data, &book); err != nil {
		return nil, fmt.Errorf("devnet auto-custody: parse witness set %s: %w", path, err)
	}
	return &book, nil
}

// validateAgainst refuses a witness set that describes a different chain,
// vault or escrow than this node resolved. Replaying a book bound to other
// addresses would build a block 0 whose witnesses cannot authorize it.
func (b *devnetGenesisWitnessBook) validateAgainst(opts DevnetCustodyOptions, vaultAddr string) error {
	if b.ChainID != opts.ChainID {
		return fmt.Errorf("devnet auto-custody: witness set %s is for chain %d but this node is chain %d — delete it and let the first validator regenerate, or fix --network", opts.WitnessPath, b.ChainID, opts.ChainID)
	}
	if b.VaultAddress != vaultAddr {
		return fmt.Errorf("devnet auto-custody: witness set %s authorizes vault %s but the loaded policy resolves to %s", opts.WitnessPath, b.VaultAddress, vaultAddr)
	}
	if escrow := GetCGEEscrowAddress(); b.EscrowAddress != "" && b.EscrowAddress != escrow {
		return fmt.Errorf("devnet auto-custody: witness set %s was built for escrow %s but this node funds %s", opts.WitnessPath, b.EscrowAddress, escrow)
	}
	if len(b.Witnesses) == 0 {
		return fmt.Errorf("devnet auto-custody: witness set %s is empty", opts.WitnessPath)
	}
	return nil
}

// authorizer serves the persisted witness for a slice AFTER re-checking it
// against the canonical message for that slice. Verification is cheap (no
// signing), and it is what makes a stale or corrupted witness set fail closed
// here instead of producing a block that cannot pass the genesis guard.
func (b *devnetGenesisWitnessBook) authorizer(policy *multisig.MultiPartyPolicy, genesisTimestamp int64) GenesisDistributionAuthorizer {
	refTime := uint64(genesisTimestamp)
	return func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
		w, ok := b.Witnesses[strconv.FormatUint(nonce, 10)]
		if !ok {
			logger.Error("devnet auto-custody: witness set has no entry for genesis slice %d (%s)", nonce, receiver)
			return nil
		}
		msg := multisig.SpendMessage(policy, b.ChainID, b.VaultAddress, receiver, amount, nonce, w.Expiry)
		if !multisig.VerifyThreshold(msg, w, refTime) {
			logger.Error("devnet auto-custody: persisted witness for genesis slice %d (%s) does not authorize this release — refusing to reuse it", nonce, receiver)
			return nil
		}
		cp := w
		return &cp
	}
}

// generateDevnetCustodySet writes N custodian key files plus the policy JSON in
// the exact on-disk shape `multisig devnet` produces, so the rest of the node
// (and the CLI) treats auto-provisioned custody like any other policy.
func generateDevnetCustodySet(keysDir, policyPath, domain string, opts DevnetCustodyOptions) error {
	if fileExists(policyPath) || dirHasEntries(keysDir) {
		// Never overwrite a real or previously generated custody set: the keys
		// are the only thing that can authorize the existing chain's block 0.
		return fmt.Errorf("devnet auto-custody: refusing to overwrite existing custody material at %s / %s", keysDir, policyPath)
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return fmt.Errorf("create devnet custody keys dir: %w", err)
	}
	km, err := key.NewKeyManager()
	if err != nil {
		return fmt.Errorf("devnet custody key manager: %w", err)
	}
	policy := &multisig.MultiPartyPolicy{Threshold: uint8(opts.Threshold), Domain: domain}
	for i := 0; i < opts.Custodians; i++ {
		sk, pk, err := km.GenerateKey()
		if err != nil {
			return fmt.Errorf("devnet custody keygen %d: %w", i, err)
		}
		skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
		if err != nil {
			return fmt.Errorf("devnet custody serialize %d: %w", i, err)
		}
		policy.PubKeys = append(policy.PubKeys, pkBytes)
		record, err := json.MarshalIndent(map[string]string{
			"private_key": hex.EncodeToString(skBytes),
			"public_key":  hex.EncodeToString(pkBytes),
		}, "", "  ")
		if err != nil {
			return err
		}
		keyPath := filepath.Join(keysDir, fmt.Sprintf("custodian-%d.json", i))
		if err := os.WriteFile(keyPath, append(record, '\n'), devnetKeyFileMode); err != nil {
			return fmt.Errorf("write %s: %w", keyPath, err)
		}
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("devnet custody policy invalid: %w", err)
	}
	if dir := filepath.Dir(policyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create policy dir: %w", err)
		}
	}
	if err := policy.Save(policyPath); err != nil {
		return fmt.Errorf("write devnet custody policy %s: %w", policyPath, err)
	}
	return nil
}

// loadDevnetCustodianKeys reads every custodian key file the generated set
// holds. The returned slice is index-aligned with the policy's public keys:
// custodian-<i>.json must carry PubKeys[i], or the witnesses it produces would
// not count toward the threshold, so a mismatch is an error rather than a skip.
func loadDevnetCustodianKeys(keysDir string) ([]devnetCustodianKey, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("devnet auto-custody: read keys dir %s: %w", keysDir, err)
	}
	keys := make([]devnetCustodianKey, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(keysDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("devnet auto-custody: read %s: %w", e.Name(), err)
		}
		var rec struct {
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
		}
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("devnet auto-custody: parse %s: %w", e.Name(), err)
		}
		sk, err := hex.DecodeString(rec.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("devnet auto-custody: %s private_key: %w", e.Name(), err)
		}
		pk, err := hex.DecodeString(rec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("devnet auto-custody: %s public_key: %w", e.Name(), err)
		}
		if len(sk) == 0 || len(pk) == 0 {
			return nil, fmt.Errorf("devnet auto-custody: %s is missing key material", e.Name())
		}
		keys = append(keys, devnetCustodianKey{sk: sk, pk: pk})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("devnet auto-custody: no custodian keys in %s", keysDir)
	}
	return keys, nil
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirHasEntries(dir string) bool {
	if dir == "" {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			return true
		}
	}
	return false
}
