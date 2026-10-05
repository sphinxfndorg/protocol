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
// ★ WHAT "AUTO" COSTS. Every witness is a real STHINCS signature (~7-8s on this
// parameter set) and block 0 needs a threshold set for each distribution slice:
// 13 slices × 2-of-3 = 26 signatures. Those signatures are independent, so they
// are signed concurrently by a BOUNDED pool (devnetCustodyWorkers: default
// runtime.NumCPU() capped at devnetCustodyWorkerCap) and collected BY INDEX.
// Measured on a 4-core/8-thread machine: 3m17s serial (workers=1) vs 1m03s with
// 8 workers (~3.1x), producing byte-identical witnesses either way — signing is
// deterministic (production parameters set RANDOMIZE=false) and results are
// placed by (slice, custodian) index, never by completion order. Reserved heap
// grows with the pool (~12 MB serial → ~25 MB at 8 workers).
//
// That one-time cost is paid only by the producer: it persists the witness set
// to config/: witnesses are public data (they ride in block 0 anyway), so peer
// nodes rebuild a byte-identical block 0 from them instantly, verify-only, and
// never need a custodian key. Secret keys stay under data/custody/devnet-auto/
// and are never distributed.
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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"

	"github.com/sphinxfndorg/protocol/src/common"
)

// DevnetChainID is the chain ID every devnet parameter set resolves to
// (SphinxChainParameters.IsDevnet). The auto-custody gate is expressed against
// this, not against a display name, so it cannot be fooled by a renamed chain.
const DevnetChainID uint64 = 73310

const (
	// Per-node relative paths used when DataDir is set. Custody private keys
	// live under <datadir>/custody/devnet-auto (NOT data/custody — that prefix
	// is the ceremony/manual `multisig devnet` namespace, and reusing it would
	// let an operator mistake auto-generated throwaways for ceremony keys).
	//
	// ★ There is no per-node path for the genesis vault policy or the block-0
	// witness book: both live as SECTIONS of the single genesis document,
	// <datadir>/config/genesis_state.json (GenesisStateFileSubdir). That is the
	// consolidation — one file, one loader, one writer, no fallback.
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
	// TRACKED-BY: https://github.com/sphinxfndorg/protocol/issues?q=is%3Aissue+ceremony-loader
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

// DevnetBundleFile describes one allowlisted PUBLIC devnet bundle file served
// over the network to late joiners. Name is the allowlist key used on the
// wire; Subdir is the per-node relative path under the node's own datadir
// (see perNodePath / GenesisStateFileSubdir). Only
// allowlisted files are ever served or fetched — custody/ private keys are never
// in this list, never served, and never fetched.
type DevnetBundleFile struct {
	Name   string
	Subdir string
}

// DevnetPublicBundleFiles is the single public genesis document a late joiner
// needs. It contains chain parameters, validators, funded accounts, both
// custody policies and the pre-signed block-0 witness book.
var DevnetPublicBundleFiles = []DevnetBundleFile{
	{Name: GenesisStateFileName, Subdir: GenesisStateFileSubdir},
}

// devnetBundleByName resolves a wire name to its bundle entry. Unknown names
// are rejected so a peer can never coax this node into serving an arbitrary
// file (in particular nothing under custody/).
func devnetBundleByName(name string) (DevnetBundleFile, bool) {
	for _, f := range DevnetPublicBundleFiles {
		if f.Name == name {
			return f, true
		}
	}
	return DevnetBundleFile{}, false
}

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

	// DataDir scopes the genesis document and private custody keys to one node.
	// The public genesis bundle is one file; secret keys remain in the existing
	// per-node custody directories.
	// Empty means the legacy shared-root layout (used by tests and the
	// same-process harness).
	DataDir string

	ChainID          uint64
	GenesisTimestamp int64

	// GenesisStatePath is the single genesis document this node reads and writes.
	// It carries the chain parameters, the initial validator set, funded
	// accounts, both custody policies and the pre-signed block-0 witness set.
	GenesisStatePath string
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
	if o.GenesisStatePath == "" {
		o.GenesisStatePath = scope(GenesisStateFileSubdir)
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

// GenesisStatePathForDataDir returns the one genesis document path for a node.
func GenesisStatePathForDataDir(datadir string) string {
	return perNodePath(datadir, GenesisStateFileSubdir)
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
	// GenesisStatePath is the single genesis document the policy and witness
	// book were merged into.
	GenesisStatePath string
}

// DevnetAutoCustodyRequested reports whether networkType selects the devnet
// phase. Deliberately strict: anything that is not exactly "devnet" (including
// empty/unknown values) fails closed to "no".
func DevnetAutoCustodyRequested(networkType string) bool {
	return strings.EqualFold(strings.TrimSpace(networkType), string(PhaseDevnet))
}

// GenesisWitnessBook is the persisted block-0 authorization set: one witness per
// distribution slice, keyed by the slice's nonce (the running transaction index
// allocationsToTxList assigns), plus the binding facts a replaying node must agree
// on before it can rebuild the same block.
//
// It is a SECTION of the single genesis document, not a file of its own.
type GenesisWitnessBook struct {
	Version       int                                 `json:"version"`
	ChainID       uint64                              `json:"chain_id"`
	VaultAddress  string                              `json:"vault_address"`
	EscrowAddress string                              `json:"escrow_address"`
	Expiry        uint64                              `json:"expiry"`
	Witnesses     map[string]multisig.MultiSigWitness `json:"witnesses"`
}

// validateSelf is the section-local sanity check; the chain/vault/escrow binding
// is checked separately by validateAgainst, which needs the resolved addresses.
// A present-but-empty book would let a peer rebuild a block 0 it cannot
// authorize, so it is refused when the document is parsed.
func (b *GenesisWitnessBook) validateSelf() error {
	if b == nil {
		return nil
	}
	if len(b.Witnesses) == 0 {
		return fmt.Errorf("witness book holds no witnesses")
	}
	return nil
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

// devnetCustodyBundlePresent reports whether this node's datadir has the single
// public genesis document needed to replay block 0.
func devnetCustodyBundlePresent(opts DevnetCustodyOptions) bool {
	return fileExists(opts.GenesisStatePath)
}

// devnetLateJoinerMissingBundleError is the refusal for a devnet node started
// with --seeds whose own datadir holds no custody bundle. It is deliberately
// verbose and copy-pasteable: the failure it replaces is a node that starts,
// builds a different block 0, and is then rejected by every peer at key
// exchange with no hint as to why.
func devnetLateJoinerMissingBundleError(opts DevnetCustodyOptions) error {
	return fmt.Errorf(`devnet late joiner has no genesis document in its own datadir: %s does not exist.

A node started with --seeds cannot mint custody material — it must REPLAY the
bootstrap node's block 0. Without the document it would build a different genesis
(legacy vault, unsigned, no witnesses), and every peer would reject it at key
exchange because the genesis hashes differ. Refusing to start instead.

Fix: wait for the bootstrap node to finish signing — a joiner now fetches
the PUBLIC bundle over the network automatically (see bind's
ensureDevnetBundleFromSeeds) and retries while the bootstrap is still
signing. If this error still fires, the network fetch itself failed
(seeds unreachable or bootstrap not yet listening); check --seeds.

Never fetch or copy the custody/ directory: a replaying node needs no keys.`,
		opts.GenesisStatePath)
}

// AutoProvisionDevnetCustody provisions (or loads) devnet custody and, when
// this node is the producer, registers the block-0 authorizer and the witness
// sink with core. It returns a non-nil error only for failures a devnet
// operator must fix — never for the "not devnet" / "test binary" no-op paths.
func AutoProvisionDevnetCustody(opts DevnetCustodyOptions) (*DevnetCustodyResult, error) {
	opts = opts.withDefaults()
	res := &DevnetCustodyResult{GenesisStatePath: opts.GenesisStatePath}

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
	gf, err := LoadGenesisFile(datadirOf(opts.GenesisStatePath))
	if err != nil {
		return fmt.Errorf("devnet auto-custody: read %s: %w", opts.GenesisStatePath, err)
	}
	if gf == nil || gf.EscrowMultisig == nil {
		if !opts.BootstrapNode {
			return fmt.Errorf("devnet auto-custody: %s has no escrow_multisig section; refusing to generate a competing escrow policy on a joiner", opts.GenesisStatePath)
		}
		if err := generateDevnetCustodySet(opts.EscrowKeysDir, "sphinx-escrow-v1", opts, saveEscrowPolicy(opts)); err != nil {
			return err
		}
		res.GeneratedKeys = true
		logger.Error("DEVNET AUTO-CUSTODY: CGE escrow policy + all %d custodian keys generated by this process (%s, policy in %s). This is devnet convenience, NOT real M-of-N security. Never use auto-provisioned keys for testnet or mainnet.", opts.Custodians, opts.EscrowKeysDir, opts.GenesisStatePath)
	}

	addr, err := LoadEscrowPolicy(datadirOf(opts.GenesisStatePath))
	if err != nil {
		return fmt.Errorf("devnet auto-custody: load escrow policy from %s: %w", opts.GenesisStatePath, err)
	}
	res.EscrowAddress = addr
	logger.Info("DEVNET AUTO-CUSTODY: escrow address %s (block 0 funds it; CGE releases stay UNGATED until enforcement is enabled)", addr)
	return nil
}

// ensureDevnetVaultPolicy makes the genesis vault a custody address and wires
// the authorizer that lets block 0 satisfy guardGenesisAuthorization.
//
// The M-of-N policy lives in the `multisig` section of the single genesis
// document and the pre-signed witnesses in its `witnesses` section, so every
// read and write here goes through LoadGenesisFile / MutateGenesisFile. There is
// no separate policy file and no separate witness book any more.
func ensureDevnetVaultPolicy(opts DevnetCustodyOptions, res *DevnetCustodyResult) error {
	autoKeysPresent := dirHasEntries(opts.VaultKeysDir)

	gf, err := LoadGenesisFile(datadirOf(opts.GenesisStatePath))
	if err != nil {
		return fmt.Errorf("devnet auto-custody: read %s: %w", opts.GenesisStatePath, err)
	}
	hasPolicy := gf != nil && gf.Multisig != nil
	hasWitnesses := gf != nil && gf.Witnesses != nil

	if !hasPolicy {
		if !opts.BootstrapNode {
			logger.Error("DEVNET AUTO-CUSTODY: %s carries no multisig section and this node is a late joiner (--seeds set) — refusing to generate a competing genesis vault policy. Start the first validator (no --seeds) once so it writes the policy plus the pre-signed genesis witnesses, then restart this node.", opts.GenesisStatePath)
			return nil
		}
		if err := generateDevnetCustodySet(opts.VaultKeysDir, "sphinx-vault-v1", opts, saveVaultPolicy(opts)); err != nil {
			return err
		}
		autoKeysPresent = true
		res.GeneratedKeys = true
		logger.Error("DEVNET AUTO-CUSTODY: genesis vault policy + all %d custodian keys generated by this process (%s, policy in %s). This is devnet convenience, NOT real M-of-N security. Never use auto-provisioned keys for testnet or mainnet.", opts.Custodians, opts.VaultKeysDir, opts.GenesisStatePath)
		logger.Error("DEVNET AUTO-CUSTODY: distribute the single PUBLIC genesis document (%s) from %s to every peer <datadir>/config/ before they start — never the keys.", GenesisStateFileName, filepath.Dir(opts.GenesisStatePath))
		logger.Error("DEVNET AUTO-CUSTODY: this node signs block 0's distribution slices (%d-of-%d each, %d slices) with a bounded worker pool — expect on the order of a minute of STHINCS signing before genesis exists (more on a single core; the completed run logs the exact wall time). The resulting witnesses are merged into %s so other devnet nodes need no custodian keys.", opts.Threshold, opts.Custodians, len(devnetCustodySlicesForGenesis(opts.GenesisTimestamp)), opts.GenesisStatePath)
	}

	// Re-read the document: generateDevnetCustodySet may have just merged a
	// freshly generated policy into it, and the witnesses/policy used below must
	// be the ones actually on disk, not the pre-generation snapshot.
	gf, err = LoadGenesisFile(datadirOf(opts.GenesisStatePath))
	if err != nil {
		return fmt.Errorf("devnet auto-custody: re-read %s: %w", opts.GenesisStatePath, err)
	}
	if gf == nil || gf.Multisig == nil {
		return fmt.Errorf("devnet auto-custody: %s has no multisig section after provisioning", opts.GenesisStatePath)
	}
	hasWitnesses = gf.Witnesses != nil

	addr, err := LoadGenesisVaultPolicy(opts.GenesisStatePath)
	if err != nil {
		return fmt.Errorf("devnet auto-custody: load genesis vault policy from %s: %w", opts.GenesisStatePath, err)
	}
	res.VaultAddress = addr

	if !autoKeysPresent && !hasWitnesses {
		// A policy with no devnet-auto keys is a REAL ceremony policy. Block 0
		// then has to come from the ceremony's own build tooling; leave the
		// authorizer unset so global.go keeps logging its unsigned-genesis
		// ERROR rather than silently signing with keys we do not have.
		logger.Warn("DEVNET AUTO-CUSTODY: vault policy in %s is not auto-provisioned (no keys at %s) — leaving block-0 authorization to the ceremony. Block 0 will be built UNSIGNED unless a witness set is supplied.", opts.GenesisStatePath, opts.VaultKeysDir)
		if !opts.BootstrapNode {
			// The common real cause: a HALF-DONE copy. The document was
			// copied before the bootstrap node finished signing. Without the
			// witnesses this node builds an unsigned block 0 from a
			// policy-owned vault, which the genesis guard then refuses with a
			// much more cryptic message ("failed transaction authorization").
			logger.Error("DEVNET AUTO-CUSTODY: this node is a late joiner and %s carries no witnesses section — that is almost always a half-done copy. Wait for the first validator to log \"persisted N genesis witnesses\", then re-copy it (see the missing-bundle instructions in %s).", opts.GenesisStatePath, "core/devnet.go")
		}
		return nil
	}

	if hasWitnesses {
		book := gf.Witnesses
		if err := book.validateAgainst(opts, addr); err != nil {
			return err
		}
		policy := gf.Multisig
		SetGenesisDistributionAuthorizer(book.authorizer(policy, opts.GenesisTimestamp), book.ChainID)
		res.ReplayNode = true
		logger.Warn("DEVNET AUTO-CUSTODY: loaded the pre-signed genesis witness set from %s (chain %d, vault %s) — this node rebuilds block 0 identically WITHOUT holding any custodian key.", opts.GenesisStatePath, book.ChainID, book.VaultAddress)
		return nil
	}

	keys, err := loadDevnetCustodianKeys(opts.VaultKeysDir)
	if err != nil {
		return err
	}
	policy := gf.Multisig
	if len(keys) < int(policy.Threshold) {
		return fmt.Errorf("devnet auto-custody: %d custodian key(s) at %s but threshold is %d — cannot sign block 0", len(keys), opts.VaultKeysDir, policy.Threshold)
	}
	signer := &devnetCustodySigner{
		policy:  policy,
		address: addr,
		chainID: opts.ChainID,
		expiry:  uint64(opts.GenesisTimestamp) + uint64(devnetWitnessValidity/time.Second),
		refTime: uint64(opts.GenesisTimestamp),
		keys:    keys,
	}

	// Sign EVERY slice up front, with a bounded worker pool, BEFORE arming the
	// authorizer or the witness sink. A failure here returns an error and leaves
	// the process with nothing armed, no sink and no witnesses section — the node
	// refuses to start instead of building a block 0 it cannot authorize.
	slices := devnetCustodySlicesForGenesis(opts.GenesisTimestamp)
	signStart := time.Now()
	if err := signer.signAll(context.Background(), slices); err != nil {
		return fmt.Errorf("devnet auto-custody: signing block 0 distributions failed: %w", err)
	}
	logger.Info("DEVNET AUTO-CUSTODY: signed %d block-0 slice(s) × %d-of-%d custodians in %s using %d worker(s)",
		len(slices), policy.Threshold, len(keys), time.Since(signStart).Round(time.Millisecond), devnetCustodyWorkerCount())

	SetGenesisDistributionAuthorizer(signer.authorizer(), opts.ChainID)
	SetGenesisWitnessSink(witnessSink(opts, addr))
	res.SigningNode = true
	logger.Error("DEVNET AUTO-CUSTODY: this node signs block 0 with the generated custodian keys kept at %s and merges the witness set into %s. These keys are devnet throwaways — never reuse them for testnet or mainnet.", opts.VaultKeysDir, opts.GenesisStatePath)
	return nil
}

// ----------------------------------------------------------------------------
// Block-0 signing pool
//
// Block 0 needs one threshold witness per distribution slice: 13 slices x
// 2-of-3 = 26 real STHINCS signatures. They are INDEPENDENT — the signature
// for (slice i, custodian j) shares no input with any other pair — so they are
// signed concurrently by a BOUNDED pool and collected BY INDEX.
//
// Determinism: the production parameter set sets RANDOMIZE=false
// (core/sthincs/config.NewSTHINCSParameters -> MakeSthincsPlusSPHINXHASH128s
// Robust(false)), and Spx_sign consumes randomness ONLY for its `opt`
// randomizer when RANDOMIZE is set. With RANDOMIZE=false signing is therefore
// a pure function of (params, key, message): the same slice signed by the same
// custodian yields the same bytes regardless of goroutine or ordering. Results
// are stored per (slice, custodian) index — never in completion order — so the
// assembled witnesses and the persisted witness book are byte-identical to the
// serial implementation for the same inputs.
// ----------------------------------------------------------------------------

// devnetCustodyWorkerCap bounds the pool. Signing is CPU- and memory-heavy
// (each Spx_sign builds a full FORS/hypertree working set), so the pool is
// capped instead of scaling with the signature count.
const devnetCustodyWorkerCap = 8

// devnetCustodyWorkers selects the pool size: 0 means runtime.NumCPU() capped
// at devnetCustodyWorkerCap; 1 is the SERIAL reference path (used by tests to
// produce the reference output). It is a variable so tests can sweep counts.
var devnetCustodyWorkers = 0

// devnetCustodyWorkerCount resolves the effective pool size (always >= 1).
func devnetCustodyWorkerCount() int {
	n := devnetCustodyWorkers
	if n <= 0 {
		n = runtime.NumCPU()
	}
	if n > devnetCustodyWorkerCap {
		n = devnetCustodyWorkerCap
	}
	if n < 1 {
		n = 1
	}
	return n
}

// devnetCustodySlice is one block-0 distribution slice, identified by the nonce
// allocationsToTxListAuthorized assigns it.
type devnetCustodySlice struct {
	receiver string
	amount   *big.Int
	nonce    uint64
}

// devnetCustodySignJob is one (slice, custodian) signature task.
type devnetCustodySignJob struct {
	sliceIdx  int
	custodian int
	slice     devnetCustodySlice
}

// devnetCustodySlicesForGenesis returns the canonical (receiver, amount, nonce)
// set block 0 will distribute. It CALLS the canonical slice builder
// (allocationsToTxList) instead of re-deriving the rule, so the signer and the
// block builder can never drift: if the slice rule changes, the signed set
// changes with it.
func devnetCustodySlicesForGenesis(genesisTimestamp int64) []devnetCustodySlice {
	gs := &GenesisState{
		Allocations: DefaultGenesisAllocations(),
		Timestamp:   genesisTimestamp,
	}
	txs := gs.allocationsToTxList()
	slices := make([]devnetCustodySlice, 0, len(txs))
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		slices = append(slices, devnetCustodySlice{receiver: tx.Receiver, amount: tx.Amount, nonce: tx.Nonce})
	}
	return slices
}

// signAll produces the threshold witness for every slice, signing with the
// first Threshold custodians exactly like the original serial implementation,
// but concurrently across a bounded worker pool.
//
// Fail closed: on the first signature error the remaining work is cancelled, no
// witnesses are published (s.witnesses stays nil), and the error is returned so
// the caller aborts startup — no witness book and no armed authorizer can
// result from a partial run. The pool is bounded, jobs are closed, and the
// WaitGroup is awaited, so no goroutine outlives the call.
//
// Serial path: devnetCustodyWorkers == 1 runs the same code with one worker,
// producing the byte-identical reference output used by tests.
func (s *devnetCustodySigner) signAll(ctx context.Context, slices []devnetCustodySlice) error {
	threshold := int(s.policy.Threshold)
	if len(slices) == 0 {
		return fmt.Errorf("no distribution slices to sign")
	}
	if len(s.keys) < threshold {
		return fmt.Errorf("%d custodian key(s) but threshold is %d — cannot sign block 0", len(s.keys), threshold)
	}

	// Per-slice signature slots: results are indexed by (slice, custodian), so
	// completion order can never influence the output bytes.
	sigBuf := make([]map[int][]byte, len(slices))
	for i := range sigBuf {
		sigBuf[i] = make(map[int][]byte, threshold)
	}

	workers := devnetCustodyWorkerCount()
	if totalJobs := threshold * len(slices); workers > totalJobs {
		workers = totalJobs
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan devnetCustodySignJob)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	recordErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel() // stop feeding; in-flight jobs unwind at the next job boundary
		}
		mu.Unlock()
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				msg := multisig.SpendMessage(s.policy, s.chainID, s.address, job.slice.receiver, job.slice.amount, job.slice.nonce, s.expiry)
				sig, err := multisig.SignCustodyMessage(msg, s.keys[job.custodian].sk, s.keys[job.custodian].pk)
				if err != nil {
					recordErr(fmt.Errorf("custodian %d failed to sign genesis slice %d (%s): %w",
						job.custodian, job.slice.nonce, job.slice.receiver, err))
					return
				}
				mu.Lock()
				sigBuf[job.sliceIdx][job.custodian] = sig
				mu.Unlock()
			}
		}()
	}

feed:
	for si, sl := range slices {
		for ci := 0; ci < threshold; ci++ {
			select {
			case <-ctx.Done():
				break feed
			case jobs <- devnetCustodySignJob{sliceIdx: si, custodian: ci, slice: sl}:
			}
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}

	// Assemble only after EVERY signature succeeded.
	witnesses := make(map[uint64]*multisig.MultiSigWitness, len(slices))
	for si, sl := range slices {
		sigs := sigBuf[si]
		if len(sigs) < threshold {
			return fmt.Errorf("genesis slice %d (%s) has %d signature(s), threshold is %d", sl.nonce, sl.receiver, len(sigs), threshold)
		}
		witnesses[sl.nonce] = &multisig.MultiSigWitness{Policy: *s.policy, Sigs: sigs, Expiry: s.expiry}
	}
	s.witnesses = witnesses
	return nil
}

// devnetCustodySigner produces threshold witnesses over the canonical spend
// message for a genesis distribution slice.
//
// Signing runs ONCE, up front, over every slice with a bounded worker pool
// (see signAll); the authorizer below is then a pure, fail-closed lookup of
// those pre-computed witnesses. That ordering is what makes a mid-run failure
// impossible to half-publish: signing either completes for every slice or the
// node aborts startup with nothing armed and no witness book written.
type devnetCustodySigner struct {
	policy  *multisig.MultiPartyPolicy
	address string
	chainID uint64
	expiry  uint64
	// refTime is the witness-expiry reference — the genesis timestamp, exactly
	// what the replay path uses (devnetGenesisWitnessBook.authorizer).
	refTime uint64
	keys    []devnetCustodianKey

	// witnesses holds the fully assembled, threshold-satisfying witness for
	// each distribution slice, keyed by the slice's nonce. It is set only by a
	// successful signAll and is never partially populated.
	witnesses map[uint64]*multisig.MultiSigWitness
}

// authorizer is the GenesisDistributionAuthorizer installed for block 0. It
// serves the pre-computed witness for a slice AFTER re-checking it against the
// canonical message for that slice, using multisig.SpendMessage — the same
// encoder multisig.CheckSpendWitness uses on the validating side — so signer
// and verifier cannot drift, and a missing or stale witness fails closed.
func (s *devnetCustodySigner) authorizer() GenesisDistributionAuthorizer {
	return func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness {
		w, ok := s.witnesses[nonce]
		if !ok || w == nil {
			logger.Error("DEVNET AUTO-CUSTODY: no pre-computed witness for genesis slice %d (%s) — refusing to authorize", nonce, receiver)
			return nil
		}
		msg := multisig.SpendMessage(s.policy, s.chainID, s.address, receiver, amount, nonce, w.Expiry)
		if !multisig.VerifyThreshold(msg, *w, s.refTime) {
			logger.Error("DEVNET AUTO-CUSTODY: pre-computed witness for genesis slice %d (%s) does not authorize this release — refusing to reuse it", nonce, receiver)
			return nil
		}
		cp := *w
		return &cp
	}
}

// witnessSink merges the witnesses block 0 was actually built with into the
// `witnesses` section of the ONE genesis document. They are the same bytes that
// ride in the block, so publishing them leaks nothing — and it is what lets a
// peer node reproduce the identical hash without keys.
//
// Fail closed on completeness: every distribution transaction must carry a
// witness. A partial set is an error and NOTHING is written — a book missing a
// slice would let a peer rebuild a block 0 it cannot authorize.
//
// The write goes through MutateGenesisFile, so it is atomic (temp file in the
// destination directory, then rename) AND leaves the chain / validators /
// funded_accounts / multisig sections of the same document untouched: a reader
// never observes a truncated witness book, a crash cannot leave a half-written
// one behind, and the bundle is still one file.
func witnessSink(opts DevnetCustodyOptions, vaultAddr string) func(*types.Block) error {
	return func(block *types.Block) error {
		if block == nil || block.Header == nil {
			return fmt.Errorf("nil genesis block")
		}
		book := GenesisWitnessBook{
			Version:       1,
			ChainID:       opts.ChainID,
			VaultAddress:  vaultAddr,
			EscrowAddress: GetCGEEscrowAddress(),
			Expiry:        uint64(opts.GenesisTimestamp) + uint64(devnetWitnessValidity/time.Second),
			Witnesses:     map[string]multisig.MultiSigWitness{},
		}
		missing := 0
		for _, tx := range block.Body.TxsList {
			if tx == nil {
				missing++
				continue
			}
			if tx.MultiSigWitness == nil {
				missing++
				continue
			}
			book.Witnesses[strconv.FormatUint(tx.Nonce, 10)] = *tx.MultiSigWitness
		}
		if len(book.Witnesses) == 0 {
			return fmt.Errorf("built genesis block carries no custody witnesses")
		}
		if missing > 0 {
			return fmt.Errorf("refusing to persist a partial witness set: %d distribution slice(s) carry no witness", missing)
		}
		if err := MutateGenesisFile(datadirOf(opts.GenesisStatePath), func(gf *GenesisStateFile) {
			gf.Witnesses = &book
		}); err != nil {
			return fmt.Errorf("merge witness book into %s: %w", opts.GenesisStatePath, err)
		}
		logger.Info("DEVNET AUTO-CUSTODY: persisted %d genesis witnesses to %s (hash %s)", len(book.Witnesses), opts.GenesisStatePath, block.GetHash())
		return nil
	}
}

// validateAgainst refuses a witness set that describes a different chain,
// vault or escrow than this node resolved. Replaying a book bound to other
// addresses would build a block 0 whose witnesses cannot authorize it.
func (b *GenesisWitnessBook) validateAgainst(opts DevnetCustodyOptions, vaultAddr string) error {
	if b.ChainID != opts.ChainID {
		return fmt.Errorf("devnet auto-custody: witness set in %s is for chain %d but this node is chain %d — delete it and let the first validator regenerate, or fix --network", opts.GenesisStatePath, b.ChainID, opts.ChainID)
	}
	if b.VaultAddress != vaultAddr {
		return fmt.Errorf("devnet auto-custody: witness set in %s authorizes vault %s but the loaded policy resolves to %s", opts.GenesisStatePath, b.VaultAddress, vaultAddr)
	}
	if escrow := GetCGEEscrowAddress(); b.EscrowAddress != "" && b.EscrowAddress != escrow {
		return fmt.Errorf("devnet auto-custody: witness set in %s was built for escrow %s but this node funds %s", opts.GenesisStatePath, b.EscrowAddress, escrow)
	}
	if err := b.validateSelf(); err != nil {
		return fmt.Errorf("devnet auto-custody: witness set in %s is invalid: %w", opts.GenesisStatePath, err)
	}
	return nil
}

// authorizer serves the persisted witness for a slice AFTER re-checking it
// against the canonical message for that slice. Verification is cheap (no
// signing), and it is what makes a stale or corrupted witness set fail closed
// here instead of producing a block that cannot pass the genesis guard.
func (b *GenesisWitnessBook) authorizer(policy *multisig.MultiPartyPolicy, genesisTimestamp int64) GenesisDistributionAuthorizer {
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

// generateDevnetCustodySet writes N custodian key files, then hands the resulting
// policy to save, which decides WHERE it lands:
//
//   - the genesis vault policy is merged into the `multisig` SECTION of the one
//     genesis document (MutateGenesisFile), so the vault authorization travels
//     with the validator set and the witness book;
//   - the CGE escrow policy is merged into the `escrow_multisig` section of the
//     same genesis document.
//
// The key files are the same in both cases, in the exact on-disk shape
// `multisig devnet` produces, so the rest of the node (and the CLI) treats
// auto-provisioned custody like any other policy.
func generateDevnetCustodySet(keysDir, domain string, opts DevnetCustodyOptions, save func(*multisig.MultiPartyPolicy) error) error {
	if save == nil {
		return fmt.Errorf("devnet auto-custody: no policy sink for %s", domain)
	}
	if dirHasEntries(keysDir) {
		// Never overwrite a real or previously generated custody set: the keys
		// are the only thing that can authorize the existing chain's block 0.
		return fmt.Errorf("devnet auto-custody: refusing to overwrite existing custody keys at %s", keysDir)
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
	return save(policy)
}

// saveVaultPolicy merges the freshly generated genesis vault policy into the
// `multisig` section of the one genesis document.
func saveVaultPolicy(opts DevnetCustodyOptions) func(*multisig.MultiPartyPolicy) error {
	return func(p *multisig.MultiPartyPolicy) error {
		return MutateGenesisFile(datadirOf(opts.GenesisStatePath), func(gf *GenesisStateFile) {
			gf.Multisig = p
		})
	}
}

// saveEscrowPolicy merges the CGE escrow policy into the single genesis document.
func saveEscrowPolicy(opts DevnetCustodyOptions) func(*multisig.MultiPartyPolicy) error {
	return func(p *multisig.MultiPartyPolicy) error {
		return MutateGenesisFile(datadirOf(opts.GenesisStatePath), func(gf *GenesisStateFile) {
			gf.EscrowMultisig = p
		})
	}
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

// devnetBundleDataDirRegistry maps a process-local serving address
// ("host:port" as the TCP listener bound it) to the datadir whose PUBLIC
// bundle should be served. Only the node's own datadir is ever registered.
var devnetBundleDataDirRegistry = struct {
	sync.RWMutex
	byAddr map[string]string
}{byAddr: map[string]string{}}

// RegisterDevnetBundleDataDir publishes datadir as the bundle source for the
// listener bound at serveAddr. Only the node's own datadir is registered.
func RegisterDevnetBundleDataDir(serveAddr, datadir string) {
	if serveAddr == "" || datadir == "" {
		return
	}
	devnetBundleDataDirRegistry.Lock()
	defer devnetBundleDataDirRegistry.Unlock()
	devnetBundleDataDirRegistry.byAddr[serveAddr] = datadir
}

func devnetBundleDataDirFor(serveAddr string) (string, bool) {
	devnetBundleDataDirRegistry.RLock()
	defer devnetBundleDataDirRegistry.RUnlock()
	d, ok := devnetBundleDataDirRegistry.byAddr[serveAddr]
	return d, ok
}

// DevnetBundleRequest is the wire request for one bundle file.
type DevnetBundleRequest struct {
	File string `json:"file"`
}

// DevnetBundleResponse carries one bundle file's bytes. Ready=false means the
// bootstrap has not produced the file yet (still signing): retryable.
type DevnetBundleResponse struct {
	File    string `json:"file"`
	Ready   bool   `json:"ready"`
	Missing bool   `json:"missing,omitempty"`
	Data    []byte `json:"data,omitempty"`
}

// bundleCompleteForDataDir reports whether datadir holds the required public
// genesis document. A restarted node with the document skips network fetch and
// never overwrites its bundle.
func bundleCompleteForDataDir(datadir string) bool {
	if datadir == "" {
		return false
	}
	for _, f := range DevnetPublicBundleFiles {
		data, err := os.ReadFile(perNodePath(datadir, f.Subdir))
		if err != nil || len(data) == 0 {
			return false
		}
	}
	return true
}

// validateBundleBytes fail-closes on fetched bytes before they touch disk.
func validateBundleBytes(name string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("bundle file %s is empty", name)
	}
	switch name {
	case GenesisStateFileName:
		var gf GenesisStateFile
		if err := ValidateGenesisFileBytes(data, &gf); err != nil {
			return fmt.Errorf("bundle %s failed validation: %w", name, err)
		}
		return nil
	default:
		return fmt.Errorf("unknown bundle file %s", name)
	}
}

// writeBundleFile persists one verified bundle file atomically (temp+rename,
// mode 0644 — public data) inside the node's OWN datadir.
func writeBundleFile(datadir, subdir string, data []byte) error {
	path := perNodePath(datadir, subdir)
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".devnet_bundle-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Chmod(0o644)
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// DevnetBundleComplete reports whether datadir already holds the full PUBLIC
// bundle. Exported for bind: a restarted node with an existing datadir skips
// the network fetch entirely and never overwrites its bundle.
func DevnetBundleComplete(datadir string) bool {
	return bundleCompleteForDataDir(datadir)
}

// ValidateDevnetBundleBytes fail-closes on fetched bytes before they touch
// disk. Exported for bind's network fetch path.
func ValidateDevnetBundleBytes(name string, data []byte) error {
	return validateBundleBytes(name, data)
}

// WriteDevnetBundleFile persists one verified bundle file atomically inside
// the node's OWN datadir. Exported for bind's network fetch path.
func WriteDevnetBundleFile(datadir, subdir string, data []byte) error {
	return writeBundleFile(datadir, subdir, data)
}

// BundleSubdirFor returns the per-node relative path for an allowlisted
// bundle file name. Unknown names are refused.
func BundleSubdirFor(name string) (string, bool) {
	entry, ok := devnetBundleByName(name)
	if !ok {
		return "", false
	}
	return entry.Subdir, true
}

// ServeDevnetBundle answers one bundle request from this node's OWN datadir.
// Only allowlisted PUBLIC files that already exist are served; custody/ keys
// are unreachable by construction (no allowlist entry, no lookup).
func ServeDevnetBundle(serveAddr string, req DevnetBundleRequest) (DevnetBundleResponse, error) {
	entry, ok := devnetBundleByName(req.File)
	if !ok || req.File == "" {
		return DevnetBundleResponse{}, fmt.Errorf("unknown bundle file %q", req.File)
	}
	datadir, ok := devnetBundleDataDirFor(serveAddr)
	if !ok || datadir == "" {
		return DevnetBundleResponse{}, fmt.Errorf("no bundle source for %s", serveAddr)
	}
	data, err := os.ReadFile(perNodePath(datadir, entry.Subdir))
	if err != nil || len(data) == 0 {
		return DevnetBundleResponse{File: entry.Name, Ready: false}, nil
	}
	return DevnetBundleResponse{File: entry.Name, Ready: true, Data: data}, nil
}

// ============================================================================
// DEVNET-ONLY: the bootstrap faucet ledger.
//
// ★ WHAT THIS BUYS. The main flow is three `node` commands and nothing else:
//
//	./sphinx node --role=validator --tcp-addr=127.0.0.1:30303 --datadir=data/node0 --pbft
//	./sphinx node --role=validator --port-offset=1 --seeds=127.0.0.1:30303 --pbft
//	./sphinx node --role=validator --port-offset=2 --seeds=127.0.0.1:30303 --pbft
//
// so nobody may be asked to paste an address or supply a key. Each node
// auto-generates ONE reward keypair in its own datadir on first start, the
// bootstrap node's genesis document carries a faucet allocation (see
// CreateGenesisForSelf), and the bootstrap pays each joiner's reward address
// min-stake ON DEMAND — see bind.runDevnetFaucet.
//
// ★ NO NODE COUNT ANYWHERE. The faucet pays whoever asks; it holds a bounded
// pool, not a list. A fixed list of pre-funded joiner addresses would be a
// hidden node count — the exact knowledge this flow deletes — so it is never
// used. Any number of joiners work, including none.
//
// ★ DEVNET ONLY, FAIL-CLOSED. Every entry point is reached only behind
// DevnetAutoCustodyRequested(networkType), so none of this can arm on a chain
// that carries value.
// ============================================================================

// devnetFaucetKeysSubdir holds the bootstrap node's faucet key + ledger. The
// key is a PRIVATE key, so — unlike the public bundle — it is never served,
// never fetched, and never appears in a genesis document.
const devnetFaucetKeysSubdir = "custody/devnet-auto/faucet"

// devnetRewardKeysSubdir holds a node's own auto-generated reward key. Also
// private, also per-node, also never served.
const devnetRewardKeysSubdir = "custody/devnet-auto/reward"

// DevnetFaucetKeyDir is the bootstrap node's faucet key directory, for the
// host (src/bind) that actually generates the key.
//
// ★ WHY GENERATION LIVES IN src/bind AND NOT HERE. Deriving a SPHINCS public
// key's SPIF address needs usi/core/key, and that package imports core — so a
// core→usi/core/key edge would be an import cycle. The host already imports
// both, so it does the generate-or-load and hands us only the resulting
// address. core keeps the ledger (pure state, no key material).
func DevnetFaucetKeyDir(datadir string) string {
	return perNodePath(datadir, devnetFaucetKeysSubdir)
}

// DevnetRewardKeyDir is a node's own reward key directory. See
// DevnetFaucetKeyDir for why generation is the host's job.
func DevnetRewardKeyDir(datadir string) string {
	return perNodePath(datadir, devnetRewardKeysSubdir)
}

// DevnetFaucetState is the bootstrap node's running faucet ledger, persisted so
// a restart never re-pays an address it already paid (which would silently
// drain the pool) and never loses track of how much is left.
type DevnetFaucetState struct {
	// Address is the faucet's own reward address (its source of funds).
	Address string `json:"address"`
	// Paid maps an already-funded joiner address to true. It is the
	// idempotence set: one address is funded at most once, ever.
	Paid map[string]bool `json:"paid"`
	// Nonce is the faucet's next transaction nonce. Transactions are
	// nonce-checked, so this must advance exactly once per payout.
	Nonce uint64 `json:"nonce"`
}

// devnetFaucetMu serialises read-modify-write cycles on the faucet ledger so
// two concurrent funding requests cannot both read the same nonce.
var devnetFaucetMu sync.Mutex

// DevnetFaucetStatePath is the bootstrap node's faucet ledger path.
func DevnetFaucetStatePath(datadir string) string {
	return perNodePath(datadir, devnetFaucetKeysSubdir+"/faucet_state.json")
}

// LoadDevnetFaucetState reads the persisted faucet ledger, returning an empty
// one when none exists yet (a faucet that has not paid anyone).
func LoadDevnetFaucetState(datadir string) (*DevnetFaucetState, error) {
	var st DevnetFaucetState
	data, err := os.ReadFile(DevnetFaucetStatePath(datadir))
	if err != nil {
		if os.IsNotExist(err) {
			return &DevnetFaucetState{Paid: map[string]bool{}}, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("devnet faucet state is unreadable: %w", err)
	}
	if st.Paid == nil {
		st.Paid = map[string]bool{}
	}
	return &st, nil
}

// SaveDevnetFaucetState persists the faucet ledger atomically (temp+rename).
func SaveDevnetFaucetState(datadir string, st *DevnetFaucetState) error {
	path := DevnetFaucetStatePath(datadir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReserveDevnetFaucetPayout atomically claims the next faucet nonce for addr.
//
// It is the single choke point that makes "pay whoever asks" safe to run
// concurrently: it refuses an address the faucet has already paid, and it hands
// out each nonce exactly once, so two joiners can never emit a same-nonce pair
// that the state transition would reject. The caller MUST release the
// reservation if it fails to broadcast the payment.
//
// Returns (nonce, ok). ok=false means "already funded" or "no ledger yet" —
// neither is an error, because both are ordinary outcomes.
func ReserveDevnetFaucetPayout(datadir, addr string) (uint64, bool, error) {
	devnetFaucetMu.Lock()
	defer devnetFaucetMu.Unlock()

	st, err := LoadDevnetFaucetState(datadir)
	if err != nil {
		return 0, false, err
	}
	canonical := common.CanonicalSPIFAddress(addr)
	if st.Paid[canonical] {
		return 0, false, nil // already funded — never pay the same address twice
	}
	nonce := st.Nonce
	st.Nonce = nonce + 1
	// Mark as paid BEFORE the broadcast commits. If the broadcast then fails,
	// ReleaseDevnetFaucetPayout rolls this back, so a transient failure does
	// not burn the joiner's one payout; a crash in between loses one payout,
	// which is the safe direction to fail.
	st.Paid[canonical] = true
	if err := SaveDevnetFaucetState(datadir, st); err != nil {
		return 0, false, err
	}
	return nonce, true, nil
}

// ReleaseDevnetFaucetPayout undoes a reservation whose payment never reached
// the mempool, so the address can still be funded on a later attempt.
func ReleaseDevnetFaucetPayout(datadir, addr string, nonce uint64) error {
	devnetFaucetMu.Lock()
	defer devnetFaucetMu.Unlock()

	st, err := LoadDevnetFaucetState(datadir)
	if err != nil {
		return err
	}
	canonical := common.CanonicalSPIFAddress(addr)
	// Only roll back OUR reservation: a later payout may already have claimed
	// this nonce, in which case the ledger is ahead and must not be rewound.
	if st.Paid[canonical] && st.Nonce == nonce+1 {
		delete(st.Paid, canonical)
		st.Nonce = nonce
		return SaveDevnetFaucetState(datadir, st)
	}
	return nil
}
