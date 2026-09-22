/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * API service layer for the Sphinx Ledger Explorer.
 * Connects the React frontend to the Go backend HTTP API.
 * All addresses from the backend (raw hex) are formatted into SPIF display format.
 */

import { Block, Transaction, Validator, Wallet, NetworkStats, HolderGrowthPoint, Attestation } from '../types';
import { formatSPIFAddress, normalizeSPIFAddress } from '../utils/formatters';
import * as mock from '../mock/blockchainData';

// Base URL for API requests. In development, Vite proxies /api to the Go backend.
// In production, the Go server serves both the static files and the API.
const API_BASE = '/api/v1/explorer';

// Data provenance. The explorer falls back to a simulated chain so the UI stays
// inspectable with no node running, but an explorer silently rendering invented
// blocks is a real hazard: an operator would believe the node is healthy. Every
// fallback flips this to 'mock' so App can render a visible warning banner.
export type DataSource = 'live' | 'mock';
let dataSource: DataSource = 'live';

/** True when the most recent API call had to fall back to simulated data. */
export function getDataSource(): DataSource {
  return dataSource;
}

// Generic fetch wrapper with graceful fallback to simulated mock data
// if the local Go backend is not yet started.
async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/json' },
      ...options,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => 'unknown error');
      throw new Error(`API ${res.status} ${res.statusText}: ${text}`);
    }

    const body = await res.json();
    dataSource = 'live';
    return body;
  } catch (err) {
    // If backend is unreachable, gracefully fall back to mock data — flagged
    // via getDataSource() so the UI never presents it as real chain state.
    return handleMockFallback<T>(endpoint);
  }
}

function handleMockFallback<T>(endpoint: string): T {
  dataSource = 'mock';
  const state = mock.getBlockchainState();
  if (endpoint.startsWith('/stats')) {
    return {
      block_count: state.stats.tipHeight,
      tps: {
        current_tps: state.stats.currentTps,
        average_tps: state.stats.averageTps,
        peak_tps: state.stats.peakTps,
      },
      mempool: {
        size: state.stats.mempoolSize,
        bytes: state.stats.mempoolBytes,
      },
      validators: {
        active_validators: state.stats.activeValidators,
        total_validators: state.stats.totalValidators,
        total_stake_spx: state.stats.totalStakeSpx,
        min_stake_spx: state.stats.minStakeSpx,
      },
      chain: {
        chain_id: state.stats.chainId,
        symbol: state.stats.symbol,
        genesis_hash: state.stats.genesisHash,
        sync_mode: state.stats.syncMode,
      },
      burn: {
        address: state.stats.burnAddress,
        burned_spx: state.stats.burnedSpx,
        burned_nspx: state.stats.burnedNspx,
        circulating_spx: state.stats.circulatingSpx,
        circulating_nspx: state.stats.circulatingNspx,
        total_supply_spx: state.stats.totalSupplySpx,
        total_supply_nspx: state.stats.totalSupplyNspx,
        max_supply_spx: state.stats.maxSupplySpx,
        burn_percent: state.stats.burnPercent,
      },
      wallets: {
        total_accounts: state.stats.totalAccounts,
        active_wallets: state.stats.activeWallets,
        spif_addresses: state.stats.sphincsAddresses,
      },
    } as unknown as T;
  }

  if (endpoint.startsWith('/blocks')) {
    return {
      blocks: state.blocks,
      total: state.blocks.length,
    } as unknown as T;
  }

  if (endpoint.startsWith('/block/')) {
    const heightOrHash = endpoint.replace('/block/', '');
    const height = parseInt(heightOrHash);
    const blk = !isNaN(height)
      ? state.blocks.find(b => b.height === height)
      : state.blocks.find(b => b.hash === heightOrHash);
    if (blk) {
      const txs = state.transactions.filter(t => t.blockHeight === blk.height);
      return {
        block_height: blk.height,
        block_hash: blk.hash,
        header: blk,
        transactions: txs,
        attestations: [],
      } as unknown as T;
    }
  }

  if (endpoint.startsWith('/mempool')) {
    // Simulated mempool: only the pending set exists, and the breakdown says
    // so explicitly rather than reporting zeros a reader might take for a real
    // node's empty pool.
    return {
      pending_txs: state.mempool,
      pool: {
        broadcast: 0,
        validating: 0,
        pending: state.mempool.length,
        invalid: 0,
        total: state.mempool.length,
      },
      in_flight_txs: [],
      rejected_txs: [],
    } as unknown as T;
  }

  if (endpoint.startsWith('/validators')) {
    return {
      validators: state.validators,
    } as unknown as T;
  }

  if (endpoint.startsWith('/wallets')) {
    return {
      rich_list: state.wallets,
    } as unknown as T;
  }

  if (endpoint.startsWith('/holders/growth')) {
    const today = new Date();
    const points = Array.from({ length: 30 }).map((_, i) => {
      const d = new Date(today);
      d.setDate(d.getDate() - (29 - i));
      return {
        date: d.toISOString().split('T')[0],
        holders: 120 + Math.floor(i * 4.2),
        new_holders: Math.floor(Math.random() * 8) + 1,
      };
    });
    return { points } as unknown as T;
  }

  if (endpoint.startsWith('/search')) {
    const urlParams = new URLSearchParams(endpoint.split('?')[1] || '');
    const q = urlParams.get('q') || '';
    return mock.searchBlockchain(q) as unknown as T;
  }

  return {} as unknown as T;
}

// ============================================================================
// Stats
// ============================================================================

export async function fetchStats(): Promise<NetworkStats> {
  const raw: any = await fetchApi('/stats');

  const burn = raw.burn || {};
  const wallets = raw.wallets || {};

  return {
    tipHeight: raw.block_count || 0,
    currentTps: raw.tps?.current_tps || 0,
    averageTps: raw.tps?.average_tps || 0,
    peakTps: raw.tps?.peak_tps || 0,
    mempoolSize: raw.mempool?.size || 0,
    mempoolBytes: raw.mempool?.bytes || 0,
    totalAccounts: wallets.total_accounts || 0,
    activeWallets: wallets.active_wallets || 0,
    sphincsAddresses: wallets.spif_addresses || 0,
    activeValidators: raw.validators?.active_validators || 0,
    totalValidators: raw.validators?.total_validators || 0,
    slashedValidators: 0,
    totalStakeSpx: raw.validators?.total_stake_spx || '0',
    minStakeSpx: raw.validators?.min_stake_spx || 0,
    chainId: raw.chain?.chain_id?.toString() || 'sphinx-post-quantum-1',
    symbol: raw.chain?.symbol || 'SPX',
    genesisHash: raw.chain?.genesis_hash || '',
    syncMode: raw.chain?.sync_mode || 'Fully Audited (SPHINCS+ Hash Signature Verified)',
    blockTimeSeconds: Number(raw.chain?.block_time_seconds) || 12,
    burnAddress: burn.address || wallets.burn_address || '',
    burnedSpx: burn.burned_spx || wallets.burned_spx || '0',
    burnedNspx: burn.burned_nspx || wallets.burned_nspx || '0',
    circulatingSpx: burn.circulating_spx || wallets.circulating_spx || '0',
    circulatingNspx: burn.circulating_nspx || wallets.circulating_nspx || '0',
    totalSupplySpx: burn.total_supply_spx || wallets.total_supply_spx || '0',
    totalSupplyNspx: burn.total_supply_nspx || wallets.total_supply_nspx || '0',
    maxSupplySpx: burn.max_supply_spx || '0',
    burnPercent: Number(burn.burn_percent) || 0,
  };
}

export async function fetchHolderGrowth(days: number = 30): Promise<HolderGrowthPoint[]> {
  try {
    const raw: any = await fetchApi(`/holders/growth?days=${days}`);
    if (!Array.isArray(raw.points)) return [];
    return raw.points.map((point: any) => ({
      date: typeof point.date === 'string' ? point.date : '',
      holders: Number(point.holders) || 0,
      newHolders: Number(point.new_holders) || 0,
    }));
  } catch {
    return [];
  }
}

// ============================================================================
// Blocks
// ============================================================================

export async function fetchBlocks(page: number = 1, limit: number = 25): Promise<Block[]> {
  const raw: any = await fetchApi(`/blocks?page=${page}&limit=${limit}`);

  if (!raw.blocks || !Array.isArray(raw.blocks)) {
    return [];
  }

  return raw.blocks.map((b: any) => mapBlock(b));
}

// Hard ceiling on pagination rounds so a malformed/circular response can never
// spin this loop: 200 pages × 100 rows = 20,000 blocks.
const MAX_BLOCK_PAGES = 200;
// The backend's max page size — anything above 100 is silently rejected and
// reset to 25 by handleExplorerBlocks, so never request more than this.
const BLOCK_PAGE_LIMIT = 100;

// fetchAllBlocks walks EVERY page of /blocks so "All Mined Block States"
// renders the entire chain instead of just the newest page. The handler
// returns blocks newest-first along with `total`; we keep requesting pages
// until every reported block has been seen.
//
// Rows are keyed by height because a block mined between page fetches shifts
// every subsequent page's window — without dedupe that shift would duplicate
// heights across the page boundary. The final sort restores strict
// newest-first order regardless of the order pages arrived in.
export async function fetchAllBlocks(): Promise<Block[]> {
  const byHeight = new Map<number, Block>();
  let total = Number.POSITIVE_INFINITY;

  for (let page = 1; page <= MAX_BLOCK_PAGES; page++) {
    const raw: any = await fetchApi(`/blocks?page=${page}&limit=${BLOCK_PAGE_LIMIT}`);
    const rows: any[] = Array.isArray(raw?.blocks) ? raw.blocks : [];
    if (rows.length === 0) {
      break;
    }

    for (const row of rows) {
      const block = mapBlock(row);
      byHeight.set(block.height, block);
    }

    const reportedTotal = Number(raw?.total);
    if (Number.isFinite(reportedTotal) && reportedTotal > 0) {
      total = reportedTotal;
    }
    if (byHeight.size >= total) {
      break;
    }
    // A short page is the last one; stop rather than asking a clamped
    // backend (it re-serves the final page for any out-of-range request).
    if (rows.length < BLOCK_PAGE_LIMIT) {
      break;
    }
  }

  return Array.from(byHeight.values()).sort((a, b) => b.height - a.height);
}

export interface BlockDetailPayload {
  block: Block;
  transactions: Transaction[];
  attestations: Attestation[];
}

export async function fetchBlockDetail(height: number): Promise<BlockDetailPayload | null> {
  try {
    const raw: any = await fetchApi(`/block/${height}`);
    if (!raw || raw.error) return null;
    return {
      block: mapBlockDetail(raw),
      transactions: (raw.transactions || []).map((tx: any) => mapBlockTransaction(tx, raw)),
      attestations: (raw.attestations || []).map(mapAttestation),
    };
  } catch {
    return null;
  }
}

export async function fetchBlockByHeight(height: number): Promise<Block | null> {
  const detail = await fetchBlockDetail(height);
  return detail ? detail.block : null;
}

export async function fetchBlockByHash(hash: string): Promise<Block | null> {
  try {
    const raw: any = await fetchApi(`/block/hash/${hash}`);
    return mapBlockDetail(raw);
  } catch {
    return null;
  }
}

function mapCommitStatus(status: unknown): Block['commitStatus'] {
  switch (String(status || '').toLowerCase()) {
    case 'proposed':
    case 'prepared':
    case 'pending':
      return 'pending';
    case 'finalized':
      return 'finalized';
    default:
      return 'committed';
  }
}

function mapBlock(b: any): Block {
  return {
    height: Number(b.height) || 0,
    hash: b.hash || '',
    parentHash: b.prev_hash || b.parent_hash || '',
    timestamp: Number(b.timestamp) || 0,
    timestampIso: b.timestamp_iso,
    difficulty: b.difficulty || '1',
    nonce: Number(b.nonce) || 0,
    gasLimit: toNumber(b.gas_limit),
    gasUsed: toNumber(b.gas_used),
    proposer: formatSPIFAddress(b.proposer || ''),
    txsRoot: b.txs_root || '',
    stateRoot: b.state_root || '',
    chainWeight: b.chain_weight || '0',
    commitStatus: mapCommitStatus(b.commit_status),
    txCount: Number(b.tx_count),
    signatureScheme: 'SPHINCS+-128s' as const,
    version: Number(b.version) || 0,
    unclesHash: b.uncles_hash || '',
    sigValid: Boolean(b.sig_valid),
    attestationCount: Number(b.attestation_count) || 0,
    confirmations: Number(b.confirmations) || 0,
    age: b.age || '',
    ageSec: Number(b.age_sec),
    burnedThisBlockSpx: b.burned_this_block_spx,
    burnedThisBlockNspx: b.burned_this_block_nspx,
    burnedBeforeNspx: b.burned_before_nspx,
    blockRewardSpx: b.block_reward_spx,
    blockRewardNspx: b.block_reward_nspx,
    blockRewardMinerNspx: b.block_reward_miner_nspx,
    blockRewardBurnedNspx: b.block_reward_burned_nspx,
    extraData: b.extra_data,
    miner: b.miner,
    logsBloom: b.logs_bloom,
    gasPrice: b.gas_price,
    proposerId: b.proposer_id || b.proposer || '',
    proposerSignature: b.proposer_signature || '',
    sigDataHash: b.sig_data_hash || '',
  };
}

function mapBlockDetail(raw: any): Block {
  const header = raw.header || raw;
  return {
    height: Number(raw.block_height ?? header.height) || 0,
    hash: raw.block_hash || header.hash || '',
    parentHash: header.parent_hash || '',
    timestamp: Number(header.timestamp) || 0,
    timestampIso: header.timestamp_iso,
    difficulty: header.difficulty || '1',
    nonce: Number(header.nonce) || 0,
    gasLimit: toNumber(header.gas_limit),
    gasUsed: toNumber(header.gas_used),
    proposer: formatSPIFAddress(header.proposer || ''),
    txsRoot: header.txs_root || '',
    stateRoot: header.state_root || '',
    chainWeight: header.chain_weight || '0',
    commitStatus: mapCommitStatus(header.commit_status),
    txCount: "tx_count" in raw ? Number(raw.tx_count) : (raw.transactions?.length ?? 0),
    signatureScheme: 'SPHINCS+-128s' as const,
    version: Number(header.version) || 0,
    unclesHash: header.uncles_hash || '',
    sigValid: Boolean(header.sig_valid),
    attestationCount: Number(raw.att_count) || 0,
    confirmations: Number(raw.confirmations) || 0,
    age: header.age || '',
    ageSec: Number(header.age_sec),
    burnedThisBlockSpx: raw.burned_this_block_spx,
    burnedThisBlockNspx: raw.burned_this_block_nspx,
    burnedBeforeNspx: raw.burned_before_nspx,
    blockRewardSpx: raw.block_reward_spx,
    blockRewardNspx: raw.block_reward_nspx,
    blockRewardMinerNspx: raw.block_reward_miner_nspx,
    blockRewardBurnedNspx: raw.block_reward_burned_nspx,
    extraData: header.extra_data,
    miner: header.miner,
    logsBloom: header.logs_bloom,
    gasPrice: header.gas_price,
    proposerId: header.proposer_id || header.proposer || '',
    proposerSignature: header.proposer_signature || '',
    sigDataHash: header.sig_data_hash || '',
  };
}

function mapAttestation(att: any): Attestation {
  return {
    validatorId: att.validator_id || '',
    blockHash: att.block_hash || '',
    view: Number(att.view) || 0,
    stakeSpx: att.stake_spx || '0',
  };
}

function mapBlockTransaction(tx: any, blockPayload: any): Transaction {
  const header = blockPayload?.header || {};
  return {
    txid: tx.txid || '',
    status: 'success' as const,
    sender: formatSPIFAddress(tx.sender || ''),
    receiver: formatSPIFAddress(tx.receiver || ''),
    amountSpx: tx.amount_spx || '0',
    amountNspx: tx.amount_nspx || '0',
    nonce: Number(tx.nonce) || 0,
    timestamp: Number(tx.timestamp) || Number(header.timestamp) || 0,
    timestampIso: tx.timestamp_iso,
    blockHeight: Number(header.height ?? blockPayload?.block_height) || 0,
    gasLimit: toNumber(tx.gas_limit),
    gasPrice: toNumber(tx.gas_price),
    gasFeeSpx: tx.fee_spx || '0',
    chainId: String(blockPayload?.chain_id ?? 'sphinx-post-quantum-1'),
    isSystemTx: Boolean(tx.is_system_tx),
    signature: tx.signature || '',
    publicKey: tx.public_key || '',
    merkleRoot: tx.merkle_root || '',
    hasFullAuth: Boolean(tx.has_full_auth),
    returnData: tx.return_data || undefined,
    returnDataText: tx.return_data_text || undefined,
    returnDataKind: tx.return_data_kind || undefined,
    signatureScheme: 'SPHINCS+-128s' as const,
    blockHash: blockPayload?.block_hash || header.hash || '',
    confirmations: Number(tx.confirmations ?? blockPayload?.confirmations) || 0,
    feeSpx: tx.fee_spx || '0',
    feeNspx: tx.fee_nspx || '0',
    age: tx.age,
    isContractTx: Boolean(tx.is_contract_tx),
    toContract: tx.to_contract ? formatSPIFAddress(tx.to_contract) : '',
    isContractDeploy: Boolean(tx.is_contract_deploy),
    createdContract: tx.created_contract ? formatSPIFAddress(tx.created_contract) : '',
    anchorContract: tx.anchor_contract ? formatSPIFAddress(tx.anchor_contract) : '',
    anchorTokenId: Number(tx.anchor_token_id) || 0,
    proof: tx.proof,
    signatureHash: tx.signature_hash || "",
    commitment: tx.commitment || "",
    authTimestamp: tx.auth_timestamp || "",
    authNonce: tx.auth_nonce || "",
    gasUsed: toNumber(tx.gas_used),
    burnedThisTxSpx: tx.burned_this_tx_spx,
    burnedThisTxNspx: tx.burned_this_tx_nspx,
  };
}

function toNumber(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

// ============================================================================
// Transactions
// ============================================================================

export async function fetchTransaction(txid: string): Promise<Transaction | null> {
  try {
    const raw: any = await fetchApi(`/tx/${txid}`);
    return mapTransaction(raw);
  } catch {
    return null;
  }
}

function mapTransaction(raw: any): Transaction {
  return {
    txid: raw.txid || '',
    status: (raw.status as 'success' | 'pending' | 'failed') || 'success',
    sender: formatSPIFAddress(raw.sender || ''),
    receiver: formatSPIFAddress(raw.receiver || ''),
    amountSpx: raw.amount_spx || '0',
    amountNspx: raw.amount_nspx || '0',
    nonce: raw.nonce || 0,
    timestamp: raw.timestamp || 0,
    timestampIso: raw.timestamp_iso,
    blockHeight: raw.block_height || 0,
    gasLimit: Number(raw.gas_limit) || 0,
    gasPrice: Number(raw.gas_price) || 0,
    gasFeeSpx: raw.gas_fee_spx || '0',
    chainId: raw.chain_id?.toString() || 'sphinx-post-quantum-1',
    isSystemTx: raw.is_system_tx || false,
    signature: raw.signature || '',
    publicKey: raw.public_key || '',
    merkleRoot: raw.merkle_root || '',
    hasFullAuth: raw.has_full_auth || false,
    returnData: raw.return_data || undefined,
    returnDataText: raw.return_data_text || undefined,
    returnDataKind: raw.return_data_kind || undefined,
    signatureScheme: 'SPHINCS+-128s' as const,
    blockHash: raw.block_hash || '',
    confirmations: Number(raw.confirmations) || 0,
    feeSpx: raw.gas_fee_spx || '0',
    feeNspx: raw.fee_nspx || '0',
    age: raw.age,
    isContractTx: Boolean(raw.is_contract_tx),
    toContract: raw.to_contract ? formatSPIFAddress(raw.to_contract) : '',
    isContractDeploy: Boolean(raw.is_contract_deploy),
    createdContract: raw.created_contract ? formatSPIFAddress(raw.created_contract) : '',
    anchorContract: raw.anchor_contract ? formatSPIFAddress(raw.anchor_contract) : '',
    anchorTokenId: Number(raw.anchor_token_id) || 0,
    proof: raw.proof,
    signatureHash: raw.signature_hash || "",
    commitment: raw.commitment || "",
    authTimestamp: raw.auth_timestamp || "",
    authNonce: raw.auth_nonce || "",
    gasUsed: Number(raw.gas_used),
    burnedThisTxSpx: raw.burned_this_tx_spx,
    burnedThisTxNspx: raw.burned_this_tx_nspx,
  };
}

// ============================================================================
// Address
// ============================================================================

export async function fetchAddress(address: string): Promise<{
  wallet: Wallet;
  transactions: Transaction[];
} | null> {
  try {
    const rawHex = normalizeSPIFAddress(address);
    const raw: any = await fetchApi(`/address/${rawHex}`);

    const formattedAddress = formatSPIFAddress(raw.address || rawHex);

    const wallet: Wallet = {
      rank: 0,
      address: formattedAddress,
      balanceSpx: raw.balance_spx || '0',
      nonce: raw.nonce || 0,
      isActive: raw.nonce > 0,
      addressType: 'SPHINCS+ (Stateless Hash)',
    };

    const transactions: Transaction[] = (raw.transactions || []).map((tx: any) => ({
      txid: tx.txid || '',
      status: (tx.status as 'success' | 'pending' | 'failed') || 'success',
      sender: formatSPIFAddress(tx.sender || ''),
      receiver: formatSPIFAddress(tx.receiver || ''),
      amountSpx: tx.amount_spx || '0',
      amountNspx: tx.amount_nspx || '0',
      nonce: tx.nonce || 0,
      timestamp: tx.timestamp || 0,
      blockHeight: Number(tx.block_height) || 0,
      gasLimit: toNumber(tx.gas_limit),
      gasPrice: toNumber(tx.gas_price),
      gasFeeSpx: tx.fee_spx || '0',
      chainId: 'sphinx-post-quantum-1',
      isSystemTx: false,
      signature: '',
      publicKey: '',
      merkleRoot: '',
      hasFullAuth: false,
      signatureScheme: 'SPHINCS+-128s' as const,
      blockHash: tx.block_hash || '',
      confirmations: Number(tx.confirmations) || 0,
      feeSpx: tx.fee_spx || '0',
      feeNspx: tx.fee_nspx || '0',
      age: tx.age,
      // Contract provenance, so a wallet/address history names the collection
      // its own deploy created and the one its mint was anchored to.
      isContractDeploy: Boolean(tx.is_contract_deploy),
      createdContract: tx.created_contract ? formatSPIFAddress(tx.created_contract) : '',
      anchorContract: tx.anchor_contract ? formatSPIFAddress(tx.anchor_contract) : '',
      anchorTokenId: Number(tx.anchor_token_id) || 0,
    }));

    return { wallet, transactions };
  } catch {
    return null;
  }
}

// ============================================================================
// Mempool
// ============================================================================

/** Per-pool counts straight from the node's MempoolSnapshot. */
export interface MempoolPoolSummary {
  /** Accepted, not yet validated. */
  broadcast: number;
  /** Mid-validation right now. */
  validating: number;
  /** Validated and mineable — what "pending" properly means. */
  pending: number;
  /** Rejected by validation; can never confirm. */
  invalid: number;
  /** Every transaction the pool still tracks. */
  total: number;
}

/**
 * One mempool row that is NOT mineable yet — either still being accepted
 * (broadcast/validating) or already refused (invalid, carrying the node's
 * reason). Kept separate from Transaction because such a row has no amount,
 * no fee and no confirmation to render: it is a pipeline state, not a
 * transfer.
 */
export interface MempoolTxRow {
  txid: string;
  sender: string;
  nonce?: number;
  status: string;
  /** Only set for a rejected row: why it can never confirm. */
  reason?: string;
}

/**
 * The full mempool picture. `pending` alone cannot answer "where did my send
 * go?" — the node returns a txid from sendrawtransaction BEFORE validating the
 * nonce, so a send is briefly in-flight and may end up rejected, and both of
 * those read as an empty pending list. The pool summary and the two extra
 * lists exist so a zero here is never the whole story.
 */
export interface MempoolView {
  pending: Transaction[];
  pool: MempoolPoolSummary;
  inFlight: MempoolTxRow[];
  rejected: MempoolTxRow[];
}

const EMPTY_POOL: MempoolPoolSummary = {
  broadcast: 0,
  validating: 0,
  pending: 0,
  invalid: 0,
  total: 0,
};

function mapMempoolTx(tx: any): Transaction {
  return {
    txid: tx.txid || '',
    status: 'pending' as const,
    sender: formatSPIFAddress(tx.sender || ''),
    receiver: formatSPIFAddress(tx.receiver || ''),
    amountSpx: tx.amount_spx || '0',
    amountNspx: '0',
    nonce: tx.nonce || 0,
    timestamp: tx.timestamp || 0,
    blockHeight: 0,
    gasLimit: toNumber(tx.gas_limit),
    gasPrice: toNumber(tx.gas_price),
    gasFeeSpx: '0',
    chainId: 'sphinx-post-quantum-1',
    isSystemTx: false,
    signature: '',
    publicKey: '',
    merkleRoot: '',
    hasFullAuth: false,
    signatureScheme: 'SPHINCS+-128s' as const,
    blockHash: '',
    confirmations: 0,
    feeSpx: '0',
    feeNspx: '0',
    // A pending deploy's address is already determined by
    // (sender, nonce, code), and a pending mint anchor already names its
    // collection, so both are carried through for the mempool view.
    isContractTx: Boolean(tx.is_contract_tx),
    toContract: tx.to_contract ? formatSPIFAddress(tx.to_contract) : '',
    isContractDeploy: Boolean(tx.is_contract_deploy),
    createdContract: tx.created_contract ? formatSPIFAddress(tx.created_contract) : '',
    anchorContract: tx.anchor_contract ? formatSPIFAddress(tx.anchor_contract) : '',
    anchorTokenId: Number(tx.anchor_token_id) || 0,
  };
}

function mapMempoolRow(raw: any): MempoolTxRow {
  return {
    txid: raw.txid || '',
    sender: formatSPIFAddress(raw.sender || ''),
    nonce: Number(raw.nonce) || 0,
    status: raw.status || 'unknown',
    reason: raw.reason || undefined,
  };
}

/**
 * Fetches the full mempool picture: the mineable pending set, the pool
 * breakdown, the in-flight entries awaiting validation, and the rejected
 * entries with the node's reason for each.
 */
export async function fetchMempoolView(): Promise<MempoolView> {
  try {
    const raw: any = await fetchApi('/mempool');
    const rows = (name: string): any[] =>
      Array.isArray(raw?.[name]) ? raw[name] : [];
    return {
      pending: rows('pending_txs').map(mapMempoolTx),
      pool: { ...EMPTY_POOL, ...(raw?.pool || {}) },
      inFlight: rows('in_flight_txs').map(mapMempoolRow),
      rejected: rows('rejected_txs').map(mapMempoolRow),
    };
  } catch {
    return { pending: [], pool: { ...EMPTY_POOL }, inFlight: [], rejected: [] };
  }
}

/** The mineable pending transactions only — see fetchMempoolView for the rest. */
export async function fetchMempool(): Promise<Transaction[]> {
  return (await fetchMempoolView()).pending;
}

// ============================================================================
// Wallets / Rich List
// ============================================================================

export async function fetchWallets(limit: number = 50): Promise<Wallet[]> {
  try {
    const raw: any = await fetchApi(`/wallets?limit=${limit}`);

    if (!raw.rich_list || !Array.isArray(raw.rich_list)) {
      return [];
    }

    return raw.rich_list.map((w: any, idx: number) => ({
      rank: w.rank || idx + 1,
      address: formatSPIFAddress(w.address || ''),
      balanceSpx: w.balance_spx || '0',
      nonce: w.nonce || 0,
      isActive: w.is_active || false,
      addressType: 'SPHINCS+ (Stateless Hash)',
    }));
  } catch {
    return [];
  }
}

// ============================================================================
// Validators
// ============================================================================

export async function fetchValidators(): Promise<Validator[]> {
  try {
    const raw: any = await fetchApi('/validators');

    if (!raw.validators || !Array.isArray(raw.validators)) {
      return [];
    }

    return raw.validators.map((v: any) => ({
      id: v.id || '',
      stakeSpx: v.stake_spx || '0',
      stakePercent: v.stake_percent || 0,
      rewardAddress: formatSPIFAddress(v.reward_address || ''),
      status: (v.status as 'active' | 'slashed' | 'exited') || 'active',
      activationEpoch: v.activation_epoch || 0,
      exitEpoch: v.exit_epoch ?? '∞',
      lastAttested: v.last_attested || 0,
      isSlashed: v.is_slashed || false,
      country: v.country || 'Unknown',
      city: v.city || 'Unknown',
      latitude: v.latitude || 0,
      longitude: v.longitude || 0,
      ip: v.ip || '',
    }));
  } catch {
    return [];
  }
}

export async function fetchValidatorMap(): Promise<Validator[]> {
  try {
    const raw: any = await fetchApi('/validators/map');

    if (!raw.validators || !Array.isArray(raw.validators)) {
      return [];
    }

    return raw.validators.map((v: any) => ({
      id: v.id || '',
      stakeSpx: v.stake_spx || '0',
      stakePercent: 0,
      rewardAddress: '',
      status: (v.status as 'active' | 'slashed' | 'exited') || 'active',
      activationEpoch: 0,
      exitEpoch: '∞',
      lastAttested: 0,
      isSlashed: false,
      country: v.country || 'Unknown',
      city: v.city || 'Unknown',
      latitude: v.latitude || 0,
      longitude: v.longitude || 0,
      ip: v.ip || '',
    }));
  } catch {
    return [];
  }
}

// ============================================================================
// Search & Mining
// ============================================================================

export async function search(query: string): Promise<{
  redirect?: string;
  matches?: Array<{ type: string; id: string; name: string; extra?: string }>;
}> {
  try {
    const normalizedQuery = normalizeSPIFAddress(query);
    const raw: any = await fetchApi(`/search?q=${encodeURIComponent(normalizedQuery)}`);
    return {
      redirect: raw.redirect,
      matches: raw.matches || [],
    };
  } catch {
    return { matches: [] };
  }
}

/** Result of a mine request, with its data provenance made explicit. */
export interface MineResult {
  block: Block;
  transactions: Transaction[];
  /**
   * True when this block came from the local simulation engine because the node
   * was unreachable. A simulated block is NOT on any chain — callers must not
   * present it as confirmed chain state.
   */
  simulated: boolean;
}

/**
 * Ask the node to produce and commit one block (POST /explorer/mine).
 *
 * The distinction between "the node said no" and "there is no node" matters
 * here: an explicit refusal (e.g. 409 on a multi-validator cluster, where the
 * PBFT leader owns block production) is thrown as an Error so the caller can
 * surface the real reason. Only a transport-level failure — nothing listening
 * on the proxy target — falls back to the simulation engine, and that fallback
 * is flagged via `simulated`.
 */
export async function mineBlock(): Promise<MineResult> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/mine`, {
      method: 'POST',
      headers: { 'Accept': 'application/json' },
    });
  } catch {
    // Backend unreachable: fall back to the simulation engine, clearly flagged.
    dataSource = 'mock';
    const result = mock.mineNewBlock();
    return {
      block: result.newBlock,
      transactions: result.addedTxs,
      simulated: true,
    };
  }

  if (!res.ok) {
    // The node answered and refused. Report why instead of inventing a block.
    const detail = await res.json().catch(() => null) as { error?: string } | null;
    throw new Error(detail?.error || `mine failed: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  dataSource = 'live';
  return {
    block: mapBlockDetail(data),
    transactions: (data.transactions || []).map((tx: any) => mapBlockTransaction(tx, data)),
    simulated: false,
  };
}

