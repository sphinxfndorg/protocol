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

// Base URL for API requests. In development, Vite proxies /api to the Go backend.
// In production, the Go server serves both the static files and the API.
const API_BASE = '/api/v1/explorer';

// ============================================================================
// Response type helpers
// ============================================================================

interface ApiResponse<T> {
  data?: T;
  error?: string;
}

// ============================================================================
// Generic fetch wrapper
// ============================================================================

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
    headers: { 'Accept': 'application/json' },
    ...options,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => 'unknown error');
    throw new Error(`API ${res.status} ${res.statusText}: ${text}`);
  }

  return res.json();
}

// ============================================================================
// Stats
// ============================================================================

export async function fetchStats(): Promise<NetworkStats> {
  const raw: any = await fetchApi('/stats');

  // Burn accounting may come from the dedicated `burn` panel or, on older
  // nodes, only from the `wallets` block. Prefer the panel and fall back so the
  // dashboard never renders an empty burn card against a compatible backend.
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

// BlockDetailPayload is what the block page binds to: the header plus the full
// transaction body and the PBFT attestations that committed it.
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

/**
 * Coerces the backend's commit status into the badge vocabulary the UI styles.
 * The node reports PBFT phases ("proposed"/"prepared"/"committed"); the explorer
 * renders a narrower set, so anything unknown reads as committed rather than
 * blank, and the pre-commit phases read as pending.
 */
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
    txCount: Number(b.tx_count) || 0,
    signatureScheme: 'SPHINCS+-128s' as const,
    version: Number(b.version) || 0,
    unclesHash: b.uncles_hash || '',
    sigValid: Boolean(b.sig_valid),
    attestationCount: Number(b.attestation_count) || 0,
    confirmations: Number(b.confirmations) || 0,
    age: b.age || '',
    ageSec: Number(b.age_sec),
    // Block-level burn information
    burnedThisBlockSpx: b.burned_this_block_spx,
    burnedThisBlockNspx: b.burned_this_block_nspx,
    burnedBeforeNspx: b.burned_before_nspx,
    // Coinbase/block reward details
    blockRewardSpx: b.block_reward_spx,
    blockRewardNspx: b.block_reward_nspx,
    blockRewardMinerNspx: b.block_reward_miner_nspx,
    blockRewardBurnedNspx: b.block_reward_burned_nspx,
    // Network/protocol details
    extraData: b.extra_data,
    miner: b.miner,
    logsBloom: b.logs_bloom,
    gasPrice: b.gas_price,
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
    txCount: Number(raw.tx_count) || raw.transactions?.length || 0,
    signatureScheme: 'SPHINCS+-128s' as const,
    version: Number(header.version) || 0,
    unclesHash: header.uncles_hash || '',
    sigValid: Boolean(header.sig_valid),
    attestationCount: Number(raw.att_count) || 0,
    confirmations: Number(raw.confirmations) || 0,
    age: header.age || '',
    ageSec: Number(header.age_sec),
    // Block-level burn information
    burnedThisBlockSpx: raw.burned_this_block_spx,
    burnedThisBlockNspx: raw.burned_this_block_nspx,
    burnedBeforeNspx: raw.burned_before_nspx,
    // Coinbase/block reward details
    blockRewardSpx: raw.block_reward_spx,
    blockRewardNspx: raw.block_reward_nspx,
    blockRewardMinerNspx: raw.block_reward_miner_nspx,
    blockRewardBurnedNspx: raw.block_reward_burned_nspx,
    // Network/protocol details
    extraData: header.extra_data,
    miner: header.miner,
    logsBloom: header.logs_bloom,
    gasPrice: header.gas_price,
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

/**
 * Maps a transaction row embedded in a block payload. Those rows carry the same
 * economic fields as the standalone /tx endpoint, so the block page can show
 * amounts, fees and confirmation depth without a request per transaction.
 */
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
    toContract: tx.to_contract || '',
    // Enhanced transaction details
    proof: tx.proof,
    gasUsed: toNumber(tx.gas_used),
    // Burn information for this transaction
    burnedThisTxSpx: tx.burned_this_tx_spx,
    burnedThisTxNspx: tx.burned_this_tx_nspx,
  };
}

/** Parses a backend numeric string (nSPX/gas figures) without losing precision. */
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
    // Confirmation provenance from the standalone endpoint: naming the block
    // that committed the tx is what lets the detail page link to it.
    blockHash: raw.block_hash || '',
    confirmations: Number(raw.confirmations) || 0,
    feeSpx: raw.gas_fee_spx || '0',
    feeNspx: raw.fee_nspx || '0',
    age: raw.age,
    isContractTx: Boolean(raw.is_contract_tx),
    toContract: raw.to_contract || '',
    // Enhanced transaction details
    proof: raw.proof,
    gasUsed: Number(raw.gas_used),
    // Burn information for this transaction
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
    // Normalize the address to raw hex before querying the backend
    const rawHex = normalizeSPIFAddress(address);
    const raw: any = await fetchApi(`/address/${rawHex}`);

    // Format the address from the response into SPIF display format
    const formattedAddress = formatSPIFAddress(raw.address || rawHex);

    const wallet: Wallet = {
      rank: 0,
      address: formattedAddress,
      balanceSpx: raw.balance_spx || '0',
      nonce: raw.nonce || 0,
      isActive: raw.nonce > 0,
      addressType: raw.address_type === 'SPIF' ? 'SPHINCS+ (Stateless Hash)' : 'Legacy (ECDSA - Vulnerable)',
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
      // The address endpoint now reports the committing block per row, so each
      // history line can state its confirmation depth.
      blockHeight: Number(tx.block_height) || 0,
      gasLimit: 0,
      gasPrice: 0,
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
    }));

    return { wallet, transactions };
  } catch {
    return null;
  }
}

// ============================================================================
// Mempool
// ============================================================================

export async function fetchMempool(): Promise<Transaction[]> {
  try {
    const raw: any = await fetchApi('/mempool');

    if (!raw.pending_txs || !Array.isArray(raw.pending_txs)) {
      return [];
    }

    return raw.pending_txs.map((tx: any) => ({
      txid: tx.txid || '',
      status: 'pending' as const,
      sender: formatSPIFAddress(tx.sender || ''),
      receiver: formatSPIFAddress(tx.receiver || ''),
      amountSpx: tx.amount_spx || '0',
      amountNspx: '0',
      nonce: tx.nonce || 0,
      timestamp: tx.timestamp || 0,
      blockHeight: 0,
      gasLimit: 0,
      gasPrice: 0,
      gasFeeSpx: '0',
      chainId: 'sphinx-post-quantum-1',
      isSystemTx: false,
      signature: '',
      publicKey: '',
      merkleRoot: '',
      hasFullAuth: false,
      signatureScheme: 'SPHINCS+-128s' as const,
      // A mempool transaction is unconfirmed by definition: no block, no depth.
      blockHash: '',
      confirmations: 0,
      feeSpx: '0',
      feeNspx: '0',
    }));
  } catch {
    return [];
  }
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
      addressType: w.address_type === 'SPIF' ? 'SPHINCS+ (Stateless Hash)' : 'Legacy (ECDSA - Vulnerable)',
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
// Search
// ============================================================================

export async function search(query: string): Promise<{
  redirect?: string;
  matches?: Array<{ type: string; id: string; name: string; extra?: string }>;
}> {
  try {
    // Normalize SPIF addresses to raw hex before sending to backend
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
