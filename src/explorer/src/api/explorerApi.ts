/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * API service layer for the Sphinx Ledger Explorer.
 * Connects the React frontend to the Go backend HTTP API.
 * All addresses from the backend (raw hex) are formatted into SPIF display format.
 */

import { Block, Transaction, Validator, Wallet, NetworkStats } from '../types';
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

  return {
    tipHeight: raw.block_count || 0,
    currentTps: raw.tps?.current_tps || 0,
    averageTps: raw.tps?.average_tps || 0,
    peakTps: raw.tps?.peak_tps || 0,
    mempoolSize: raw.mempool?.size || 0,
    mempoolBytes: raw.mempool?.bytes || 0,
    totalAccounts: raw.wallets?.total_accounts || 0,
    activeWallets: raw.wallets?.active_wallets || 0,
    sphincsAddresses: raw.wallets?.spif_addresses || 0,
    activeValidators: raw.validators?.active_validators || 0,
    totalValidators: raw.validators?.total_validators || 0,
    slashedValidators: 0,
    totalStakeSpx: raw.validators?.total_stake_spx || '0',
    minStakeSpx: raw.validators?.min_stake_spx || 0,
    chainId: raw.chain?.chain_id?.toString() || 'sphinx-post-quantum-1',
    symbol: raw.chain?.symbol || 'SPX',
    genesisHash: raw.chain?.genesis_hash || '',
    syncMode: raw.chain?.sync_mode || 'Fully Audited (SPHINCS+ Hash Signature Verified)',
  };
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

export async function fetchBlockByHeight(height: number): Promise<Block | null> {
  try {
    const raw: any = await fetchApi(`/block/${height}`);
    return mapBlockDetail(raw);
  } catch {
    return null;
  }
}

export async function fetchBlockByHash(hash: string): Promise<Block | null> {
  try {
    const raw: any = await fetchApi(`/block/hash/${hash}`);
    return mapBlockDetail(raw);
  } catch {
    return null;
  }
}

function mapBlock(b: any): Block {
  return {
    height: b.height,
    hash: b.hash || '',
    parentHash: b.prev_hash || '',
    timestamp: b.timestamp || 0,
    difficulty: b.difficulty || '1',
    nonce: b.nonce?.toString() || '0',
    gasLimit: Number(b.gas_limit) || 0,
    gasUsed: Number(b.gas_used) || 0,
    proposer: formatSPIFAddress(b.proposer || ''),
    txsRoot: b.txs_root || '',
    stateRoot: b.state_root || '',
    chainWeight: b.chain_weight || '0',
    commitStatus: (b.commit_status as 'committed' | 'finalized' | 'pending') || 'committed',
    txCount: b.tx_count || 0,
    signatureScheme: 'SPHINCS+-128s' as const,
  };
}

function mapBlockDetail(raw: any): Block {
  const header = raw.header || raw;
  return {
    height: raw.block_height ?? header.height ?? 0,
    hash: raw.block_hash || header.hash || '',
    parentHash: header.parent_hash || '',
    timestamp: header.timestamp || 0,
    difficulty: header.difficulty || '1',
    nonce: header.nonce?.toString() || '0',
    gasLimit: Number(header.gas_limit) || 0,
    gasUsed: Number(header.gas_used) || 0,
    proposer: formatSPIFAddress(header.proposer || ''),
    txsRoot: header.txs_root || '',
    stateRoot: header.state_root || '',
    chainWeight: header.chain_weight || '0',
    commitStatus: (header.commit_status as 'committed' | 'finalized' | 'pending') || 'committed',
    txCount: raw.tx_count || raw.transactions?.length || 0,
    signatureScheme: 'SPHINCS+-128s' as const,
  };
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
    signatureScheme: 'SPHINCS+-128s' as const,
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