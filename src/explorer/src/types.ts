/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface Block {
  height: number;
  hash: string;
  parentHash: string;
  timestamp: number;
  timestampIso?: string;
  difficulty: string;
  nonce: number;
  gasLimit: number;
  gasUsed: number;
  proposer: string;
  txsRoot: string;
  stateRoot: string;
  chainWeight: string;
  commitStatus: 'committed' | 'finalized' | 'pending';
  txCount: number;
  signatureScheme: 'SPHINCS+-128f' | 'SPHINCS+-128s' | 'SPHINCS+-192f' | 'SPHINCS+-256f' | 'XMSS';
  // Header fields the audit view renders. They are present on both the list and
  // detail payloads so a block card never has to guess at a commitment.
  version: number;
  unclesHash: string;
  sigValid: boolean;
  attestationCount: number;
  confirmations: number;
  age: string;
  ageSec?: number;
  // Optional: only the detail payload carries a per-transaction body, so list
  // rows leave this undefined rather than pretending the block is empty.
  transactions?: Transaction[];
  attestations?: Attestation[];
  // Block-level burn information (added for enhanced explorer view)
  burnedThisBlockSpx?: string;
  burnedThisBlockNspx?: string;
  burnedBeforeNspx?: string;
  // Coinbase/block reward details
  blockRewardSpx?: string;
  blockRewardNspx?: string;
  // Reward split: the proposer's spendable slice and the permanently-burned
  // slice (BlockRewardBurnBPS). Both are nSPX strings.
  blockRewardMinerNspx?: string;
  blockRewardBurnedNspx?: string;
  // Network/protocol details
  extraData?: string;
  miner?: string;
  logsBloom?: string;
  gasPrice?: string;
}

// Attestation is a PBFT commit vote from a validator for a specific block.
export interface Attestation {
  validatorId: string;
  blockHash: string;
  view: number;
  stakeSpx: string;
}

export interface Transaction {
  txid: string;
  status: 'success' | 'pending' | 'failed';
  sender: string;
  receiver: string;
  amountSpx: string;
  amountNspx: string;
  nonce: number;
  timestamp: number;
  timestampIso?: string;
  blockHeight: number;
  gasLimit: number;
  gasPrice: number;
  gasFeeSpx: string;
  chainId: string;
  isSystemTx: boolean;
  signature: string;
  publicKey: string;
  merkleRoot: string;
  hasFullAuth: boolean;
  returnData?: string;
  // Human-readable rendering of the OP_RETURN payload (printable ASCII as
  // text, anything else hex) plus a coarse classification so the UI can label
  // mint anchors, JSON payloads and plain memos distinctly.
  returnDataText?: string;
  returnDataKind?: string;
  signatureScheme: 'SPHINCS+-128f' | 'SPHINCS+-128s' | 'SPHINCS+-192f' | 'SPHINCS+-256f' | 'XMSS' | 'Legacy (ECDSA)';
  // Confirmation provenance. blockHash is empty and confirmations is 0 while a
  // transaction is still in the mempool.
  blockHash: string;
  confirmations: number;
  feeSpx: string;
  feeNspx: string;
  age?: string;
  isContractTx?: boolean;
  toContract?: string;
  // Enhanced transaction details
  proof?: string;
  gasUsed?: number;
  // Burn information for this transaction
  burnedThisTxSpx?: string;
  burnedThisTxNspx?: string;
}

export interface Validator {
  id: string;
  stakeSpx: string;
  stakePercent: number;
  rewardAddress: string;
  status: 'active' | 'slashed' | 'exited';
  activationEpoch: number;
  exitEpoch: string | number;
  lastAttested: number;
  isSlashed: boolean;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  ip: string;
}

export interface Wallet {
  rank: number;
  address: string;
  balanceSpx: string;
  nonce: number;
  isActive: boolean;
  addressType: 'SPHINCS+ (Stateless Hash)' | 'Legacy (ECDSA - Vulnerable)';
}

export interface NetworkStats {
  tipHeight: number;
  currentTps: number;
  averageTps: number;
  peakTps: number;
  mempoolSize: number;
  mempoolBytes: number;
  totalAccounts: number;
  activeWallets: number;
  sphincsAddresses: number;
  activeValidators: number;
  totalValidators: number;
  slashedValidators: number;
  totalStakeSpx: string;
  minStakeSpx: number;
  chainId: string;
  symbol: string;
  genesisHash: string;
  syncMode: string;
  // Supply and burn accounting, served verbatim by /explorer/stats. Burned coins
  // live at the provably-unspendable DEAD address, so the totals below are the
  // single auditable source for "how many coins have been burned".
  burnAddress: string;
  burnedSpx: string;
  burnedNspx: string;
  circulatingSpx: string;
  circulatingNspx: string;
  totalSupplySpx: string;
  totalSupplyNspx: string;
  maxSupplySpx: string;
  burnPercent: number;
}

// An address is counted only when it is first seen in a canonical block.
// Offline wallet creation is deliberately not collected by the explorer.
export interface HolderGrowthPoint {
  date: string;
  holders: number;
  newHolders: number;
}

// Block detail with enhanced information for the explorer view
export interface BlockDetail extends Block {
  // Burn state for this specific block
  burnState?: {
    burnAddress: string;
    burnedSpx: string;
    burnedNspx: string;
    feeBurnBps: number;
    rewardBurnBps: number;
  };
  // Distribution information
  distribution?: {
    totalStake: string;
    validatorRewards: string;
    stakerRewards: string;
    treasury: string;
    burned: string;
  };
  // Full block header details
  headerDetails?: {
    version: number;
    height: number;
    timestamp: number;
    timestampIso: string;
    parentHash: string;
    hash: string;
    difficulty: string;
    nonce: number;
    txsRoot: string;
    stateRoot: string;
    unclesHash: string;
    gasLimit: string;
    gasUsed: string;
    extraData: string;
    miner: string;
    logsBloom: string;
    proposer: string;
    sigValid: boolean;
    commitStatus: string;
    chainWeight: string;
  };
}
