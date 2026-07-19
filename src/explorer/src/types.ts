/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface Block {
  height: number;
  hash: string;
  parentHash: string;
  timestamp: number;
  difficulty: string;
  nonce: string;
  gasLimit: number;
  gasUsed: number;
  proposer: string;
  txsRoot: string;
  stateRoot: string;
  chainWeight: string;
  commitStatus: 'committed' | 'finalized' | 'pending';
  txCount: number;
  signatureScheme: 'SPHINCS+-128f' | 'SPHINCS+-128s' | 'SPHINCS+-192f' | 'SPHINCS+-256f' | 'XMSS';
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
  signatureScheme: 'SPHINCS+-128f' | 'SPHINCS+-128s' | 'SPHINCS+-192f' | 'SPHINCS+-256f' | 'XMSS' | 'Legacy (ECDSA)';
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
}
