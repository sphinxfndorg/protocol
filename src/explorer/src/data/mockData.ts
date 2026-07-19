/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Block, Transaction, Validator, Wallet, NetworkStats } from '../types';

// Helper to generate a random hex string simulating post-quantum hash
function genHex(length: number): string {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * 16)];
  }
  return result;
}

function genPQHash(prefix: string): string {
  return `${prefix}_${genHex(48)}`;
}

// Global lists
let blocks: Block[] = [];
let transactions: Transaction[] = [];
let mempool: Transaction[] = [];
let validators: Validator[] = [];
let wallets: Wallet[] = [];
let stats: NetworkStats;

// Locations for validators
const cities = [
  { city: 'Reykjavik', country: 'Iceland', lat: 64.1466, lon: -21.9426, ip: '185.112.144.' },
  { city: 'Tokyo', country: 'Japan', lat: 35.6762, lon: 139.6503, ip: '210.140.10.' },
  { city: 'Zurich', country: 'Switzerland', lat: 47.3769, lon: 8.5417, ip: '193.134.254.' },
  { city: 'San Francisco', country: 'USA', lat: 37.7749, lon: -122.4194, ip: '104.244.42.' },
  { city: 'Singapore', country: 'Singapore', lat: 1.3521, lon: 103.8198, ip: '46.137.222.' },
  { city: 'Frankfurt', country: 'Germany', lat: 50.1109, lon: 8.6821, ip: '194.25.100.' },
  { city: 'Sydney', country: 'Australia', lat: -33.8688, lon: 151.2093, ip: '118.209.12.' },
  { city: 'São Paulo', country: 'Brazil', lat: -23.5505, lon: -46.6333, ip: '177.100.200.' },
  { city: 'Cape Town', country: 'South Africa', lat: -33.9249, lon: 18.4241, ip: '197.80.12.' },
  { city: 'Mumbai', country: 'India', lat: 19.0760, lon: 72.8777, ip: '125.22.45.' },
  { city: 'Toronto', country: 'Canada', lat: 43.6532, lon: -79.3832, ip: '198.51.100.' },
  { city: 'Stockholm', country: 'Sweden', lat: 59.3293, lon: 18.0686, ip: '192.36.125.' },
  { city: 'London', country: 'UK', lat: 51.5074, lon: -0.1278, ip: '195.12.33.' },
  { city: 'Paris', country: 'France', lat: 48.8566, lon: 2.3522, ip: '194.254.12.' },
  { city: 'New York', country: 'USA', lat: 40.7128, lon: -74.0060, ip: '108.160.10.' },
  { city: 'Buenos Aires', country: 'Argentina', lat: -34.6037, lon: -58.3816, ip: '200.45.121.' },
  { city: 'Nairobi', country: 'Kenya', lat: -1.2921, lon: 36.8219, ip: '197.248.8.' },
  { city: 'Lagos', country: 'Nigeria', lat: 6.5244, lon: 3.3792, ip: '105.112.50.' },
  { city: 'Cairo', country: 'Egypt', lat: 30.0444, lon: 31.2357, ip: '196.218.4.' },
  { city: 'Dubai', country: 'UAE', lat: 25.2048, lon: 55.2708, ip: '91.74.19.' },
  { city: 'Seoul', country: 'South Korea', lat: 37.5665, lon: 126.9780, ip: '211.234.80.' },
  { city: 'Taipei', country: 'Taiwan', lat: 25.0330, lon: 121.5654, ip: '210.60.12.' },
  { city: 'Bangkok', country: 'Thailand', lat: 13.7563, lon: 100.5018, ip: '203.150.19.' },
  { city: 'Auckland', country: 'New Zealand', lat: -36.8485, lon: 174.7633, ip: '121.30.222.' },
  { city: 'Honolulu', country: 'USA (Hawaii)', lat: 21.3069, lon: -157.8583, ip: '66.160.20.' },
  { city: 'Bogota', country: 'Colombia', lat: 4.7110, lon: -74.0721, ip: '186.28.140.' },
  { city: 'Casablanca', country: 'Morocco', lat: 33.5731, lon: -7.5898, ip: '196.200.120.' },
  { city: 'Warsaw', country: 'Poland', lat: 52.2297, lon: 21.0122, ip: '195.116.14.' },
  { city: 'Jakarta', country: 'Indonesia', lat: -6.2088, lon: 106.8456, ip: '103.12.19.' },
  { city: 'Madrid', country: 'Spain', lat: 40.4168, lon: -3.7038, ip: '212.128.40.' }
];

// Initialize Data
export function initializeBlockchain() {
  const baseTipHeight = 125420;
  const now = Math.floor(Date.now() / 1000);

  // 1. Generate Wallets
  wallets = [
    {
      rank: 1,
      address: 'spif1_sphincsplus_reserve_' + genHex(32),
      balanceSpx: '24500000.00000000',
      nonce: 1420,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 2,
      address: 'spif1_sphincsplus_treasury_' + genHex(32),
      balanceSpx: '12800000.00000000',
      nonce: 840,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 3,
      address: 'spif1_quantum_safe_cold_' + genHex(32),
      balanceSpx: '8420000.55000000',
      nonce: 310,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 4,
      address: 'spif1_sphincsplus_whale_' + genHex(32),
      balanceSpx: '4500000.00000000',
      nonce: 45,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 5,
      address: 'spif1_node_operator_alpha_' + genHex(32),
      balanceSpx: '2500000.12500000',
      nonce: 990,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 6,
      address: 'spif1_republique_zurich_' + genHex(32),
      balanceSpx: '1850000.00000000',
      nonce: 122,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 7,
      address: 'spif1_sphincsplus_nexus_node_' + genHex(32),
      balanceSpx: '1200000.00000000',
      nonce: 412,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 8,
      address: 'spif1_early_miner_' + genHex(32),
      balanceSpx: '950000.00000000',
      nonce: 12,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 9,
      address: 'spif1_quantum_armor_vault_' + genHex(32),
      balanceSpx: '720000.00000000',
      nonce: 204,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    },
    {
      rank: 10,
      address: 'spif1_shield_user_wallet_' + genHex(32),
      balanceSpx: '45000.42000000',
      nonce: 88,
      isActive: true,
      addressType: 'SPHINCS+ (Stateless Hash)'
    }
  ];

  // Generate 20 more minor wallets
  for (let i = 11; i <= 30; i++) {
    const addressType = 'SPHINCS+ (Stateless Hash)';
    const prefix = 'spif1_';
    wallets.push({
      rank: i,
      address: prefix + genHex(32),
      balanceSpx: (Math.random() * 25000 + 50).toFixed(8),
      nonce: Math.floor(Math.random() * 100),
      isActive: Math.random() > 0.2,
      addressType: addressType
    });
  }

  // 2. Generate Validators
  validators = cities.map((c, i) => {
    const stake = (500000 + Math.random() * 1500000).toFixed(4);
    return {
      id: `val_${genHex(12)}_node_${i + 1}`,
      stakeSpx: stake,
      stakePercent: 0, // calculated later
      rewardAddress: 'spif1_val_reward_' + genHex(24),
      status: Math.random() > 0.1 ? 'active' : (Math.random() > 0.5 ? 'exited' : 'slashed'),
      activationEpoch: 12,
      exitEpoch: '∞',
      lastAttested: baseTipHeight - Math.floor(Math.random() * 5),
      isSlashed: false,
      city: c.city,
      country: c.country,
      latitude: c.lat,
      longitude: c.lon,
      ip: c.ip + Math.floor(Math.random() * 254)
    };
  });

  // Handle slashed validator
  const slashedVal = validators.find(v => v.status === 'slashed');
  if (slashedVal) slashedVal.isSlashed = true;

  // Calculate percentages
  const totalStake = validators.reduce((acc, v) => acc + parseFloat(v.stakeSpx), 0);
  validators.forEach(v => {
    v.stakePercent = (parseFloat(v.stakeSpx) / totalStake) * 100;
  });

  // 3. Generate Historical Blocks
  let prevHash = genPQHash('0x_genesis');
  for (let i = 15; i >= 0; i--) {
    const height = baseTipHeight - i;
    const blockTime = now - i * 15 - Math.floor(Math.random() * 5); // roughly 15s blocks
    const blockHash = genPQHash(`0x_block_${height}`);
    const proposer = validators[Math.floor(Math.random() * validators.length)].id;
    const txCount = Math.floor(Math.random() * 8) + 1;
    const signatureScheme = 'SPHINCS+-128s';

    // Generate block transactions
    const blockTxs: Transaction[] = [];
    for (let t = 0; t < txCount; t++) {
      const senderIdx = Math.floor(Math.random() * wallets.length);
      const receiverIdx = (senderIdx + 1) % wallets.length;
      const amount = (Math.random() * 150 + 0.1).toFixed(8);
      const isSystem = t === 0; // Coinbase

      const txid = genPQHash('0x_tx');
      const tx: Transaction = {
        txid,
        status: 'success',
        sender: isSystem ? '0x_genesis_coinbase_pqc' : wallets[senderIdx].address,
        receiver: wallets[receiverIdx].address,
        amountSpx: amount,
        amountNspx: (parseFloat(amount) * 100000000).toFixed(0),
        nonce: isSystem ? 0 : wallets[senderIdx].nonce++,
        timestamp: blockTime,
        blockHeight: height,
        gasLimit: 85000,
        gasPrice: 15,
        gasFeeSpx: (0.001275).toFixed(8),
        chainId: 'sphinx-post-quantum-1',
        isSystemTx: isSystem,
        signature: 'pq_sig_' + genHex(128),
        publicKey: 'pq_pk_' + genHex(64),
        merkleRoot: 'mr_' + genHex(32),
        hasFullAuth: true,
        signatureScheme: 'SPHINCS+-128s',
        returnData: isSystem ? 'Sphinx block reward & quantum signature validation' : (Math.random() > 0.7 ? 'OP_RETURN: Quantum-Proof Token Swap' : undefined)
      };

      // Apply balances
      if (!isSystem) {
        const sBal = parseFloat(wallets[senderIdx].balanceSpx) - parseFloat(amount) - 0.001275;
        wallets[senderIdx].balanceSpx = Math.max(0, sBal).toFixed(8);
      }
      const rBal = parseFloat(wallets[receiverIdx].balanceSpx) + parseFloat(amount);
      wallets[receiverIdx].balanceSpx = rBal.toFixed(8);

      blockTxs.push(tx);
      transactions.unshift(tx); // add to global tx log
    }

    const block: Block = {
      height,
      hash: blockHash,
      parentHash: prevHash,
      timestamp: blockTime,
      difficulty: '8.45T (SPHINCS+ validated)',
      nonce: 'pq_nonce_' + genHex(16),
      gasLimit: 25000000,
      gasUsed: blockTxs.reduce((acc, tx) => acc + tx.gasLimit, 0),
      proposer,
      txsRoot: 'mr_txs_' + genHex(32),
      stateRoot: 'mr_state_' + genHex(32),
      chainWeight: (i * 240 + 10000).toString(),
      commitStatus: i === 0 ? 'pending' : (i < 3 ? 'committed' : 'finalized'),
      txCount,
      signatureScheme: signatureScheme as any
    };

    blocks.unshift(block);
    prevHash = blockHash;
  }

  // 4. Populate Mempool
  for (let i = 0; i < 6; i++) {
    const senderIdx = Math.floor(Math.random() * wallets.length);
    const receiverIdx = (senderIdx + 1) % wallets.length;
    const amount = (Math.random() * 50 + 1).toFixed(8);
    mempool.push({
      txid: genPQHash('0x_tx_pending'),
      status: 'pending',
      sender: wallets[senderIdx].address,
      receiver: wallets[receiverIdx].address,
      amountSpx: amount,
      amountNspx: (parseFloat(amount) * 100000000).toFixed(0),
      nonce: wallets[senderIdx].nonce++,
      timestamp: now - Math.floor(Math.random() * 5),
      blockHeight: -1,
      gasLimit: 85000,
      gasPrice: 16,
      gasFeeSpx: '0.00136000',
      chainId: 'sphinx-post-quantum-1',
      isSystemTx: false,
      signature: 'pq_sig_' + genHex(128),
      publicKey: 'pq_pk_' + genHex(64),
      merkleRoot: 'mr_' + genHex(32),
      hasFullAuth: true,
      signatureScheme: 'SPHINCS+-128s',
      returnData: Math.random() > 0.5 ? 'OP_RETURN: Safe Vault Transfer' : undefined
    });
  }

  // 5. Build Stats
  stats = {
    tipHeight: baseTipHeight,
    currentTps: 4.25,
    averageTps: 3.84,
    peakTps: 24.50,
    mempoolSize: mempool.length,
    mempoolBytes: mempool.length * 480,
    totalAccounts: wallets.length,
    activeWallets: wallets.filter(w => w.isActive).length,
    sphincsAddresses: wallets.filter(w => w.addressType.includes('SPHINCS+')).length,
    activeValidators: validators.filter(v => v.status === 'active').length,
    totalValidators: validators.length,
    slashedValidators: validators.filter(v => v.status === 'slashed').length,
    totalStakeSpx: totalStake.toFixed(4),
    minStakeSpx: 100000,
    chainId: 'sphinx-post-quantum-1',
    symbol: 'SPX',
    genesisHash: '0x_genesis_' + genHex(48),
    syncMode: 'Fully Audited (SPHINCS+ Hash Signature Verified)'
  };
}

// Global actions
export function getBlockchainState() {
  if (blocks.length === 0) {
    initializeBlockchain();
  }
  return {
    blocks: [...blocks],
    transactions: [...transactions],
    mempool: [...mempool],
    validators: [...validators],
    wallets: [...wallets],
    stats: { ...stats }
  };
}

// Mine new block (simulates live blockchain activity)
export function mineNewBlock() {
  if (blocks.length === 0) initializeBlockchain();

  const now = Math.floor(Date.now() / 1000);
  const nextHeight = stats.tipHeight + 1;
  const blockHash = genPQHash(`0x_block_${nextHeight}`);
  const parentHash = blocks[0].hash; // since blocks are ordered descending (latest first)
  const proposer = validators[Math.floor(Math.random() * validators.length)].id;

  // Pull transactions from mempool
  const txCount = Math.min(mempool.length, Math.floor(Math.random() * 4) + 1);
  const blockTxs = mempool.splice(0, txCount);

  // Add coinbase reward transaction
  const rewardAmount = '12.50000000';
  const coinbaseTx: Transaction = {
    txid: genPQHash('0x_tx_coinbase'),
    status: 'success',
    sender: '0x_genesis_coinbase_pqc',
    receiver: validators.find(v => v.id === proposer)?.rewardAddress || wallets[0].address,
    amountSpx: rewardAmount,
    amountNspx: '1250000000',
    nonce: 0,
    timestamp: now,
    blockHeight: nextHeight,
    gasLimit: 85000,
    gasPrice: 0,
    gasFeeSpx: '0.00000000',
    chainId: 'sphinx-post-quantum-1',
    isSystemTx: true,
    signature: 'pq_sig_coinbase_' + genHex(128),
    publicKey: 'pq_pk_coinbase_' + genHex(64),
    merkleRoot: 'mr_cb_' + genHex(32),
    hasFullAuth: true,
    signatureScheme: 'SPHINCS+-128s',
    returnData: 'SPHINCS+ Coinbase block reward to validator node'
  };

  blockTxs.unshift(coinbaseTx);

  // Apply transactions to balances and save to general log
  blockTxs.forEach(tx => {
    tx.blockHeight = nextHeight;
    tx.status = 'success';
    transactions.unshift(tx);

    // update wallet balance for receiver
    const receiver = wallets.find(w => w.address === tx.receiver);
    if (receiver) {
      receiver.balanceSpx = (parseFloat(receiver.balanceSpx) + parseFloat(tx.amountSpx)).toFixed(8);
    }
  });

  const newBlock: Block = {
    height: nextHeight,
    hash: blockHash,
    parentHash,
    timestamp: now,
    difficulty: '8.48T (SPHINCS+ validated)',
    nonce: 'pq_nonce_' + genHex(16),
    gasLimit: 25000000,
    gasUsed: blockTxs.reduce((acc, tx) => acc + tx.gasLimit, 0),
    proposer,
    txsRoot: 'mr_txs_' + genHex(32),
    stateRoot: 'mr_state_' + genHex(32),
    chainWeight: (parseInt(blocks[0].chainWeight) + 240).toString(),
    commitStatus: 'pending',
    txCount: blockTxs.length,
    signatureScheme: 'SPHINCS+-128s'
  };

  // Update previous block commit statuses
  blocks.forEach(b => {
    if (b.commitStatus === 'pending') b.commitStatus = 'committed';
    else if (b.commitStatus === 'committed') b.commitStatus = 'finalized';
  });

  blocks.unshift(newBlock);
  if (blocks.length > 50) blocks.pop(); // limit size
  if (transactions.length > 300) transactions.pop();

  // Create 1-3 new transactions in mempool
  const pendingCount = Math.floor(Math.random() * 3) + 1;
  for (let i = 0; i < pendingCount; i++) {
    const senderIdx = Math.floor(Math.random() * wallets.length);
    const receiverIdx = (senderIdx + 1) % wallets.length;
    const amount = (Math.random() * 45 + 0.5).toFixed(8);
    mempool.push({
      txid: genPQHash('0x_tx_pending'),
      status: 'pending',
      sender: wallets[senderIdx].address,
      receiver: wallets[receiverIdx].address,
      amountSpx: amount,
      amountNspx: (parseFloat(amount) * 100000000).toFixed(0),
      nonce: wallets[senderIdx].nonce++,
      timestamp: now,
      blockHeight: -1,
      gasLimit: 85000,
      gasPrice: 15,
      gasFeeSpx: '0.00127500',
      chainId: 'sphinx-post-quantum-1',
      isSystemTx: false,
      signature: 'pq_sig_' + genHex(128),
      publicKey: 'pq_pk_' + genHex(64),
      merkleRoot: 'mr_' + genHex(32),
      hasFullAuth: true,
      signatureScheme: 'SPHINCS+-128s',
      returnData: Math.random() > 0.6 ? 'OP_RETURN: Encrypted Quantum Vault Seed' : undefined
    });
  }

  // Update stats
  stats.tipHeight = nextHeight;
  stats.mempoolSize = mempool.length;
  stats.mempoolBytes = mempool.length * 480;
  stats.currentTps = 2 + Math.random() * 5;
  stats.averageTps = (stats.averageTps * 99 + stats.currentTps) / 100;
  if (stats.currentTps > stats.peakTps) stats.peakTps = stats.currentTps;

  return { newBlock, addedTxs: blockTxs };
}

// Search utility
export function searchBlockchain(query: string) {
  const q = query.trim().toLowerCase();
  if (!q) return { matches: [] };

  const matches: Array<{ type: 'block' | 'transaction' | 'address'; id: string; name: string; extra?: string }> = [];

  // Check block height
  const heightNum = parseInt(q);
  if (!isNaN(heightNum)) {
    const block = blocks.find(b => b.height === heightNum);
    if (block) {
      return { redirect: `/block/${heightNum}` };
    }
  }

  // Check block hash
  const blockByHash = blocks.find(b => b.hash.toLowerCase() === q);
  if (blockByHash) {
    return { redirect: `/block/${blockByHash.height}` };
  }

  // Check txid
  const tx = transactions.find(t => t.txid.toLowerCase() === q) || mempool.find(t => t.txid.toLowerCase() === q);
  if (tx) {
    return { redirect: `/tx/${tx.txid}` };
  }

  // Check address
  const wallet = wallets.find(w => w.address.toLowerCase() === q);
  if (wallet) {
    return { redirect: `/address/${wallet.address}` };
  }

  // Partial match searches
  blocks.forEach(b => {
    if (b.hash.toLowerCase().includes(q)) {
      matches.push({ type: 'block', id: b.height.toString(), name: `Block #${b.height}`, extra: b.hash });
    }
  });

  transactions.forEach(t => {
    if (t.txid.toLowerCase().includes(q) || t.sender.toLowerCase().includes(q) || t.receiver.toLowerCase().includes(q)) {
      matches.push({ type: 'transaction', id: t.txid, name: `Transaction ${t.txid.substring(0, 10)}...`, extra: `${t.amountSpx} SPX` });
    }
  });

  mempool.forEach(t => {
    if (t.txid.toLowerCase().includes(q)) {
      matches.push({ type: 'transaction', id: t.txid, name: `Pending Tx ${t.txid.substring(0, 10)}...`, extra: `${t.amountSpx} SPX (Mempool)` });
    }
  });

  wallets.forEach(w => {
    if (w.address.toLowerCase().includes(q)) {
      matches.push({ type: 'address', id: w.address, name: `${w.addressType.split(' ')[0]} Address`, extra: w.address });
    }
  });

  return { matches };
}

// Generate SPHINCS+ keypair right on client
export function simulateSphincsKeyPair() {
  const seed = genHex(32);
  const secretKey = 'pq_sk_sphincsplus_' + genHex(128);
  const publicKey = 'pq_pk_sphincsplus_' + genHex(64);
  const address = 'spif1_sphincsplus_' + genHex(32);
  
  // Calculate relative sizes compared to classical ECDSA
  // Classical ECDSA: pk ~ 64 bytes, sk ~ 32 bytes, sig ~ 64 bytes
  // SPHINCS+-128f: pk ~ 32 bytes, sk ~ 64 bytes, sig ~ 17KB (very large!)
  return {
    seed,
    secretKey,
    publicKey,
    address,
    keySizeSec: '64 Bytes',
    keySizePub: '32 Bytes',
    signatureSize: '17,088 Bytes (17.08 KB)',
    classicalSigSize: '64 Bytes',
    safetyRating: 'Quantum-Safe (128-bit Post-Quantum security strength)'
  };
}
