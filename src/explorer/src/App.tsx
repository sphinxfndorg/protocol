/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, FormEvent } from 'react';
import { 
  Database, Users, Activity, Radio, Key, Globe, 
  Copy, Check, Clock, Search, Shield
} from 'lucide-react';
import { Block, Transaction, Validator, Wallet, NetworkStats } from './types';
import { formatHash, formatSPX } from './utils/formatters';

// API service layer
import * as api from './api/explorerApi';

// Component imports
import QuantumGrid from './components/QuantumGrid';
import Hero from './components/Hero';
import ExplorerDashboard from './components/ExplorerDashboard';
import BlockDetail from './components/BlockDetail';
import TxDetail from './components/TxDetail';
import AddressDetail from './components/AddressDetail';
import ValidatorMap from './components/ValidatorMap';

export default function App() {
  // Global blockchain state
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [mempool, setMempool] = useState<Transaction[]>([]);
  const [validators, setValidators] = useState<Validator[]>([]);
  const [wallets, setWallets] = useState<Wallet[]>([]);

  // Loading state
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Navigation and detail state
  const [activeTab, setActiveTab] = useState<'dashboard' | 'blocks' | 'validators' | 'wallets' | 'mempool'>('dashboard');
  const [selectedBlockHeight, setSelectedBlockHeight] = useState<number | null>(null);
  const [selectedTxId, setSelectedTxId] = useState<string | null>(null);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);

  // Search input in header
  const [headerSearch, setHeaderSearch] = useState('');

  // Digital clock
  const [footerTime, setFooterTime] = useState(new Date().toUTCString());

  // Periodic refresh interval (ms)
  const REFRESH_INTERVAL = 15000; // 15 seconds

  // Helper to fetch all initial data from the backend
  const fetchAllData = async () => {
    try {
      // Fetch block transactions by getting the block detail from each block
      const blocksData = await api.fetchBlocks(1, 25);

      // Fetch mempool, validators, wallets, and stats in parallel
      const [statsData, mempoolData, validatorsData, walletsData] = await Promise.all([
        api.fetchStats(),
        api.fetchMempool(),
        api.fetchValidators(),
        api.fetchWallets(50),
      ]);

      // Collect all transactions: start with mempool txs, then add block txs
      const allTxs: Transaction[] = [...mempoolData];

      // For richer data, fetch the first 5 recent blocks with full detail (includes txs)
      const recentBlocks = blocksData.slice(0, 5);
      for (const block of recentBlocks) {
        // fetchBlockByHeight for the backend's /api/v1/explorer/block/:height
        // which includes the full transaction list in the response
        const blockDetail = await fetch(`/api/v1/explorer/block/${block.height}`)
          .then(r => r.json())
          .catch(() => null);
        if (blockDetail && blockDetail.transactions) {
          blockDetail.transactions.forEach((tx: any) => {
            allTxs.push({
              txid: tx.txid || '',
              status: 'success' as const,
              sender: tx.sender || '',
              receiver: tx.receiver || '',
              amountSpx: tx.amount_spx || '0',
              amountNspx: tx.amount_nspx || '0',
              nonce: tx.nonce || 0,
              timestamp: tx.timestamp || blockDetail.header?.timestamp || 0,
              blockHeight: block.height,
              gasLimit: Number(blockDetail.header?.gas_limit) || 0,
              gasPrice: 0,
              gasFeeSpx: tx.amount_spx || '0',
              chainId: 'sphinx-post-quantum-1',
              isSystemTx: tx.is_system_tx || false,
              signature: tx.signature || '',
              publicKey: tx.public_key || '',
              merkleRoot: tx.merkle_root || '',
              hasFullAuth: tx.has_full_auth || false,
              signatureScheme: 'SPHINCS+-128s' as const,
            });
          });
        }
      }

      setStats(statsData);
      setBlocks(blocksData);
      setMempool(mempoolData);
      setValidators(validatorsData);
      setWallets(walletsData);
      setTransactions(allTxs);
      setIsLoading(false);
      setError(null);
    } catch (err: any) {
      console.error('Failed to fetch blockchain data:', err);
      setError(err.message || 'Failed to connect to blockchain');
      setIsLoading(false);
    }
  };

  // Initialize and periodically refresh data
  useEffect(() => {
    fetchAllData();

    const interval = setInterval(() => {
      fetchAllData();
    }, REFRESH_INTERVAL);

    return () => clearInterval(interval);
  }, []);

  // Tick clock
  useEffect(() => {
    const interval = setInterval(() => {
      setFooterTime(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Perform search query resolution via backend
  const handleSearch = async (query: string) => {
    try {
      const result = await api.search(query);
      if (result.redirect) {
        const route = result.redirect;
        if (route.startsWith('/block/')) {
          const height = parseInt(route.replace('/block/', ''));
          setSelectedBlockHeight(height);
          setSelectedTxId(null);
          setSelectedAddress(null);
        } else if (route.startsWith('/tx/')) {
          const txid = route.replace('/tx/', '');
          setSelectedTxId(txid);
          setSelectedBlockHeight(null);
          setSelectedAddress(null);
        } else if (route.startsWith('/address/')) {
          const addr = route.replace('/address/', '');
          setSelectedAddress(addr);
          setSelectedBlockHeight(null);
          setSelectedTxId(null);
        }
      } else {
        alert(`Search item "${query}" not found in current ledger state. Try a block number, transaction hash, or address.`);
      }
    } catch (err) {
      alert(`Search failed: ${err}`);
    }
  };

  const handleHeaderSearchSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (headerSearch.trim()) {
      handleSearch(headerSearch);
      setHeaderSearch('');
    }
  };

  // Wallet Migration callback (UI-only; actual migration would need a real backend call)
  const handleMigrateWallet = async (legacyAddress: string, newPqAddress: string, balance: string) => {
    // Update wallets array locally
    setWallets(prev => {
      return prev.map(w => {
        if (w.address === legacyAddress) {
          return {
            ...w,
            address: newPqAddress,
            addressType: 'SPHINCS+ (Stateless Hash)',
            balanceSpx: balance
          };
        }
        return w;
      });
    });

    // Remap transactions associated with legacy Address
    setTransactions(prev => {
      return prev.map(t => {
        const tCopy = { ...t };
        if (tCopy.sender === legacyAddress) tCopy.sender = newPqAddress;
        if (tCopy.receiver === legacyAddress) tCopy.receiver = newPqAddress;
        return tCopy;
      });
    });

    // Update selected address view to the newly generated one
    setTimeout(() => {
      setSelectedAddress(newPqAddress);
    }, 100);
  };

  const clearDetailViews = () => {
    setSelectedBlockHeight(null);
    setSelectedTxId(null);
    setSelectedAddress(null);
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#060714] flex flex-col items-center justify-center text-slate-400">
        <Activity className="w-8 h-8 text-brand-cyan animate-pulse mb-3" />
        <span className="font-mono text-xs">Synchronizing Sphinx Quantum Mesh...</span>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen bg-[#060714] flex flex-col items-center justify-center text-slate-400">
        <Shield className="w-8 h-8 text-brand-red animate-pulse mb-3" />
        <span className="font-mono text-xs text-brand-red mb-4">Connection Error</span>
        <p className="font-mono text-xs text-slate-500 mb-4 max-w-md text-center">{error}</p>
        <button
          onClick={fetchAllData}
          className="px-4 py-2 bg-brand-cyan/10 border border-brand-cyan/30 text-brand-cyan rounded-xl text-xs font-mono hover:bg-brand-cyan/20 transition cursor-pointer"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen text-slate-100 flex flex-col justify-between relative overflow-hidden">
      
      {/* Dynamic Grid Particles Overlay */}
      <QuantumGrid />

      {/* 1. Header / Navigation bar */}
      <header className="sticky top-0 z-40 bg-brand-bg/90 border-b border-white/5 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-4 flex items-center justify-center">
          
          {/* Main Menu Links */}
          <nav className="flex items-center gap-1 overflow-x-auto max-w-full pb-1 md:pb-0">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: Activity },
              { id: 'blocks', label: 'Blocks', icon: Database },
              { id: 'validators', label: 'Validators', icon: Globe },
              { id: 'wallets', label: 'Rich List', icon: Users },
              { id: 'mempool', label: 'Mempool', icon: Radio },
            ].map((tab) => {
              const Icon = tab.icon;
              const isSelected = activeTab === tab.id && !selectedBlockHeight && !selectedTxId && !selectedAddress;
              return (
                <button
                  key={tab.id}
                  onClick={() => {
                    clearDetailViews();
                    setActiveTab(tab.id as any);
                  }}
                  className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold tracking-wide transition duration-150 cursor-pointer ${
                    isSelected
                      ? 'bg-brand-cyan/15 text-brand-cyan border border-brand-cyan/20 shadow-[0_0_15px_rgba(0,240,255,0.06)]'
                      : 'text-slate-400 hover:text-white hover:bg-white/[0.02]'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              );
            })}
          </nav>

        </div>
      </header>

      {/* 2. Main content container */}
      <main className="flex-1 max-w-7xl mx-auto px-4 md:px-6 py-8 w-full z-10">
        
        {/* Render hero if on dashboard main tab with no subview selected */}
        {activeTab === 'dashboard' && !selectedBlockHeight && !selectedTxId && !selectedAddress && (
          <Hero onSearch={handleSearch} />
        )}

        <div id="explorer-core">
          
          {/* A. Subviews rendering (Blocks / Txs / Addresses details) */}
          {selectedBlockHeight !== null && (
            <BlockDetail
              block={blocks.find(b => b.height === selectedBlockHeight) || blocks[0]}
              blockTxs={transactions.filter(t => t.blockHeight === selectedBlockHeight)}
              onBack={clearDetailViews}
              onSelectTx={setSelectedTxId}
              onSelectAddress={setSelectedAddress}
            />
          )}

          {selectedTxId !== null && (
            <TxDetail
              tx={transactions.find(t => t.txid === selectedTxId) || mempool.find(t => t.txid === selectedTxId) || transactions[0]}
              onBack={clearDetailViews}
              onSelectBlock={setSelectedBlockHeight}
              onSelectAddress={setSelectedAddress}
            />
          )}

          {selectedAddress !== null && (
            <AddressDetail
              wallet={wallets.find(w => w.address === selectedAddress) || {
                rank: 999,
                address: selectedAddress,
                balanceSpx: '0.00000000',
                nonce: 0,
                isActive: true,
                addressType: 'SPHINCS+ (Stateless Hash)'
              }}
              addressTxs={transactions.filter(t => t.sender === selectedAddress || t.receiver === selectedAddress)}
              onBack={clearDetailViews}
              onSelectTx={setSelectedTxId}
              onMigrateWallet={handleMigrateWallet}
            />
          )}

          {/* B. Base Tab rendering */}
          {!selectedBlockHeight && !selectedTxId && !selectedAddress && (
            <>
              {activeTab === 'dashboard' && stats && (
                <ExplorerDashboard
                  stats={stats}
                  blocks={blocks}
                  transactions={transactions}
                  mempool={mempool}
                  wallets={wallets}
                  autoMineActive={false}
                  onToggleAutoMine={() => {}}
                  onManualMine={() => {}}
                  onSearch={handleSearch}
                  onSelectBlock={setSelectedBlockHeight}
                  onSelectTx={setSelectedTxId}
                  onSelectAddress={setSelectedAddress}
                />
              )}

              {activeTab === 'blocks' && (
                <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                      <Database className="w-5 h-5 text-brand-cyan" />
                      All Mined Block States ({blocks.length})
                    </h2>
                    <span className="text-xs text-slate-500 font-mono">Lattice Consensus</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {blocks.map((block) => (
                      <button
                        key={block.height}
                        onClick={() => setSelectedBlockHeight(block.height)}
                        className="text-left bg-slate-950/60 border border-white/5 hover:border-brand-cyan/30 rounded-xl p-4 transition-all duration-300 hover:shadow-[0_0_15px_rgba(0,240,255,0.05)] cursor-pointer group"
                      >
                        <div className="flex justify-between items-center mb-2">
                          <span className="text-sm font-bold text-brand-cyan group-hover:underline">
                            Block #{block.height}
                          </span>
                          <span className="text-[10px] uppercase font-mono bg-brand-cyan/10 border border-brand-cyan/20 px-2 py-0.5 rounded text-brand-cyan">
                            {block.signatureScheme}
                          </span>
                        </div>
                        <div className="text-xs font-mono text-slate-500 truncate mb-3">
                          {block.hash}
                        </div>
                        <div className="flex justify-between items-center text-[11px] text-slate-400 font-mono border-t border-white/5 pt-3">
                          <span>{block.txCount} txs packed</span>
                          <span>Gas: {block.gasLimit > 0 ? ((block.gasUsed / block.gasLimit) * 100).toFixed(0) : 0}%</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === 'validators' && (
                <ValidatorMap 
                  validators={validators} 
                  onSelectAddress={setSelectedAddress} 
                />
              )}

              {activeTab === 'wallets' && (
                <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                      <Users className="w-5 h-5 text-brand-cyan" />
                      Ledger Rich List (Top Accounts)
                    </h2>
                    <span className="text-xs text-slate-500 font-mono">Distribution metrics</span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm text-slate-300">
                      <thead>
                        <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                          <th className="py-3 px-2">Rank</th>
                          <th className="py-3 px-2">Address Hash</th>
                          <th className="py-3 px-2">Armor Standard</th>
                          <th className="py-3 px-2">Confirmed Balance</th>
                          <th className="py-3 px-2 text-right">Integrity Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {wallets.map((wallet) => {
                          return (
                            <tr 
                              key={wallet.address}
                              onClick={() => setSelectedAddress(wallet.address)}
                              className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer text-xs"
                            >
                              <td className="py-3.5 px-2 font-mono text-slate-500">
                                #{wallet.rank}
                              </td>
                              <td className="py-3.5 px-2 font-mono text-brand-cyan font-semibold">
                                {wallet.address}
                              </td>
                              <td className="py-3.5 px-2 font-mono text-slate-400">
                                {wallet.addressType}
                              </td>
                              <td className="py-3.5 px-2 font-mono font-bold text-white">
                                {formatSPX(wallet.balanceSpx)}
                              </td>
                              <td className="py-3.5 px-2 text-right">
                                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-brand-green/10 text-brand-green border border-brand-green/20">
                                  Armored (SPHINCS+-128s)
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {activeTab === 'mempool' && (
                <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                      <Radio className="w-5 h-5 text-brand-cyan animate-pulse" />
                      Pending Mempool State Workspace
                    </h2>
                    <span className="text-xs text-slate-500 font-mono">Queue Buffer size</span>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch mb-8">
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">Pending Txs</span>
                      <div className="text-2xl font-bold font-mono text-white mt-1">{mempool.length} txs</div>
                    </div>
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">Buffer Bytes</span>
                      <div className="text-2xl font-bold font-mono text-white mt-1">{(mempool.length * 480).toLocaleString()} Bytes</div>
                    </div>
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">Avg Gas Limit</span>
                      <div className="text-2xl font-bold font-mono text-white mt-1">85,000</div>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm text-slate-300">
                      <thead>
                        <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                          <th className="py-3 px-2">TXID</th>
                          <th className="py-3 px-2">Sender Address</th>
                          <th className="py-3 px-2">Recipient Address</th>
                          <th className="py-3 px-2">Amount</th>
                          <th className="py-3 px-2 text-right">Signature Protocol</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 text-xs">
                        {mempool.map((tx) => (
                          <tr 
                            key={tx.txid}
                            onClick={() => setSelectedTxId(tx.txid)}
                            className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer"
                          >
                            <td className="py-3.5 px-2 font-mono text-brand-purple font-semibold">
                              {tx.txid}
                            </td>
                            <td className="py-3.5 px-2 font-mono text-slate-400">
                              {formatHash(tx.sender, 12)}
                            </td>
                            <td className="py-3.5 px-2 font-mono text-slate-400">
                              {formatHash(tx.receiver, 12)}
                            </td>
                            <td className="py-3.5 px-2 font-mono text-white font-bold">
                              {parseFloat(tx.amountSpx).toFixed(4)} SPX
                            </td>
                            <td className="py-3.5 px-2 text-right text-brand-cyan font-mono font-bold">
                              {tx.signatureScheme}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}

        </div>
      </main>

      {/* 3. Footer */}
      <footer className="bg-[#050611] border-t border-white/5 py-8 mt-12 z-10 text-slate-500 text-xs">
        <div className="max-w-7xl mx-auto px-4 md:px-6 flex flex-col md:flex-row gap-6 justify-between items-center">
          <div className="space-y-1.5 text-center md:text-left">
            <p className="max-w-md leading-relaxed text-[11px]">
              Sphinx is a next-generation decentralized layer specializing in stateless hash-based (SPHINCS+) cryptography to secure the web and states against Y2Q quantum threats.
            </p>
          </div>

          <div className="flex flex-col items-center md:items-end gap-2 text-[11px] font-mono">
            <div className="flex items-center gap-1.5 text-slate-300">
              <Clock className="w-3.5 h-3.5 text-brand-cyan animate-pulse" />
              <span>{footerTime}</span>
            </div>
            <div>
              © 2026 Sphinx Network. All rights reserved.
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}