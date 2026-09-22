/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, FormEvent } from 'react';
import { 
  Database, Users, Activity, Radio, Globe, 
  Clock, Shield, CheckCircle, Sparkles
} from 'lucide-react';
import { Block, Transaction, Validator, Wallet, NetworkStats, HolderGrowthPoint } from './types';
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
import BlockChainIcon from './components/BlockChainIcon';

export default function App() {
  // Global blockchain state
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  // Full detail payloads (header + body + attestations) keyed by height
  const [blockDetails, setBlockDetails] = useState<Record<number, api.BlockDetailPayload>>({});
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [mempool, setMempool] = useState<Transaction[]>([]);
  // The FULL mempool picture: pool breakdown plus the rows that are not
  // mineable yet. `mempool` is only the validated pending set, which reads
  // empty both while a send is still being validated and after the node has
  // refused it — exactly the two states a user asking "where did my send go?"
  // needs told apart.
  const [mempoolView, setMempoolView] = useState<api.MempoolView | null>(null);
  const [validators, setValidators] = useState<Validator[]>([]);
  const [wallets, setWallets] = useState<Wallet[]>([]);
  const [holderGrowth, setHolderGrowth] = useState<HolderGrowthPoint[]>([]);

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

  // Block production & confirmation state
  const [autoMineActive, setAutoMineActive] = useState<boolean>(false);
  const [isMining, setIsMining] = useState<boolean>(false);
  // Surface both the provenance of the data being displayed and the reason a
  // mine request was refused, instead of failing silently in the console.
  const [simulatedData, setSimulatedData] = useState<boolean>(false);
  const [mineNotice, setMineNotice] = useState<string | null>(null);

  const handleToggleAutoMine = () => {
    setAutoMineActive(prev => !prev);
  };

  const handleManualMine = async () => {
    if (isMining) return;
    setIsMining(true);
    setMineNotice(null);
    try {
      const res = await api.mineBlock();
      if (res.simulated) {
        // A simulated block is NOT on any chain. Reflect it in the demo state
        // but tell the operator, rather than passing it off as a real block.
        setSimulatedData(true);
        setMineNotice('Backend unreachable — showing a SIMULATED block, not chain state.');
      }
      const { block, transactions: newTxs } = res;
      // Block Produced
      const formingBlock: Block = {
        ...block,
        commitStatus: 'pending',
      };
      setBlocks(prev => [formingBlock, ...prev.filter(b => b.height !== block.height)]);
      setStats(prev => prev ? {
        ...prev,
        tipHeight: block.height,
        mempoolSize: Math.max(0, prev.mempoolSize - newTxs.length)
      } : prev);
      setTransactions(prev => [...newTxs, ...prev]);

      // After 1000ms transition to Confirmed
      setTimeout(() => {
        setBlocks(prev => prev.map(b => b.height === block.height ? { ...b, commitStatus: 'committed' } : b));
      }, 1000);

      // Refresh real chain state so the next render reflects the committed tip.
      fetchAllData();
    } catch (err) {
      // The node answered and refused (e.g. 409 on a multi-validator cluster).
      // Show the node's reason rather than fabricating a block.
      const message = err instanceof Error ? err.message : String(err);
      setMineNotice(message);
      console.error('Failed to mine block:', err);
    } finally {
      setIsMining(false);
    }
  };

  // Auto-mining scheduler loop
  useEffect(() => {
    if (!autoMineActive) return;
    const interval = setInterval(() => {
      handleManualMine();
    }, 9000);
    return () => clearInterval(interval);
  }, [autoMineActive]);

  // Periodic refresh interval (ms)
  const REFRESH_INTERVAL = 15000; // 15 seconds

  // Helper to fetch all initial data from the backend
  const fetchAllData = async () => {
    try {
      // Fetch EVERY mined block (all pages) so "All Mined Block States"
      // renders the whole chain. A single page-1/limit-25 fetch only ever
      // delivered the newest 25 heights — with the tip at #60 the list
      // stopped at #37 and everything older was silently never requested.
      const blocksData = await api.fetchAllBlocks();

      // Fetch mempool (full view: pending + pool breakdown + in-flight +
      // rejected), validators, wallets, and stats in parallel
      const [statsData, mempoolData, validatorsData, walletsData, holderGrowthData] = await Promise.all([
        api.fetchStats(),
        api.fetchMempoolView(),
        api.fetchValidators(),
        api.fetchWallets(50),
        api.fetchHolderGrowth(30),
      ]);

      // Collect all transactions: start with mempool txs, then add block txs
      const allTxs: Transaction[] = [...mempoolData.pending];

      const recentBlocks = blocksData.slice(0, 5);
      const details: Record<number, api.BlockDetailPayload> = {};
      for (const block of recentBlocks) {
        const detail = await api.fetchBlockDetail(block.height);
        if (!detail) continue;
        details[block.height] = detail;
        detail.transactions.forEach((tx) => allTxs.push(tx));
      }

      setStats(statsData);
      setBlocks(blocksData);
      setBlockDetails(details);
      setMempool(mempoolData.pending);
      setMempoolView(mempoolData);
      setValidators(validatorsData);
      setWallets(walletsData);
      setHolderGrowth(holderGrowthData);
      setTransactions(allTxs);
      // Provenance check: the API layer falls back to a simulated chain when
      // the node is unreachable, and that must be visible, not silent.
      setSimulatedData(api.getDataSource() === 'mock');
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

  useEffect(() => {
    if (selectedBlockHeight === null) return;
    if (blockDetails[selectedBlockHeight]) return;

    let cancelled = false;
    (async () => {
      const detail = await api.fetchBlockDetail(selectedBlockHeight);
      if (cancelled || !detail) return;
      setBlockDetails(prev => ({ ...prev, [selectedBlockHeight]: detail }));
      setTransactions(prev => {
        const known = new Set(prev.map(t => t.txid));
        const additions = detail.transactions.filter(t => !known.has(t.txid));
        return additions.length > 0 ? [...prev, ...additions] : prev;
      });
    })();

    return () => {
      cancelled = true;
    };
  }, [selectedBlockHeight, blockDetails]);

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

  // Wallet Migration callback
  const handleMigrateWallet = async (legacyAddress: string, newPqAddress: string, balance: string) => {
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

    setTransactions(prev => {
      return prev.map(t => {
        const tCopy = { ...t };
        if (tCopy.sender === legacyAddress) tCopy.sender = newPqAddress;
        if (tCopy.receiver === legacyAddress) tCopy.receiver = newPqAddress;
        return tCopy;
      });
    });

    setTimeout(() => {
      setSelectedAddress(newPqAddress);
    }, 100);
  };

  const clearDetailViews = () => {
    setSelectedBlockHeight(null);
    setSelectedTxId(null);
    setSelectedAddress(null);
  };

  // Mempool pipeline breakdown for the mempool tab below. `mempool` holds only
  // the VALIDATED mineable set, so it reads empty both while a broadcast send
  // is still being validated and after the node refused it — the two states a
  // user asking "where did my send go?" needs told apart. These counts and the
  // two row lists are what let the view say WHICH happened instead of showing
  // a bare zero.
  const pool = mempoolView?.pool;
  const inFlightRows = mempoolView?.inFlight ?? [];
  const rejectedRows = mempoolView?.rejected ?? [];
  const inFlightCount = pool ? pool.broadcast + pool.validating : inFlightRows.length;
  const rejectedCount = pool ? pool.invalid : rejectedRows.length;
  const pendingCount = pool ? pool.pending : mempool.length;
  const bufferBytes = stats?.mempoolBytes ?? mempool.length * 480;
  const notMineable = inFlightRows.length + rejectedRows.length;

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
        <div className="max-w-7xl mx-auto px-4 md:px-6 py-4 flex items-center justify-between">
          
          {/* Logo / Brand with 3D Isometric Box-Shaped Block & Chain Icon */}
          <div 
            onClick={() => {
              clearDetailViews();
              setActiveTab('dashboard');
            }}
            className="flex items-center cursor-pointer group"
          >
            <div className="p-1 rounded-xl bg-slate-950/80 border border-brand-cyan/30 shadow-[0_0_12px_rgba(0,240,255,0.2)] group-hover:border-brand-cyan/60 transition-colors">
              <BlockChainIcon size={36} state="confirmed" animated={true} />
            </div>
          </div>

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

      {/* Data-provenance banner: the API layer falls back to a simulated chain
          when the node is unreachable. An explorer must never present invented
          blocks and balances as chain state, so this is rendered loudly. */}
      {(simulatedData || mineNotice) && (
        <div className="sticky top-[73px] z-30 w-full">
          {simulatedData && (
            <div className="bg-brand-gold/10 border-b border-brand-gold/20 px-4 md:px-6 py-2 flex items-center justify-center gap-2 text-[11px] font-mono uppercase tracking-wider text-brand-gold">
              <Shield className="w-3.5 h-3.5 animate-pulse" />
              Simulated data — Go backend unreachable on /api. Start a node to see real chain state.
            </div>
          )}
          {mineNotice && (
            <div className="bg-brand-purple/10 border-b border-brand-purple/20 px-4 md:px-6 py-2 flex items-center justify-center gap-2 text-[11px] font-mono text-brand-purple">
              <Sparkles className="w-3.5 h-3.5" />
              {mineNotice}
              <button
                onClick={() => setMineNotice(null)}
                className="ml-2 text-slate-500 hover:text-white transition cursor-pointer"
                aria-label="Dismiss notice"
              >
                ✕
              </button>
            </div>
          )}
        </div>
      )}

      {/* 2. Main content container */}
      <main className="flex-1 max-w-7xl mx-auto px-4 md:px-6 py-8 w-full z-10">
        
        {/* Render hero if on dashboard main tab with no subview selected */}
        {activeTab === 'dashboard' && !selectedBlockHeight && !selectedTxId && !selectedAddress && (
          <Hero onSearch={handleSearch} />
        )}

        <div id="explorer-core">
          
          {/* A. Subviews rendering (Blocks / Txs / Addresses details) */}
          {selectedBlockHeight !== null && (() => {
            const detail = blockDetails[selectedBlockHeight];
            const block = detail?.block
              || blocks.find(b => b.height === selectedBlockHeight)
              || blocks[0];
            if (!block) return null;
            const blockTxs = detail?.transactions
              ?? transactions.filter(t => t.blockHeight === selectedBlockHeight);
            return (
              <BlockDetail
                block={block}
                blockTxs={blockTxs}
                attestations={detail?.attestations ?? []}
                onBack={clearDetailViews}
                onSelectTx={setSelectedTxId}
                onSelectAddress={setSelectedAddress}
              />
            );
          })()}

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
                  mempoolView={mempoolView}
                  wallets={wallets}
                  holderGrowth={holderGrowth}
                  autoMineActive={autoMineActive}
                  onToggleAutoMine={handleToggleAutoMine}
                  onManualMine={handleManualMine}
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
                    {blocks.map((block) => {
                      const isConfirmed = block.commitStatus === 'finalized' || block.commitStatus === 'committed';
                      return (
                        <button
                          key={block.height}
                          onClick={() => setSelectedBlockHeight(block.height)}
                          className="text-left bg-slate-950/60 border border-white/5 hover:border-brand-cyan/30 rounded-xl p-4 transition-all duration-300 hover:shadow-[0_0_15px_rgba(0,240,255,0.05)] cursor-pointer group"
                        >
                          <div className="flex justify-between items-center mb-3">
                            <div className="flex items-center gap-2">
                              {/* 3D Isometric Block & Chain Icon */}
                              <BlockChainIcon
                                size={36}
                                height={block.height}
                                state={isConfirmed ? 'confirmed' : 'produced'}
                                animated={true}
                              />
                              <span className="text-sm font-bold text-brand-cyan group-hover:underline">
                                Block #{block.height}
                              </span>
                            </div>
                            <span className="text-[10px] uppercase font-mono bg-brand-cyan/10 border border-brand-cyan/20 px-2 py-0.5 rounded text-brand-cyan">
                              {block.signatureScheme}
                            </span>
                          </div>
                          <div className="text-xs font-mono text-slate-500 truncate mb-2">
                            {block.hash}
                          </div>
                          <div className="space-y-1 text-[10px] font-mono text-slate-500 mb-3">
                            <div className="flex justify-between gap-2">
                              <span className="text-slate-600">Parent</span>
                              <span className="text-slate-400 truncate">{formatHash(block.parentHash, 10)}</span>
                            </div>
                            <div className="flex justify-between gap-2">
                              <span className="text-slate-600">Tx Root</span>
                              <span className="text-slate-400 truncate">{formatHash(block.txsRoot, 10)}</span>
                            </div>
                            <div className="flex justify-between gap-2">
                              <span className="text-slate-600">Nonce</span>
                              <span className="text-slate-400">{block.nonce.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between gap-2">
                              <span className="text-slate-600">Time</span>
                              <span className="text-slate-400">
                                {block.timestampIso || new Date(block.timestamp * 1000).toISOString()}
                              </span>
                            </div>
                          </div>
                          <div className="flex justify-between items-center text-[11px] text-slate-400 font-mono border-t border-white/5 pt-3">
                            <span>{block.txCount} txs packed</span>
                            <span>Gas: {block.gasLimit > 0 ? ((block.gasUsed / block.gasLimit) * 100).toFixed(0) : 0}%</span>
                          </div>
                          <div className="flex justify-between items-center text-[11px] font-mono border-t border-white/5 pt-2 mt-2">
                            <span className="text-slate-600">Burned</span>
                            <span className={block.burnedThisBlockSpx && parseFloat(block.burnedThisBlockSpx) > 0 ? 'text-brand-red' : 'text-slate-600'}>
                              {block.burnedThisBlockSpx ? `${parseFloat(block.burnedThisBlockSpx).toFixed(6)} SPX` : '—'}
                            </span>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {activeTab === 'validators' && (
                <ValidatorMap 
                  validators={validators} 
                  onSelectAddress={setSelectedAddress} 
                  tipHeight={stats?.tipHeight}
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
                                {wallet.addressType && !wallet.addressType.includes('ECDSA') ? wallet.addressType : 'SPHINCS+ (Stateless Hash)'}
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

                  <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-stretch mb-8">
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">Pending Txs</span>
                      <div className="text-2xl font-bold font-mono text-white mt-1">{pendingCount} txs</div>
                      <span className="text-[10px] text-slate-600 font-mono">validated · mineable</span>
                    </div>
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">In Flight</span>
                      <div className={`text-2xl font-bold font-mono mt-1 ${inFlightCount ? 'text-amber-400' : 'text-white'}`}>{inFlightCount} txs</div>
                      <span className="text-[10px] text-slate-600 font-mono">awaiting validation</span>
                    </div>
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">Rejected</span>
                      <div className={`text-2xl font-bold font-mono mt-1 ${rejectedCount ? 'text-brand-red' : 'text-white'}`}>{rejectedCount} txs</div>
                      <span className="text-[10px] text-slate-600 font-mono">cannot confirm</span>
                    </div>
                    <div className="bg-slate-950/60 border border-white/5 p-4 rounded-xl">
                      <span className="text-[10px] text-slate-500 font-mono uppercase">Buffer Bytes</span>
                      <div className="text-2xl font-bold font-mono text-white mt-1">{bufferBytes.toLocaleString()} Bytes</div>
                      <span className="text-[10px] text-slate-600 font-mono">{pool ? `${pool.total} tracked` : 'estimated'}</span>
                    </div>
                  </div>

                  {/* A zero here used to be the whole story. Say what the zero
                      actually means before the (empty) pending table. */}
                  {pendingCount === 0 && notMineable > 0 && (
                    <div className="mb-4 rounded-xl border border-amber-500/30 bg-amber-950/30 p-3 text-xs font-mono text-amber-300">
                      0 mineable right now — {inFlightCount} accepted but still validating, {rejectedCount} rejected by the node. Both are listed below.
                    </div>
                  )}

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
                        {mempool.length === 0 && (
                          <tr>
                            <td colSpan={5} className="py-6 text-center font-mono text-slate-600">
                              No mineable transactions in the pool.
                            </td>
                          </tr>
                        )}
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

                  {/* Everything the pool holds that a block CANNOT take yet.
                      Without this a rejected send — the node refused its
                      nonce, say — was invisible here: the pending table stayed
                      empty and the view reported a bare "0 pending" right when
                      the reason for it was sitting in the pool. */}
                  {notMineable > 0 && (
                    <div className="mt-6 space-y-3">
                      <h3 className="text-xs font-semibold text-white uppercase tracking-widest font-mono">
                        Not Mineable Yet ({notMineable})
                      </h3>
                      {[...inFlightRows, ...rejectedRows].map((row) => {
                        const rejected = row.status === 'invalid';
                        const badge = rejected
                          ? 'border-brand-red/30 bg-brand-red/10 text-brand-red'
                          : 'border-amber-500/30 bg-amber-500/10 text-amber-400';
                        return (
                          <div
                            key={`${row.status}-${row.txid}`}
                            onClick={() => setSelectedTxId(row.txid)}
                            className="bg-slate-950 border border-white/5 rounded-xl p-3 cursor-pointer hover:bg-white/[0.02] active:bg-white/[0.04] transition"
                          >
                            <div className="flex items-center justify-between gap-3 flex-wrap">
                              <span className="text-[10px] font-mono text-brand-purple break-all">{row.txid}</span>
                              <span className={`text-[9px] font-mono uppercase tracking-wider border rounded px-1.5 py-0.5 shrink-0 ${badge}`}>
                                {row.status}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 mt-1">
                              from {formatHash(row.sender, 10)}{row.nonce !== undefined && row.nonce !== null ? ` · nonce ${row.nonce}` : ''}
                            </div>
                            {row.reason && (
                              <div className="text-[11px] font-mono text-brand-red mt-1 break-words">
                                ✗ {row.reason}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
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
