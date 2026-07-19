/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect } from 'react';
import { 
  ShieldAlert, Cpu, HardDrive, Database, 
  Users, Activity, Key, Globe, Radio, Play, Pause, RefreshCw 
} from 'lucide-react';
import { Block, Transaction, NetworkStats, Wallet } from '../types';
import { formatHash } from '../utils/formatters';

interface DashboardProps {
  stats: NetworkStats;
  blocks: Block[];
  transactions: Transaction[];
  mempool: Transaction[];
  wallets: Wallet[];
  autoMineActive: boolean;
  onToggleAutoMine: () => void;
  onManualMine: () => void;
  onSearch: (query: string) => void;
  onSelectBlock: (height: number) => void;
  onSelectTx: (txid: string) => void;
  onSelectAddress: (address: string) => void;
}

export default function ExplorerDashboard({
  stats,
  blocks,
  transactions,
  mempool,
  wallets,
  autoMineActive,
  onToggleAutoMine,
  onManualMine,
  onSearch,
  onSelectBlock,
  onSelectTx,
  onSelectAddress
}: DashboardProps) {
  const [mempoolAnimationOffset, setMempoolAnimationOffset] = useState(0);

  // Animate mempool bubbles subtly
  useEffect(() => {
    const interval = setInterval(() => {
      setMempoolAnimationOffset(prev => (prev + 0.05) % (Math.PI * 2));
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const getSignatureBadge = (scheme: string) => {
    if (scheme.startsWith('SPHINCS+')) {
      return (
        <span className="px-2 py-0.5 bg-brand-cyan/15 border border-brand-cyan/20 text-brand-cyan text-[11px] font-mono rounded font-semibold shadow-[0_0_8px_rgba(0,240,255,0.05)]">
          {scheme}
        </span>
      );
    }
    switch (scheme) {
      case 'XMSS':
        return (
          <span className="px-2 py-0.5 bg-brand-gold/15 border border-brand-gold/20 text-brand-gold text-[11px] font-mono rounded font-semibold">
            XMSS
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 bg-brand-red/15 border border-brand-red/20 text-brand-red text-[11px] font-mono rounded font-semibold animate-pulse">
            ECDSA (Vuln)
          </span>
        );
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      
      {/* 1. Live Engine Controls */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-slate-900/50 border border-white/5 p-4 rounded-2xl backdrop-blur-md">
        
        {/* Status Indicator Info */}
        <div className="flex items-center gap-2.5 px-3 py-1.5 bg-slate-950/50 border border-white/5 rounded-xl text-xs font-mono text-slate-400">
          <Database className="w-4 h-4 text-brand-cyan" />
          <span>LEDGER ENGINE SIMULATOR STATUS</span>
        </div>

        {/* Engine Controls */}
        <div className="flex gap-2.5 items-center w-full md:w-auto justify-end">
          <div className="flex items-center gap-1.5 bg-slate-950 border border-white/10 px-3 py-1.5 rounded-xl">
            <span className={`inline-block w-2.5 h-2.5 rounded-full ${autoMineActive ? 'bg-brand-green animate-pulse' : 'bg-slate-600'}`} />
            <span className="text-[11px] text-slate-400 uppercase tracking-widest font-mono">
              {autoMineActive ? 'Mining Active' : 'Mining Paused'}
            </span>
          </div>

          <button
            onClick={onToggleAutoMine}
            className={`p-2.5 rounded-xl border transition duration-200 cursor-pointer ${
              autoMineActive 
                ? 'bg-slate-950 text-brand-cyan hover:bg-slate-900/50 border-brand-cyan/20' 
                : 'bg-brand-cyan/10 text-brand-cyan border-brand-cyan/30 hover:bg-brand-cyan/20'
            }`}
            title={autoMineActive ? "Pause Automatic Block Mining" : "Start Automatic Block Mining"}
          >
            {autoMineActive ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
          </button>

          <button
            onClick={onManualMine}
            className="flex items-center gap-1.5 px-4 py-2.5 bg-brand-purple/10 border border-brand-purple/30 hover:bg-brand-purple/20 text-brand-purple font-semibold rounded-xl text-xs transition duration-200 cursor-pointer"
            title="Force mine a new block now"
          >
            <RefreshCw className="w-3.5 h-3.5 animate-spin-slow" />
            Mine Block
          </button>
        </div>
      </div>

      {/* 2. Quantum Network Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Block Height */}
        <div className="bg-slate-900/40 border border-white/5 hover:border-brand-cyan/15 rounded-2xl p-5 backdrop-blur-md transition-all duration-300 relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
            <Database className="w-16 h-16 text-brand-cyan" />
          </div>
          <div className="text-[10px] text-slate-500 uppercase tracking-widest font-mono font-semibold mb-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-brand-cyan shadow-[0_0_8px_#00f0ff]" />
            Block Height
          </div>
          <div className="text-3xl font-bold text-white font-mono leading-none tracking-tight mb-2">
            #{stats.tipHeight.toLocaleString()}
          </div>
          <p className="text-xs text-slate-400 font-mono truncate">
            Finality: {stats.syncMode.split(' ')[0]}
          </p>
        </div>

        {/* Card 2: TPS */}
        <div className="bg-slate-900/40 border border-white/5 hover:border-brand-purple/15 rounded-2xl p-5 backdrop-blur-md transition-all duration-300 relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
            <Activity className="w-16 h-16 text-brand-purple" />
          </div>
          <div className="text-[10px] text-slate-500 uppercase tracking-widest font-mono font-semibold mb-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-brand-purple" />
            Throughput (TPS)
          </div>
          <div className="text-3xl font-bold text-white font-mono leading-none tracking-tight mb-2">
            {stats.currentTps.toFixed(2)}
          </div>
          <p className="text-xs text-slate-400 font-mono">
            Avg {stats.averageTps.toFixed(2)} / Peak {stats.peakTps.toFixed(1)}
          </p>
        </div>

        {/* Card 3: Quantum Safety */}
        <div className="bg-slate-900/40 border border-white/5 hover:border-brand-green/15 rounded-2xl p-5 backdrop-blur-md transition-all duration-300 relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
            <Key className="w-16 h-16 text-brand-green" />
          </div>
          <div className="text-[10px] text-slate-500 uppercase tracking-widest font-mono font-semibold mb-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-brand-green" />
            Shielded Accounts
          </div>
          <div className="text-3xl font-bold text-white font-mono leading-none tracking-tight mb-2">
            {((stats.sphincsAddresses / stats.totalAccounts) * 100).toFixed(0)}%
          </div>
          <p className="text-xs text-slate-400 font-mono">
            {stats.sphincsAddresses} of {stats.totalAccounts} accounts safe
          </p>
        </div>

        {/* Card 4: Global Stake */}
        <div className="bg-slate-900/40 border border-white/5 hover:border-brand-gold/15 rounded-2xl p-5 backdrop-blur-md transition-all duration-300 relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
            <ShieldAlert className="w-16 h-16 text-brand-gold" />
          </div>
          <div className="text-[10px] text-slate-500 uppercase tracking-widest font-mono font-semibold mb-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-brand-gold animate-pulse" />
            Active Validators
          </div>
          <div className="text-3xl font-bold text-white font-mono leading-none tracking-tight mb-2">
            {stats.activeValidators}
            <span className="text-xs text-slate-500 font-normal ml-1">/ {stats.totalValidators}</span>
          </div>
          <p className="text-xs text-slate-400 font-mono truncate">
            Stake: {parseFloat(stats.totalStakeSpx).toLocaleString()} SPX
          </p>
        </div>
      </div>

      {/* 3. Splitted View: Blocks/Txs and the Mempool Live Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left: Latest Blocks and Transactions */}
        <div className="lg:col-span-8 space-y-8">
          
          {/* Blocks Section */}
          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <span className="w-1.5 h-4 bg-brand-cyan rounded-full" />
                Latest Blocks
              </h2>
              <span className="text-xs text-slate-500 font-mono">Live Mine Stream</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead>
                  <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                    <th className="py-3 px-2">Height</th>
                    <th className="py-3 px-2">Hash</th>
                    <th className="py-3 px-2">TXs</th>
                    <th className="py-3 px-2">Proposer Node</th>
                    <th className="py-3 px-2 text-right">Protection</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {blocks.slice(0, 5).map((block) => (
                    <tr 
                      key={block.height}
                      onClick={() => onSelectBlock(block.height)}
                      className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer"
                    >
                      <td className="py-3 px-2 font-mono font-bold text-brand-cyan">
                        #{block.height}
                      </td>
                      <td className="py-3 px-2 font-mono text-xs text-slate-400">
                        {formatHash(block.hash, 10)}
                      </td>
                      <td className="py-3 px-2 font-mono text-xs">
                        {block.txCount} txs
                      </td>
                      <td className="py-3 px-2 font-mono text-xs text-slate-500 hover:text-brand-purple">
                        {formatHash(block.proposer, 6)}
                      </td>
                      <td className="py-3 px-2 text-right">
                        {getSignatureBadge(block.signatureScheme)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Active Address Section */}
          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <span className="w-1.5 h-4 bg-brand-cyan rounded-full" />
                Active Address
              </h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead>
                  <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                    <th className="py-3 px-2">Address</th>
                    <th className="py-3 px-2 text-right">Integrity Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {[...wallets]
                    .sort((a, b) => b.nonce - a.nonce || parseFloat(b.balanceSpx) - parseFloat(a.balanceSpx))
                    .slice(0, 6)
                    .map((wallet) => {
                      return (
                        <tr 
                          key={wallet.address}
                          onClick={() => onSelectAddress(wallet.address)}
                          className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer"
                        >
                          <td className="py-3.5 px-2 font-mono text-xs text-brand-cyan font-semibold truncate max-w-[150px] md:max-w-[200px]" title={wallet.address}>
                            {wallet.address}
                          </td>
                          <td className="py-3.5 px-2 text-right">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-brand-green/10 text-brand-green border border-brand-green/20 shadow-[0_0_8px_rgba(0,240,255,0.1)]">
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

        </div>

        {/* Right: Live Activity Mempool Visualizer (Website Exclusive Concept) */}
        <div className="lg:col-span-4 flex flex-col gap-6">
          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md flex-1 flex flex-col">
            <div className="mb-4">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <span className="w-1.5 h-4 bg-brand-gold rounded-full" />
                Mempool Live Activity
              </h2>
              <p className="text-xs text-slate-500 font-mono mt-1">Pending transactions floating in state space</p>
            </div>

            {/* Simulated Mempool Activity Area */}
            <div className="relative border border-white/5 bg-slate-950/80 rounded-2xl h-80 overflow-hidden flex-1 flex flex-col items-center justify-center">
              
              {/* Particle flow lines background in Card */}
              <div className="absolute inset-0 opacity-20 pointer-events-none">
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-48 h-48 rounded-full border border-dashed border-brand-gold animate-spin-slow" />
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 rounded-full border border-dashed border-brand-cyan/40 animate-pulse" />
              </div>

              {/* Transactions floating bubbles */}
              {mempool.length === 0 ? (
                <div className="text-center p-4 z-10 text-slate-600 space-y-2">
                  <Radio className="w-8 h-8 text-slate-700 mx-auto animate-pulse" />
                  <p className="text-xs font-mono font-medium">Mempool Cleared — Miner Synchronized</p>
                </div>
              ) : (
                <div className="absolute inset-0 z-10 p-4">
                  {mempool.map((tx, idx) => {
                    // Calculate floating sinusoidal physics values based on index and animated offset
                    const phase = idx * (Math.PI / 3) + mempoolAnimationOffset;
                    const xPercent = 20 + ((idx * 35) % 60);
                    const yPercent = 25 + ((idx * 27 + Math.sin(phase) * 12) % 55);
                    const sizePx = 45 + (parseFloat(tx.amountSpx) % 20); // bubble size relates to tx amount

                    return (
                      <button
                        key={tx.txid}
                        onClick={() => onSelectTx(tx.txid)}
                        className="absolute -translate-x-1/2 -translate-y-1/2 flex flex-col items-center justify-center rounded-full border cursor-pointer transition-all duration-300 hover:scale-115 hover:z-20 text-[9px] group"
                        style={{
                          left: `${xPercent}%`,
                          top: `${yPercent}%`,
                          width: `${sizePx}px`,
                          height: `${sizePx}px`,
                          background: tx.signatureScheme.includes('SPHINCS+') 
                            ? 'rgba(0, 240, 255, 0.08)' 
                            : tx.signatureScheme.includes('XMSS')
                            ? 'rgba(255, 170, 51, 0.08)'
                            : 'rgba(255, 51, 102, 0.08)',
                          borderColor: tx.signatureScheme.includes('SPHINCS+') 
                            ? 'rgba(0, 240, 255, 0.25)' 
                            : tx.signatureScheme.includes('XMSS')
                            ? 'rgba(255, 170, 51, 0.25)'
                            : 'rgba(255, 51, 102, 0.25)',
                          boxShadow: tx.signatureScheme.includes('SPHINCS+')
                            ? '0 0 15px rgba(0,240,255,0.05)'
                            : '0 0 15px rgba(255,170,51,0.05)'
                        }}
                      >
                        <span className="font-mono text-slate-400 text-[8px] tracking-tight group-hover:text-white">
                          {formatHash(tx.txid, 3)}
                        </span>
                        <span className="font-bold text-white leading-none mt-0.5">
                          {parseFloat(tx.amountSpx).toFixed(0)} SPX
                        </span>
                        
                        {/* Interactive tooltip */}
                        <div className="absolute bottom-full mb-2 hidden group-hover:flex flex-col bg-slate-900 border border-white/10 rounded-lg p-2.5 w-40 text-left pointer-events-none text-[10px] space-y-1 font-mono shadow-2xl z-30 leading-snug animate-fadeIn">
                          <div className="text-white font-bold text-xs border-b border-white/5 pb-1 mb-1">Pending Tx</div>
                          <div><span className="text-slate-500">Val:</span> <span className="text-white">{parseFloat(tx.amountSpx).toFixed(2)} SPX</span></div>
                          <div className="truncate"><span className="text-slate-500">From:</span> <span className="text-slate-300">{tx.sender}</span></div>
                          <div className="truncate"><span className="text-slate-500">Sig:</span> <span className="text-brand-cyan font-bold">{tx.signatureScheme}</span></div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            <div className="mt-4 flex justify-between text-[11px] text-slate-500 font-mono border-t border-white/5 pt-4">
              <div>Total Pending: {stats.mempoolSize}</div>
              <div>Buffer: {stats.mempoolBytes.toLocaleString()} Bytes</div>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
