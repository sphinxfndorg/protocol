/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { 
  ShieldAlert, Database, Activity, Key, Radio, Play, Pause, RefreshCw 
} from 'lucide-react';
import { Block, Transaction, NetworkStats, Wallet, HolderGrowthPoint } from '../types';
import { MempoolView } from '../api/explorerApi';
import { formatHash } from '../utils/formatters';
import BlockChainIcon from './BlockChainIcon';
import MempoolChainView from './MempoolChainView';

interface DashboardProps {
  stats: NetworkStats;
  blocks: Block[];
  transactions: Transaction[];
  mempool: Transaction[];
  /**
   * Full mempool picture. `mempool` alone is the validated mineable set, so it
   * reads zero both while a broadcast send is still being validated and after
   * the node refused it — passing the breakdown through is what lets the
   * status chip say WHICH, instead of asserting "0 Pending TXs" over a pool
   * that is very much not empty.
   */
  mempoolView?: MempoolView | null;
  wallets: Wallet[];
  holderGrowth: HolderGrowthPoint[];
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
  mempoolView,
  wallets,
  holderGrowth,
  autoMineActive,
  onToggleAutoMine,
  onManualMine,
  onSearch,
  onSelectBlock,
  onSelectTx,
  onSelectAddress
}: DashboardProps) {
  const maxHolders = Math.max(1, ...holderGrowth.map(point => point.holders));
  const growthPath = holderGrowth.map((point, index) => {
    const x = holderGrowth.length <= 1 ? 0 : (index / (holderGrowth.length - 1)) * 100;
    const y = 100 - (point.holders / maxHolders) * 88 - 6;
    return `${index === 0 ? 'M' : 'L'} ${x} ${y}`;
  }).join(' ');

  // Mempool breakdown. Fall back to `mempool` when the node's payload predates
  // the pool summary, so an older API still renders a sane pending number.
  const pool = mempoolView?.pool;
  const pendingCount = pool ? pool.pending : mempool.length;
  const inFlightCount = pool ? pool.broadcast + pool.validating : (mempoolView?.inFlight.length ?? 0);
  const rejectedCount = pool ? pool.invalid : (mempoolView?.rejected.length ?? 0);

  return (
    <div className="space-y-8 animate-fadeIn">
      
      {/* 1. Live Engine Controls */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-slate-900/50 border border-white/5 p-4 rounded-2xl backdrop-blur-md">
        
        {/* Status Indicator Info with Live Mempool Telemetry */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950/50 border border-white/5 rounded-xl text-xs font-mono text-slate-400">
            <Database className="w-4 h-4 text-brand-cyan" />
            <span className="font-semibold text-white">ENGINE STATUS</span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950/50 border border-white/5 rounded-xl text-xs font-mono text-slate-300">
            <Radio className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
            {/* The pending count used to be the ONLY number here, so a pool
                holding an in-flight or a rejected send still read "0 Pending
                TXs". Report the three states side by side; the rejected chip
                is red and explicit because those transactions can never
                confirm — the reader needs the reason from the mempool tab. */}
            <span className="text-amber-400 font-bold">
              {pendingCount} Pending TXs
            </span>
            {inFlightCount > 0 && (
              <>
                <span className="text-slate-600">|</span>
                <span className="text-amber-300 font-semibold">{inFlightCount} in flight</span>
              </>
            )}
            {rejectedCount > 0 && (
              <>
                <span className="text-slate-600">|</span>
                <span className="text-brand-red font-semibold">{rejectedCount} rejected</span>
              </>
            )}
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">{((stats.mempoolBytes ?? (mempool.length * 480)) / 1024).toFixed(0)} KB Buffer</span>
            <span className="text-slate-600">|</span>
            <span className="text-brand-cyan font-medium">{stats.currentTps || 24} TPS</span>
          </div>
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

      {/* MEMPOOL.SPACE BLOCK & CHAIN VIEW */}
      <MempoolChainView
        stats={stats}
        blocks={blocks}
        mempool={mempool}
        onSelectBlock={onSelectBlock}
        onManualMine={onManualMine}
      />

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

      {/* Canonical address discovery history */}
      <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span className="w-1.5 h-4 bg-brand-green rounded-full" />
              SPIF Holder Growth
            </h2>
            <p className="text-xs text-slate-500 font-mono mt-1">Addresses first observed in finalized blocks — last 30 days</p>
          </div>
          <div className="text-right font-mono">
            <div className="text-xl text-brand-green font-bold">{holderGrowth.at(-1)?.holders ?? 0}</div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">on-chain addresses</div>
          </div>
        </div>
        {holderGrowth.length === 0 ? (
          <div className="h-32 flex items-center justify-center text-xs font-mono text-slate-600">No canonical address events in this period.</div>
        ) : (
          <div className="h-32 relative">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="w-full h-full overflow-visible" role="img" aria-label="SPIF holder growth chart">
              <path d={growthPath} fill="none" stroke="rgb(52 211 153)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
              {holderGrowth.map((point, index) => {
                const x = holderGrowth.length <= 1 ? 0 : (index / (holderGrowth.length - 1)) * 100;
                const y = 100 - (point.holders / maxHolders) * 88 - 6;
                return <circle key={point.date} cx={x} cy={y} r="1.8" fill="rgb(52 211 153)"><title>{`${point.date}: ${point.holders} holders, +${point.newHolders} new`}</title></circle>;
              })}
            </svg>
            <div className="absolute inset-x-0 bottom-0 flex justify-between text-[10px] text-slate-600 font-mono pointer-events-none">
              <span>{holderGrowth[0]?.date}</span><span>{holderGrowth.at(-1)?.date}</span>
            </div>
          </div>
        )}
      </div>

      {/* 3. Latest Blocks and Active Addresses */}
      <div className="space-y-8">
        {/* Blocks Section with 3D Isometric Box & Chain Link Icons */}
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
                  <th className="py-3 px-2">Block State</th>
                  <th className="py-3 px-2">Height</th>
                  <th className="py-3 px-2">Hash</th>
                  <th className="py-3 px-2">TXs</th>
                  <th className="py-3 px-2 text-right">Proposer Node</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {blocks.slice(0, 5).map((block) => {
                  const isBlockConfirmed = block.commitStatus === 'finalized' || block.commitStatus === 'committed';
                  return (
                    <tr 
                      key={block.height}
                      onClick={() => onSelectBlock(block.height)}
                      className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer"
                    >
                      <td className="py-2.5 px-2">
                        <div className="flex items-center gap-1.5">
                          <BlockChainIcon
                            size={32}
                            height={block.height}
                            state={isBlockConfirmed ? 'confirmed' : 'produced'}
                            animated={true}
                          />
                          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border uppercase font-bold ${
                            isBlockConfirmed
                              ? 'bg-brand-green/10 text-brand-green border-brand-green/20'
                              : 'bg-brand-cyan/10 text-brand-cyan border-brand-cyan/20 animate-pulse'
                          }`}>
                            {isBlockConfirmed ? 'Locked' : 'Produced'}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-2 font-mono font-bold text-brand-cyan">
                        #{block.height}
                      </td>
                      <td className="py-3 px-2 font-mono text-xs text-slate-400">
                        {formatHash(block.hash, 10)}
                      </td>
                      <td className="py-3 px-2 font-mono text-xs">
                        {block.txCount} txs
                      </td>
                      <td className="py-3 px-2 font-mono text-xs text-slate-500 hover:text-brand-purple text-right">
                        {formatHash(block.proposer, 6)}
                      </td>
                    </tr>
                  );
                })}
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

    </div>
  );
}
