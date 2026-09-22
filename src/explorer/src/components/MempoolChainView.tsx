/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mempool.space-inspired Horizontal Block & Chain Visualizer.
 * Displays real-time chain conveyor with:
 * - Projected / Mempool blocks (amber/orange) on the left
 * - Real-time mining frontier / current tip divider
 * - Confirmed mined blocks (indigo/purple) linked with physical chain links on the right
 */

import { Block, NetworkStats, Transaction } from '../types';
import { formatTimeAgo } from '../utils/formatters';
import BlockChainIcon from './BlockChainIcon';

interface MempoolChainViewProps {
  stats: NetworkStats;
  blocks: Block[];
  mempool: Transaction[];
  onSelectBlock: (height: number) => void;
  onManualMine?: () => void;
}

/** Physical interlocking chain bridge between adjacent blocks */
function ChainBridge({ isPending = false }: { isPending?: boolean }) {
  const strokeColor = isPending ? '#f97316' : '#818cf8';
  const fillColor = isPending ? '#431407' : '#1e1b4b';

  return (
    <div className="shrink-0 flex items-center justify-center w-8 -mx-1 z-10 select-none">
      <svg width="34" height="26" viewBox="0 0 34 26" fill="none">
        {/* Link 1 (Horizontal) */}
        <path
          d="M 2 13 C 2 7, 10 5, 18 7 L 22 8 C 28 10, 28 16, 22 18 L 18 19 C 10 21, 2 19, 2 13 Z"
          fill={fillColor}
          stroke={strokeColor}
          strokeWidth="2.2"
        />
        <path
          d="M 8 13 C 8 10, 12 9, 16 10 L 18 11 C 21 12, 21 14, 18 15 L 16 16 C 12 17, 8 16, 8 13 Z"
          fill="#050814"
          stroke={strokeColor}
          strokeWidth="1"
          strokeOpacity="0.7"
        />

        {/* Link 2 (Interlocking Vertical Link) */}
        <path
          d="M 14 13 C 14 6, 22 4, 30 7 L 32 8 C 34 10, 34 16, 32 18 L 30 19 C 22 22, 14 20, 14 13 Z"
          fill={fillColor}
          stroke={strokeColor}
          strokeWidth="2.2"
        />
        <path
          d="M 20 13 C 20 10, 24 9, 27 10 L 28 11 C 30 12, 30 14, 28 15 L 27 16 C 24 17, 20 16, 20 13 Z"
          fill="#050814"
          stroke={strokeColor}
          strokeWidth="1"
          strokeOpacity="0.7"
        />
      </svg>
    </div>
  );
}

export default function MempoolChainView({
  stats,
  blocks,
  mempool,
  onSelectBlock,
  onManualMine,
}: MempoolChainViewProps) {
  // Show the latest 4-5 confirmed blocks
  const confirmedBlocks = blocks.slice(0, 5);

  // Compute real projected incoming block data from mempool
  const mempoolTxCount = mempool.length;
  const mempoolGasSum = mempool.reduce((sum, tx) => sum + (tx.gasLimit || 0), 0);
  // Use the latest confirmed block's gas limit as the projected block's capacity
  const tipBlock = blocks[0];
  const projectedBlockGasLimit = tipBlock && tipBlock.gasLimit > 0 ? tipBlock.gasLimit : 50000000;
  const projectedWeightPct = projectedBlockGasLimit > 0
    ? Math.min(98, Math.max(2, Math.round((mempoolGasSum / projectedBlockGasLimit) * 100)))
    : 0;
  const pendingSizeMb = stats.mempoolBytes
    ? (stats.mempoolBytes / (1024 * 1024)).toFixed(2)
    : ((mempoolTxCount * 1.35 + 420) / 1024).toFixed(2);
  // Estimate when the next block is likely to be sealed, based on the chain's
  // target block time. With an empty mempool this is ~0 txs and the "in ~Xs"
  // reads as the block-time interval; with a full mempool the estimate is the
  // same interval because block production cadence is policy-driven, not
  // demand-driven.
  const blockTimeSec = stats.blockTimeSeconds || 12;
  const estimatedSeconds = blockTimeSec;

  return (
    <div className="w-full bg-slate-950/90 border border-white/10 hover:border-white/20 rounded-2xl p-4 md:p-5 backdrop-blur-md shadow-2xl relative overflow-hidden transition-all duration-300">
      {/* Ambient background gradients */}
      <div className="absolute top-0 left-1/4 w-96 h-32 bg-amber-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute top-0 right-1/4 w-96 h-32 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Horizontal Chain Conveyor (mempool.space style) */}
      <div className="flex items-center overflow-x-auto pb-2 pt-1 scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
        <div className="flex items-center mx-auto min-w-max px-2">

          {/* 1. PROJECTED MEMPOOL BLOCK (Amber / Orange) */}
          <div
            onClick={onManualMine}
            title="Click to mine this pending block"
            className="group relative flex flex-col items-center w-48 md:w-52 p-3.5 rounded-xl border border-amber-500/40 bg-gradient-to-b from-amber-950/70 via-slate-950/80 to-slate-950 hover:border-amber-400 hover:shadow-[0_0_24px_rgba(245,158,11,0.25)] transition-all duration-200 cursor-pointer shrink-0"
          >
            {/* Top Header */}
            <div className="w-full flex items-center justify-between text-[11px] font-mono text-amber-400 font-semibold mb-1">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                ~{pendingSizeMb} MB
              </span>
              <span className="text-amber-500/80 text-[10px]">In ~{estimatedSeconds}s</span>
            </div>

            {/* 3D Isometric Mempool Block & Interlocking Chain */}
            <div className="my-1 flex items-center justify-center">
              <BlockChainIcon
                size={88}
                state="produced"
                fullness={projectedWeightPct}
                animated={true}
                showBadge={false}
              />
            </div>

            {/* Sub-stats */}
            <div className="w-full mt-1.5 pt-1.5 border-t border-amber-500/20 text-center font-mono text-[10px] text-amber-200/90 space-y-0.5">
              <div className="font-bold flex items-center justify-between">
                <span>{mempoolTxCount} transactions</span>
                <span className="text-amber-400">~{stats.currentTps || 24} TPS</span>
              </div>
              <div className="text-slate-400 text-[9px] flex items-center justify-between">
                <span>Weight: {projectedWeightPct}%</span>
                <span className="text-amber-300">Mine now →</span>
              </div>
            </div>

            {/* Capacity fill indicator bar */}
            <div className="w-full h-1 bg-amber-950/80 rounded-full mt-2 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-amber-500 to-amber-300 rounded-full transition-all duration-500"
                style={{ width: `${projectedWeightPct}%` }}
              />
            </div>
          </div>

          {/* Physical Chain Link to Mining Frontier */}
          <ChainBridge isPending={true} />

          {/* 2. MINING FRONTIER / DOTTED DIVIDER (mempool.space "Now" Line) */}
          <div className="flex flex-col items-center justify-center px-3 shrink-0 select-none">
            <div className="h-6 w-px border-l-2 border-dashed border-white/20" />
            <div className="my-1.5 px-2 py-0.5 rounded-full text-[9px] font-mono font-bold tracking-widest uppercase bg-white/10 text-white/80 border border-white/20 shadow-sm flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-brand-green animate-pulse" />
              TIP
            </div>
            <div className="h-6 w-px border-l-2 border-dashed border-white/20" />
          </div>

          {/* 3. CONFIRMED MINED BLOCKS (Mempool.space Deep Indigo/Purple) */}
          {confirmedBlocks.map((block, idx) => {
            const blockCapacityPct = Math.min(98, Math.max(2, block.gasLimit > 0 ? Math.round((block.gasUsed / block.gasLimit) * 100) : 0));
            const isLatest = idx === 0;

            return (
              <div key={block.height} className="flex items-center shrink-0">
                {/* Physical Interlocking Chain Link between blocks */}
                <ChainBridge isPending={false} />

                {/* Confirmed Block Card */}
                <div
                  onClick={() => onSelectBlock(block.height)}
                  className={`group relative flex flex-col items-center w-48 md:w-52 p-3.5 rounded-xl border transition-all duration-200 cursor-pointer ${
                    isLatest
                      ? 'border-indigo-400/60 bg-gradient-to-b from-indigo-950/80 via-slate-950/90 to-slate-950 shadow-[0_0_20px_rgba(99,102,241,0.2)] hover:border-indigo-300'
                      : 'border-white/10 bg-slate-950/70 hover:border-indigo-500/40 hover:bg-slate-900/60'
                  }`}
                >
                  {/* Top Header */}
                  <div className="w-full flex items-center justify-between text-[11px] font-mono font-semibold mb-1">
                    <span className="text-white font-bold tracking-tight">
                      #{block.height.toLocaleString()}
                    </span>
                    <span className="text-slate-400 text-[10px]">
                      {formatTimeAgo(block.timestamp)}
                    </span>
                  </div>

                  {/* 3D Isometric Block & Interlocking Chain */}
                  <div className="my-1 flex items-center justify-center">
                    <BlockChainIcon
                      size={88}
                      height={block.height}
                      state="confirmed"
                      fullness={blockCapacityPct}
                      animated={true}
                      showBadge={false}
                    />
                  </div>

                  {/* Sub-stats */}
                  <div className="w-full mt-1.5 pt-1.5 border-t border-white/10 text-center font-mono text-[10px] text-slate-300 space-y-0.5">
                    <div className="font-medium flex items-center justify-between">
                      <span className="text-white">{block.txCount} transactions</span>
                      <span className="text-indigo-300 font-bold">{block.blockRewardSpx || '2.0'} SPX</span>
                    </div>
                    <div className="text-slate-400 text-[9px] flex items-center justify-between">
                      <span>Gas: {(block.gasUsed > 0 ? (block.gasUsed / 1000) : 0).toFixed(0)}k</span>
                      <span className="text-emerald-400 font-semibold">Confirmed</span>
                    </div>
                  </div>

                  {/* Capacity fill indicator bar */}
                  <div className="w-full h-1 bg-indigo-950/80 rounded-full mt-2 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-indigo-500 to-emerald-400 rounded-full"
                      style={{ width: `${blockCapacityPct}%` }}
                    />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
