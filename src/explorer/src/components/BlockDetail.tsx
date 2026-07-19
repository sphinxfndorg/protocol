/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Block, Transaction } from '../types';
import { ArrowLeft, Copy, CheckCircle, Clock, Calendar, ShieldAlert } from 'lucide-react';
import { formatHash, formatTimeAgo } from '../utils/formatters';

interface BlockDetailProps {
  block: Block;
  blockTxs: Transaction[];
  onBack: () => void;
  onSelectTx: (txid: string) => void;
  onSelectAddress: (address: string) => void;
}

export default function BlockDetail({
  block,
  blockTxs,
  onBack,
  onSelectTx,
  onSelectAddress
}: BlockDetailProps) {
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const gasPercentage = Math.min(100, Math.round((block.gasUsed / block.gasLimit) * 100));

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* 1. Page Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-5">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2.5 bg-slate-900 border border-white/5 hover:border-white/10 text-slate-300 hover:text-white rounded-xl transition cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-brand-cyan font-mono bg-brand-cyan/10 border border-brand-cyan/20 px-2.5 py-0.5 rounded-full uppercase tracking-wider font-bold">
                Mined Node
              </span>
              <span className="text-xs text-slate-500 font-mono">#{block.height}</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-white mt-1">
              Block #{block.height.toLocaleString()}
            </h1>
          </div>
        </div>
        <div className="flex items-center gap-1.5 bg-brand-green/10 text-brand-green border border-brand-green/20 px-3.5 py-1.5 rounded-xl text-xs font-mono">
          <CheckCircle className="w-4 h-4" />
          {block.commitStatus.toUpperCase()}
        </div>
      </div>

      {/* 2. Block Header Technical Specs */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        
        {/* Specs Table */}
        <div className="md:col-span-8 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md space-y-6">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="w-1.5 h-4 bg-brand-cyan rounded-full" />
            Block Header Metadata
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            {/* Hash */}
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Block Hash</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300 select-all truncate break-all">
                  {block.hash}
                </span>
                <button
                  onClick={() => handleCopy(block.hash)}
                  className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"
                  title="Copy Hash"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Parent Hash */}
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Parent Hash</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-400 truncate">
                  {block.parentHash}
                </span>
                <button
                  onClick={() => handleCopy(block.parentHash)}
                  className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Proposer */}
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Proposer Node Signature</span>
              <div className="text-xs font-mono text-brand-purple truncate">
                {block.proposer}
              </div>
            </div>

            {/* Timestamp */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Mined Timestamp</span>
              <div className="text-xs text-white font-mono flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                {new Date(block.timestamp * 1000).toLocaleTimeString()} ({formatTimeAgo(block.timestamp)})
              </div>
            </div>

            {/* Date */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Mined Date</span>
              <div className="text-xs text-white font-mono flex items-center gap-1.5">
                <Calendar className="w-3.5 h-3.5 text-slate-500" />
                {new Date(block.timestamp * 1000).toLocaleDateString()}
              </div>
            </div>

            {/* Difficulty */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Consensus Weight / Difficulty</span>
              <div className="text-xs text-brand-cyan font-mono font-semibold">
                {block.difficulty}
              </div>
            </div>

            {/* Signature scheme */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Stateless Shield Standard</span>
              <div className="text-xs text-brand-green font-mono font-semibold uppercase">
                {block.signatureScheme} Cryptography
              </div>
            </div>

            {/* State Roots */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Merkle State Root</span>
              <div className="text-xs text-slate-400 font-mono truncate">
                {block.stateRoot}
              </div>
            </div>

            {/* Txs Roots */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Merkle TXs Root</span>
              <div className="text-xs text-slate-400 font-mono truncate">
                {block.txsRoot}
              </div>
            </div>

          </div>
        </div>

        {/* Gas and Finality Gauge Card */}
        <div className="md:col-span-4 flex flex-col gap-6">
          
          {/* Gas Card */}
          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md space-y-4">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider font-mono text-slate-500">
              Block Gas Analytics
            </h3>

            <div className="space-y-2.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-400">Gas Utilization</span>
                <span className="text-brand-cyan font-bold">{gasPercentage}%</span>
              </div>
              <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-white/5">
                <div 
                  className="bg-gradient-to-r from-brand-cyan to-brand-purple h-full rounded-full" 
                  style={{ width: `${gasPercentage}%` }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs font-mono border-t border-white/5 pt-4">
              <div>
                <span className="text-[10px] text-slate-500 block mb-0.5">USED</span>
                <span className="text-white font-bold">{block.gasUsed.toLocaleString()}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 block mb-0.5">LIMIT</span>
                <span className="text-white font-bold">{block.gasLimit.toLocaleString()}</span>
              </div>
            </div>
          </div>

          {/* PQ Hardening Alert */}
          <div className="bg-brand-purple/5 border border-brand-purple/20 rounded-2xl p-6 backdrop-blur-md flex items-start gap-4">
            <ShieldAlert className="w-10 h-10 text-brand-purple shrink-0 mt-0.5" />
            <div className="space-y-1.5">
              <h4 className="text-xs font-bold text-white font-mono uppercase tracking-widest">Quantum Attested</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                This block is verified through stateless hash trees. A quantum computer cannot forge the block seal or rewrite its history.
              </p>
            </div>
          </div>

        </div>

      </div>

      {/* 3. Block Transactions list */}
      <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
        <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-6">
          <span className="w-1.5 h-4 bg-brand-purple rounded-full" />
          Transactions Mapped Inside Block ({blockTxs.length})
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead>
              <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                <th className="py-3 px-2">TXID Hash</th>
                <th className="py-3 px-2">Sender Address</th>
                <th className="py-3 px-2">Receiver Address</th>
                <th className="py-3 px-2">Amount</th>
                <th className="py-3 px-2 text-right">Sig Standard</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {blockTxs.map((tx) => (
                <tr 
                  key={tx.txid}
                  onClick={() => onSelectTx(tx.txid)}
                  className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer text-xs"
                >
                  <td className="py-3 px-2 font-mono text-brand-purple font-semibold">
                    {formatHash(tx.txid, 12)}
                  </td>
                  <td className="py-3 px-2 font-mono text-slate-400">
                    {tx.isSystemTx ? 'SYSTEM COINBASE' : formatHash(tx.sender, 10)}
                  </td>
                  <td className="py-3 px-2 font-mono text-slate-400">
                    {formatHash(tx.receiver, 10)}
                  </td>
                  <td className="py-3 px-2 font-mono font-bold text-white">
                    {parseFloat(tx.amountSpx).toFixed(4)} SPX
                  </td>
                  <td className="py-3 px-2 text-right text-brand-cyan font-mono">
                    {tx.signatureScheme}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
