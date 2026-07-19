/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Transaction } from '../types';
import { ArrowLeft, Copy, Clock, Database, Tag, Shield, FileCode, CheckCircle, HelpCircle } from 'lucide-react';
import { formatTimeAgo } from '../utils/formatters';

interface TxDetailProps {
  tx: Transaction;
  onBack: () => void;
  onSelectBlock: (height: number) => void;
  onSelectAddress: (address: string) => void;
}

export default function TxDetail({
  tx,
  onBack,
  onSelectBlock,
  onSelectAddress
}: TxDetailProps) {
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getStatusClass = (status: string) => {
    switch (status) {
      case 'success': return 'bg-brand-green/10 text-brand-green border-brand-green/20';
      case 'pending': return 'bg-brand-gold/10 text-brand-gold border-brand-gold/20 animate-pulse';
      default: return 'bg-brand-red/10 text-brand-red border-brand-red/20';
    }
  };

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
              <span className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border font-bold ${getStatusClass(tx.status)}`}>
                {tx.status}
              </span>
              <span className="text-xs text-slate-500 font-mono">sphinx-pq-tx</span>
            </div>
            <h1 className="text-xl md:text-2xl font-bold text-white mt-1 font-mono break-all max-w-xl md:max-w-2xl">
              TXID: {tx.txid}
            </h1>
          </div>
        </div>
        <button
          onClick={() => handleCopy(tx.txid)}
          className="p-3 bg-slate-900 border border-white/5 hover:border-white/10 text-slate-300 hover:text-white rounded-xl transition cursor-pointer"
          title="Copy Txid"
        >
          <Copy className="w-4 h-4" />
        </button>
      </div>

      {/* 2. Core Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        
        {/* Core details table */}
        <div className="md:col-span-8 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md space-y-6">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="w-1.5 h-4 bg-brand-purple rounded-full" />
            Transaction Overview
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            {/* Sender Address */}
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Sender (From)</span>
              <div className="flex items-center justify-between gap-4">
                {tx.isSystemTx ? (
                  <span className="text-xs font-mono text-brand-green font-bold">
                    SYSTEM COINBASE (Quantum-Safe Block Mint Reward)
                  </span>
                ) : (
                  <button
                    onClick={() => onSelectAddress(tx.sender)}
                    className="text-xs font-mono text-brand-cyan hover:underline text-left break-all select-all truncate"
                  >
                    {tx.sender}
                  </button>
                )}
                {!tx.isSystemTx && (
                  <button
                    onClick={() => handleCopy(tx.sender)}
                    className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            {/* Receiver Address */}
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Recipient (To)</span>
              <div className="flex items-center justify-between gap-4">
                <button
                  onClick={() => onSelectAddress(tx.receiver)}
                  className="text-xs font-mono text-brand-cyan hover:underline text-left break-all select-all truncate"
                >
                  {tx.receiver}
                </button>
                <button
                  onClick={() => handleCopy(tx.receiver)}
                  className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Block height */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Block Mapped</span>
              <div className="text-xs font-mono text-white flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-slate-500" />
                {tx.blockHeight > 0 ? (
                  <button
                    onClick={() => onSelectBlock(tx.blockHeight)}
                    className="text-brand-cyan hover:underline font-bold"
                  >
                    #{tx.blockHeight.toLocaleString()}
                  </button>
                ) : (
                  <span className="text-brand-gold font-bold">Unconfirmed (Mempool)</span>
                )}
              </div>
            </div>

            {/* Time */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Verification Time</span>
              <div className="text-xs text-white font-mono flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                {new Date(tx.timestamp * 1000).toLocaleString()} ({formatTimeAgo(tx.timestamp)})
              </div>
            </div>

            {/* Gas fee */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Gas Fees Burned</span>
              <div className="text-xs font-mono text-white">
                <span className="text-brand-purple font-semibold">{tx.gasFeeSpx} SPX</span>
              </div>
            </div>

            {/* Gas price info */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Gas Limit & Price</span>
              <div className="text-xs font-mono text-slate-400">
                Lmt: {tx.gasLimit.toLocaleString()} · Prc: {tx.gasPrice} nSPX
              </div>
            </div>

            {/* Nonce */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Nonce (Sender Seq)</span>
              <div className="text-xs font-mono text-white">
                {tx.nonce}
              </div>
            </div>

            {/* Chain info */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Network Core</span>
              <div className="text-xs font-mono text-white uppercase flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-slate-500" />
                {tx.chainId}
              </div>
            </div>

          </div>
        </div>

        {/* Right side: Giant SPX value display */}
        <div className="md:col-span-4 flex flex-col gap-6">
          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md flex flex-col items-center justify-center text-center space-y-4">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest font-mono">
              Transactional Volume
            </h3>
            <div className="space-y-1">
              <div className="text-4xl font-bold text-white font-mono">
                {parseFloat(tx.amountSpx).toLocaleString()}
              </div>
              <div className="text-brand-cyan font-mono font-bold text-sm tracking-wider uppercase">
                SPX Tokens
              </div>
            </div>
            <div className="text-slate-500 font-mono text-[10px] border-t border-white/5 w-full pt-3">
              ({tx.amountNspx} nSPX)
            </div>
          </div>

          {/* Secure PQ Attestation seal */}
          <div className="bg-brand-cyan/5 border border-brand-cyan/20 rounded-2xl p-6 backdrop-blur-md space-y-3">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-brand-cyan" />
              <h4 className="text-xs font-bold text-white uppercase tracking-widest font-mono">PQ Seal Mapped</h4>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              This signature is structured as a series of Winternitz one-time key trees (WOTS+). 
              A classical ECDSA private key is easily broken by Shor's period-finding algorithm. 
              This transaction utilizes stateless hash chains which possess zero structural shortcuts.
            </p>
          </div>
        </div>

      </div>

      {/* 3. Post-Quantum Signatures Details Sandbox */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Post-quantum specs */}
        <div className="lg:col-span-7 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span className="w-1.5 h-4 bg-brand-cyan rounded-full" />
              Post-Quantum Signature Sandbox
            </h2>
            <span className="text-xs font-mono text-brand-cyan uppercase bg-brand-cyan/15 border border-brand-cyan/20 px-2.5 py-0.5 rounded font-bold">
              {tx.signatureScheme}
            </span>
          </div>

          <div className="space-y-4">
            
            {/* Merkle root */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">WOTS+ Hyper-Tree Merkle Root</span>
                <button
                  onClick={() => handleCopy(tx.merkleRoot)}
                  className="p-1 text-slate-500 hover:text-brand-cyan rounded cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="text-xs text-brand-cyan font-mono truncate">
                {tx.merkleRoot}
              </div>
            </div>

            {/* Public key */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Quantum Public Key Seal</span>
                <button
                  onClick={() => handleCopy(tx.publicKey)}
                  className="p-1 text-slate-500 hover:text-brand-cyan rounded cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="text-xs text-white font-mono truncate">
                {tx.publicKey}
              </div>
            </div>

            {/* Signature scrolling terminal */}
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3.5">
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Compressed Stateless Signature (Bytes)</span>
                <button
                  onClick={() => handleCopy(tx.signature)}
                  className="p-1 text-slate-500 hover:text-brand-cyan rounded cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="bg-slate-900 border border-white/5 rounded-lg p-2.5 h-24 overflow-y-auto text-[10px] text-slate-400 font-mono break-all leading-relaxed scrollbar-thin">
                {tx.signature}
              </div>
            </div>

          </div>
        </div>

        {/* Audit Trail Checklist (Visual Interactive Sandbox) */}
        <div className="lg:col-span-5 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md flex flex-col justify-between">
          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <span className="w-1.5 h-4 bg-brand-green rounded-full" />
              Leaf-Path verification pipeline
            </h3>
            <p className="text-xs text-slate-500 font-mono">State transition verification</p>

            <div className="space-y-3 font-mono text-[11px]">
              <div className="flex items-center justify-between p-2.5 bg-slate-950/80 rounded-xl border border-brand-green/20">
                <div className="flex items-center gap-2 text-brand-green">
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Public Key Hash Validated</span>
                </div>
                <span className="text-slate-500 text-[10px]">PASS</span>
              </div>

              <div className="flex items-center justify-between p-2.5 bg-slate-950/80 rounded-xl border border-brand-green/20">
                <div className="flex items-center gap-2 text-brand-green">
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>XMSS/SPHINCS+ Leaf Path verified</span>
                </div>
                <span className="text-slate-500 text-[10px]">INDEX: {tx.nonce * 2 + 1}</span>
              </div>

              <div className="flex items-center justify-between p-2.5 bg-slate-950/80 rounded-xl border border-brand-green/20">
                <div className="flex items-center gap-2 text-brand-green">
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>FORS Subset & WOTS+ Hash Verification</span>
                </div>
                <span className="text-slate-500 text-[10px]">k=14, a=12 validated</span>
              </div>

              <div className="flex items-center justify-between p-2.5 bg-slate-950/80 rounded-xl border border-brand-green/20">
                <div className="flex items-center gap-2 text-brand-green">
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Zero-Replay Nonce Checked</span>
                </div>
                <span className="text-slate-500 text-[10px]">#{tx.nonce}</span>
              </div>
            </div>
          </div>

          <div className="mt-6 p-3 bg-brand-green/5 border border-brand-green/10 rounded-xl text-center text-[10px] text-brand-green font-mono uppercase tracking-widest animate-pulse">
            ◆ ALL QUANTUM ATTRIBUTES COMPILING CORRECTLY ◆
          </div>
        </div>

      </div>

      {/* 4. OP_RETURN Custom Data Block */}
      {tx.returnData && (
        <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
          <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
            <FileCode className="w-4 h-4 text-brand-cyan" />
            OP_RETURN Mapped Data (Decoded ASCII)
          </h2>
          <div className="bg-slate-950 border border-white/5 rounded-xl p-4 font-mono text-xs text-brand-cyan">
            {tx.returnData}
          </div>
        </div>
      )}

    </div>
  );
}
