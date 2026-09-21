/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Block, Transaction, Attestation } from '../types';
import { ArrowLeft, Copy, CheckCircle, ShieldAlert, Flame, Hash, Info, FileCode } from 'lucide-react';
import { formatHash, formatTimeAgo, formatSPX, formatNSPX } from '../utils/formatters';

interface BlockDetailProps {
  block: Block;
  blockTxs: Transaction[];
  attestations?: Attestation[];
  onBack: () => void;
  onSelectTx: (txid: string) => void;
  onSelectAddress: (address: string) => void;
}

export default function BlockDetail({
  block,
  blockTxs,
  attestations = [],
  onBack,
  onSelectTx,
  onSelectAddress
}: BlockDetailProps) {
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const gasPercentage = Math.min(100, Math.round((block.gasUsed / block.gasLimit) * 100));

  // Optional header fields are aliased to `const` bindings: TypeScript drops
  // property narrowing inside the onClick closures below (a callback may run
  // after the property changes), but a const binding keeps it, so
  // handleCopy(extraData) type-checks without a non-null assertion.
  const extraData = block.extraData;
  const miner = block.miner;

  const totalBurnedNspx = block.burnedThisBlockNspx ? BigInt(block.burnedThisBlockNspx).toString() : '0';
  const totalBurnedSpx = block.burnedThisBlockSpx ? parseFloat(block.burnedThisBlockSpx) : 0;
  const totalRewardNspx = block.blockRewardNspx ? BigInt(block.blockRewardNspx).toString() : '0';
  const totalRewardSpx = block.blockRewardSpx ? parseFloat(block.blockRewardSpx) : 0;

  return (
    <div className="space-y-8 animate-fadeIn">
      <div className="flex items-center justify-between border-b border-white/5 pb-5">
        <div className="flex items-center gap-3">
          <button onClick={onBack} className="p-2.5 bg-slate-900 border border-white/5 hover:border-white/10 text-slate-300 hover:text-white rounded-xl transition cursor-pointer">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-brand-cyan font-mono bg-brand-cyan/10 border border-brand-cyan/20 px-2.5 py-0.5 rounded-full uppercase tracking-wider font-bold">Mined Node</span>
              <span className="text-xs text-slate-500 font-mono">#{block.height}</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-white mt-1">Block #{block.height.toLocaleString()}</h1>
          </div>
        </div>
        <div className="flex items-center gap-1.5 bg-brand-green/10 text-brand-green border border-brand-green/20 px-3.5 py-1.5 rounded-xl text-xs font-mono">
          <CheckCircle className="w-4 h-4" />
          {block.commitStatus.toUpperCase()}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        <div className="md:col-span-8 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md space-y-6">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="w-1.5 h-4 bg-brand-cyan rounded-full" />
            Block Header Metadata
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Block Hash</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300 select-all truncate break-all">{block.hash}</span>
                <button onClick={() => handleCopy(block.hash)} className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"><Copy className="w-3.5 h-3.5" /></button>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Parent Hash</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300 select-all truncate break-all">{formatHash(block.parentHash, 48)}</span>
                <button onClick={() => handleCopy(block.parentHash)} className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"><Copy className="w-3.5 h-3.5" /></button>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Tx Merkle Root</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300 select-all truncate break-all">{formatHash(block.txsRoot, 48)}</span>
                <button onClick={() => handleCopy(block.txsRoot)} className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"><Copy className="w-3.5 h-3.5" /></button>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">State Root</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300 select-all truncate break-all">{formatHash(block.stateRoot, 48)}</span>
                <button onClick={() => handleCopy(block.stateRoot)} className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"><Copy className="w-3.5 h-3.5" /></button>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Nonce</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300">{block.nonce.toLocaleString()}</span>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Timestamp</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300">{block.timestampIso || new Date(block.timestamp * 1000).toISOString()}</span>
                <span className="text-[10px] text-slate-500 font-mono">{formatTimeAgo(block.timestamp)}</span>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Difficulty</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300">{block.difficulty}</span>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Version</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300">{block.version}</span>
              </div>
            </div>
            <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Uncles Hash</span>
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-mono text-slate-300 select-all truncate break-all">{formatHash(block.unclesHash, 48)}</span>
              </div>
            </div>
            <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
              <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Gas Usage</span>
              <div className="w-full bg-slate-800 rounded-full h-2.5 mb-2 overflow-hidden">
                <div className="h-full rounded-full transition-all duration-300 ease-out" style={{width: `${gasPercentage}%`, backgroundColor: gasPercentage > 90 ? '#ef4444' : gasPercentage > 70 ? '#f59e0b' : '#22c55e'}} />
              </div>
              <div className="grid grid-cols-2 gap-4 text-xs font-mono border-t border-white/5 pt-4">
                <div><span className="text-[10px] text-slate-500 block mb-0.5">USED</span><span className="text-white font-bold">{block.gasUsed.toLocaleString()}</span></div>
                <div><span className="text-[10px] text-slate-500 block mb-0.5">LIMIT</span><span className="text-white font-bold">{block.gasLimit.toLocaleString()}</span></div>
              </div>
            </div>
            {extraData && (
              <div className="col-span-2 flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Extra Data</span>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-xs font-mono text-slate-300 select-all truncate break-all max-w-2xl">{formatHash(extraData, 96)}</span>
                  <button onClick={() => handleCopy(extraData)} className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"><Copy className="w-3.5 h-3.5" /></button>
                </div>
              </div>
            )}
            {miner && (
              <div className="flex flex-col gap-1.5 bg-slate-950 border border-white/5 rounded-xl p-3">
                <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">Miner</span>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-xs font-mono text-slate-300 select-all truncate break-all">{formatHash(miner, 40)}</span>
                  <button onClick={() => handleCopy(miner)} className="p-1.5 text-slate-500 hover:text-brand-cyan rounded transition cursor-pointer"><Copy className="w-3.5 h-3.5" /></button>
                </div>
              </div>
            )}
          </div>
          <div className="bg-brand-purple/5 border border-brand-purple/20 rounded-2xl p-6 backdrop-blur-md flex items-start gap-4">
            <ShieldAlert className="w-10 h-10 text-brand-purple shrink-0 mt-0.5" />
            <div className="space-y-1.5">
              <h4 className="text-xs font-bold text-white font-mono uppercase tracking-widest">Quantum Attested</h4>
              <p className="text-xs text-slate-400 leading-relaxed">This block is verified through stateless hash trees. A quantum computer cannot forge the block seal or rewrite its history.</p>
            </div>
          </div>
        </div>

        <div className="md:col-span-4 space-y-4">
          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center gap-2 mb-4">
              <Flame className="w-4 h-4 text-brand-red" />
              <h3 className="text-sm font-semibold text-white">Coin Burn This Block</h3>
            </div>
            {totalBurnedNspx !== '0' && BigInt(totalBurnedNspx) > BigInt(0) ? (
              <div className="space-y-3">
                <div className="bg-slate-950 border border-white/5 rounded-xl p-4">
                  <div className="text-2xl font-bold text-brand-red font-mono">{formatSPX(totalBurnedSpx)}<span className="text-sm font-normal text-slate-400 ml-1">SPX</span></div>
                  <div className="text-xs text-slate-500 font-mono mt-1">{formatNSPX(totalBurnedNspx)}<span className="text-slate-600 mx-1">nSPX</span></div>
                </div>
                {block.burnedBeforeNspx && BigInt(block.burnedBeforeNspx) > BigInt(0) && (
                  <div className="text-xs text-slate-500 font-mono">Total burned before: {formatNSPX(block.burnedBeforeNspx)} nSPX</div>
                )}
                <div className="text-xs text-slate-500 mt-2 flex items-center gap-2">
                  <Info className="w-3 h-3" />
                  <span>Coins sent to DEAD address are permanently removed</span>
                </div>
              </div>
            ) : (
              <div className="bg-slate-950/50 border border-white/5 rounded-xl p-4 text-center">
                <Flame className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-xs text-slate-500">No coins burned in this block</p>
              </div>
            )}
          </div>

          <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
            <div className="flex items-center gap-2 mb-4">
              <Hash className="w-4 h-4 text-brand-cyan" />
              <h3 className="text-sm font-semibold text-white">Block Reward (Coinbase)</h3>
            </div>
            {block.blockRewardNspx ? (
              <div className="space-y-3">
                <div className="bg-slate-950 border border-white/5 rounded-xl p-4">
                  <div className="text-2xl font-bold text-brand-cyan font-mono">{formatSPX(totalRewardSpx)}<span className="text-sm font-normal text-slate-400 ml-1">SPX</span></div>
                  <div className="text-xs text-slate-500 font-mono mt-1">{formatNSPX(totalRewardNspx)}<span className="text-slate-600 mx-1">nSPX</span></div>
                </div>

                {/* Policy split: proposer's spendable slice and the slice burned
                    per BlockRewardBurnBPS. Total = miner + burned exactly. */}
                {(block.blockRewardMinerNspx || block.blockRewardBurnedNspx) && (
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                    <div className="bg-slate-950/60 border border-brand-cyan/10 rounded-lg p-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">TO PROPOSER</span>
                      <span className="text-brand-cyan font-bold">
                        {formatSPX(parseFloat(block.blockRewardMinerNspx || '0') / 1e18)}
                      </span>
                    </div>
                    <div className="bg-slate-950/60 border border-brand-red/10 rounded-lg p-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">REWARD BURNED</span>
                      <span className="text-brand-red font-bold">
                        {formatSPX(parseFloat(block.blockRewardBurnedNspx || '0') / 1e18)}
                      </span>
                    </div>
                  </div>
                )}

                {block.gasPrice && (
                  <div className="text-xs text-slate-500 font-mono">Gas Price: {block.gasPrice} nSPX</div>
                )}
                <div className="text-xs text-slate-500 mt-2 flex items-center gap-2">
                  <Info className="w-3 h-3" />
                  <span>Newly minted coins awarded to block proposer</span>
                </div>
              </div>
            ) : (
              <div className="bg-slate-950/50 border border-white/5 rounded-xl p-4 text-center">
                <Hash className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-xs text-slate-500">No reward data available</p>
              </div>
            )}
          </div>

          {attestations.length > 0 && (
            <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
              <div className="flex items-center gap-2 mb-4">
                <CheckCircle className="w-4 h-4 text-brand-green" />
                <h3 className="text-sm font-semibold text-white">Attestations ({attestations.length})</h3>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {attestations.slice(0, 5).map((att, idx) => (
                  <div key={idx} className="flex items-center justify-between bg-slate-950/50 border border-white/5 rounded-lg p-2 text-xs">
                    <span className="text-slate-400 font-mono truncate">{formatHash(att.validatorId, 12)}</span>
                    <span className="text-slate-500 font-mono">View {att.view}</span>
                  </div>
                ))}
                {attestations.length > 5 && (
                  <div className="text-xs text-slate-500 text-center pt-2">+{attestations.length - 5} more</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="w-1.5 h-4 bg-brand-purple rounded-full" />
            Transactions Mapped Inside Block ({blockTxs.length})
          </h2>
          <span className="text-xs text-slate-500 font-mono">Total Value: {blockTxs.reduce((sum, tx) => sum + parseFloat(tx.amountSpx || '0'), 0).toFixed(4)} SPX</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead>
              <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                <th className="py-3 px-2">TXID Hash</th>
                <th className="py-3 px-2">Sender</th>
                <th className="py-3 px-2">Receiver</th>
                <th className="py-3 px-2">Nonce</th>
                <th className="py-3 px-2">Amount</th>
                <th className="py-3 px-2">Fee</th>
                <th className="py-3 px-2">Burned</th>
                <th className="py-3 px-2">Gas Used</th>
                <th className="py-3 px-2">OP_RETURN Memo</th>
                <th className="py-3 px-2 text-right">Signature</th>
                <th className="py-3 px-2 text-right">Confirmations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {blockTxs.map((tx) => (
                <tr key={tx.txid} onClick={() => onSelectTx(tx.txid)} className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer text-xs">
                  <td className="py-3 px-2 font-mono text-brand-purple font-semibold">{formatHash(tx.txid, 12)}</td>
                  <td className="py-3 px-2 font-mono text-slate-400">{tx.isSystemTx ? 'SYSTEM COINBASE' : formatHash(tx.sender, 10)}</td>
                  <td className="py-3 px-2 font-mono text-slate-400">{formatHash(tx.receiver, 10)}</td>
                  <td className="py-3 px-2 font-mono text-slate-400">{tx.nonce}</td>
                  <td className="py-3 px-2 font-mono font-bold text-white">{parseFloat(tx.amountSpx).toFixed(4)} SPX</td>
                  <td className="py-3 px-2 font-mono text-slate-400">{parseFloat(tx.feeSpx).toFixed(6)} SPX</td>
                  <td className="py-3 px-2 font-mono">
                    {tx.burnedThisTxNspx && BigInt(tx.burnedThisTxNspx) > BigInt(0)
                      ? <span className="text-brand-red">{parseFloat(tx.burnedThisTxSpx || '0').toFixed(6)} SPX</span>
                      : <span className="text-slate-600">-</span>}
                  </td>
                  <td className="py-3 px-2 font-mono text-slate-400">
                    {tx.gasUsed !== undefined ? tx.gasUsed.toLocaleString() : '—'}
                  </td>
                  <td className="py-3 px-2 font-mono text-brand-cyan max-w-[16rem] truncate" title={tx.returnDataText || tx.returnData || ''}>
                    {tx.returnDataText || (tx.returnData ? formatHash(tx.returnData, 12) : <span className="text-slate-600">—</span>)}
                  </td>
                  <td className="py-3 px-2 text-right text-brand-cyan font-mono">{tx.signatureScheme}</td>
                  <td className="py-3 px-2 text-right font-mono text-slate-400">{tx.confirmations}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* OP_RETURN memos decoded in full. The table truncates for scan
            width; this panel is where a whole anchor tag or memo is readable
            without a per-transaction request. */}
        {blockTxs.some((tx) => tx.returnData || tx.returnDataText) && (
          <div className="mt-6 space-y-3">
            <h3 className="text-xs font-semibold text-white uppercase tracking-widest font-mono flex items-center gap-2">
              <FileCode className="w-3.5 h-3.5 text-brand-cyan" />
              OP_RETURN Payloads ({blockTxs.filter((tx) => tx.returnData || tx.returnDataText).length})
            </h3>
            {blockTxs
              .filter((tx) => tx.returnData || tx.returnDataText)
              .map((tx) => (
                <div key={`memo-${tx.txid}`} className="bg-slate-950 border border-white/5 rounded-xl p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-[10px] font-mono text-brand-purple">{formatHash(tx.txid, 16)}</span>
                    <span className="text-[10px] font-mono uppercase text-slate-500">
                      {tx.returnDataKind || 'memo'}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-brand-cyan break-all whitespace-pre-wrap max-h-40 overflow-y-auto">
                    {tx.returnDataText || tx.returnData}
                  </div>
                </div>
              ))}
          </div>
        )}
        {blockTxs.length > 0 && (
          <div className="mt-4 pt-4 border-t border-white/5 flex flex-wrap gap-4 text-xs text-slate-500 font-mono">
            <span>Total Transactions: {blockTxs.length}</span>
            <span>Total Fees: {blockTxs.reduce((sum, tx) => sum + parseFloat(tx.feeSpx || '0'), 0).toFixed(6)} SPX</span>
            <span>Total Burned: {blockTxs.reduce((sum, tx) => sum + BigInt(tx.burnedThisTxNspx || '0'), BigInt(0)).toString()} nSPX</span>
          </div>
        )}
      </div>
    </div>
  );
}
