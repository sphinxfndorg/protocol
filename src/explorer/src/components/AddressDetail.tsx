/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { 
  ArrowLeft, Copy, ShieldCheck, ShieldAlert, ArrowUpRight, 
  ArrowDownLeft, Key, Zap, CheckCircle 
} from 'lucide-react';
import { Wallet, Transaction } from '../types';
import { formatHash, formatTimeAgo } from '../utils/formatters';

interface AddressDetailProps {
  wallet: Wallet;
  addressTxs: Transaction[];
  onBack: () => void;
  onSelectTx: (txid: string) => void;
  onMigrateWallet: (legacyAddress: string, newPqAddress: string, balance: string) => void;
}

export default function AddressDetail({
  wallet,
  addressTxs,
  onBack,
  onSelectTx,
  onMigrateWallet
}: AddressDetailProps) {
  const [migrationStep, setMigrationStep] = useState<
    'idle' | 'generating' | 'broadcasting' | 'complete'
  >('idle');
  const [newPqAddress, setNewPqAddress] = useState('');
  const [migrationTxId, setMigrationTxId] = useState('');

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const isLegacy = false;

  // Trigger interactive migration
  const handleStartMigration = () => {
    setMigrationStep('generating');
    
    // Simulate generation of a secure SPHINCS+ address
    setTimeout(() => {
      const generated = 'spif1_sphincsplus_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      setNewPqAddress(generated);
      setMigrationStep('broadcasting');

      // Simulate blockchain ledger broadcast
      setTimeout(() => {
        const txid = '0x_pq_migration_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        setMigrationTxId(txid);
        setMigrationStep('complete');
        
        // Notify parent state to perform migration
        onMigrateWallet(wallet.address, generated, wallet.balanceSpx);
      }, 1500);

    }, 1200);
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
              <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded-full uppercase tracking-wider font-bold ${
                isLegacy 
                  ? 'bg-brand-red/10 text-brand-red border border-brand-red/20' 
                  : 'bg-brand-green/10 text-brand-green border border-brand-green/20'
              }`}>
                {isLegacy ? 'Classical Key (Critical)' : 'Shielded Key (Armored)'}
              </span>
              <span className="text-xs text-slate-500 font-mono">Rank #{wallet.rank} Rich List</span>
            </div>
            <h1 className="text-xl md:text-2xl font-bold text-white mt-1 font-mono break-all max-w-xl md:max-w-2xl">
              Address: {wallet.address}
            </h1>
          </div>
        </div>
        <button
          onClick={() => handleCopy(wallet.address)}
          className="p-3 bg-slate-900 border border-white/5 hover:border-white/10 text-slate-300 hover:text-white rounded-xl transition cursor-pointer"
          title="Copy Public Key Address"
        >
          <Copy className="w-4 h-4" />
        </button>
      </div>

      {/* 2. Balance Statistics & Quantum Armour Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
        
        {/* Balances Block */}
        <div className="lg:col-span-4 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md flex flex-col justify-between">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest font-mono mb-4">
            Balance Overview
          </h3>

          <div className="space-y-4">
            <div>
              <span className="text-[10px] text-slate-500 font-mono uppercase">Confirmed Holdings</span>
              <div className="text-3xl font-bold text-white font-mono mt-1 break-words">
                {parseFloat(wallet.balanceSpx).toLocaleString(undefined, { minimumFractionDigits: 4 })}
              </div>
              <span className="text-xs text-brand-cyan font-bold font-mono">SPX</span>
            </div>

            <div className="grid grid-cols-2 gap-4 border-t border-white/5 pt-4 text-xs font-mono">
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Sequence Nonce</span>
                <span className="text-white font-bold">#{wallet.nonce}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">State Count</span>
                <span className="text-white font-bold">{addressTxs.length} TXs</span>
              </div>
            </div>
          </div>
        </div>

        {/* Quantum Armored Check Card */}
        <div className="lg:col-span-8 bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md flex flex-col justify-between">
          
          <div className="flex items-start gap-4">
            {isLegacy ? (
              <div className="p-3 bg-brand-red/10 rounded-xl text-brand-red shrink-0">
                <ShieldAlert className="w-8 h-8" />
              </div>
            ) : (
              <div className="p-3 bg-brand-green/10 rounded-xl text-brand-green shrink-0">
                <ShieldCheck className="w-8 h-8" />
              </div>
            )}
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-white">
                {isLegacy ? 'Quantum Vulnerability Critical' : 'Quantum-Resistant Armor Active'}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Cryptographic Signature Profile: <span className={isLegacy ? 'text-brand-red' : 'text-brand-green'}>{wallet.addressType}</span>
              </p>
              <p className="text-xs text-slate-400 leading-relaxed pt-1.5">
                {isLegacy 
                  ? 'This address uses classical ECDSA keys. When quantum computers breach the 2,048 logical qubit ceiling, they can use Shor\'s algorithm to deduce your private key directly from your public transaction history. Please migrate immediately.' 
                  : 'SPHINCS+ is a stateless, hash-based signature scheme. It relies purely on the mathematical security of standard cryptographic hash functions (such as SHA256 or SHAKE256) combined with multi-tree hyper-tree (XMSS) structures, making it completely immune to Shor\'s algorithm quantum attacks.'
                }
              </p>
            </div>
          </div>

          {/* Interactive Migration Action (For vulnerable addresses) */}
          {isLegacy && (
            <div className="mt-6 border-t border-white/5 pt-6 flex flex-col gap-4">
              {migrationStep === 'idle' && (
                <div className="flex flex-col sm:flex-row gap-4 items-center justify-between bg-brand-red/5 p-4 rounded-xl border border-brand-red/20">
                  <div className="text-xs space-y-0.5">
                    <div className="text-white font-semibold">Interactive Laboratory: PQC Transition</div>
                    <p className="text-slate-400">Migrate your SPX holdings from ECDSA to SPHINCS+ instantly.</p>
                  </div>
                  <button
                    onClick={handleStartMigration}
                    className="w-full sm:w-auto flex items-center gap-1.5 px-5 py-2.5 bg-brand-red text-slate-950 hover:bg-brand-red/90 font-bold rounded-xl text-xs transition transform hover:-translate-y-0.5 shadow-[0_0_15px_rgba(255,51,102,0.2)] cursor-pointer"
                  >
                    <Zap className="w-4 h-4" />
                    Migrate to SPHINCS+
                  </button>
                </div>
              )}

              {migrationStep === 'generating' && (
                <div className="flex flex-col gap-2 bg-slate-950 p-4 rounded-xl border border-white/5 animate-pulse text-xs font-mono">
                  <div className="flex justify-between text-slate-400">
                    <span>Generating NIST-compliant SPHINCS+ Keypair...</span>
                    <span>40%</span>
                  </div>
                  <div className="w-full bg-slate-900 h-1 rounded-full overflow-hidden">
                    <div className="bg-brand-cyan w-2/5 h-full" />
                  </div>
                </div>
              )}

              {migrationStep === 'broadcasting' && (
                <div className="flex flex-col gap-2 bg-slate-950 p-4 rounded-xl border border-white/5 animate-pulse text-xs font-mono">
                  <div className="flex justify-between text-brand-purple">
                    <span>Broadcasting Post-Quantum Shield Transaction to Ledger...</span>
                    <span>80%</span>
                  </div>
                  <div className="w-full bg-slate-900 h-1 rounded-full overflow-hidden">
                    <div className="bg-brand-purple w-4/5 h-full" />
                  </div>
                  <p className="text-[10px] text-slate-500">Destination: {newPqAddress.substring(0, 30)}...</p>
                </div>
              )}

              {migrationStep === 'complete' && (
                <div className="flex items-start gap-3 bg-brand-green/5 border border-brand-green/20 p-4 rounded-xl animate-fadeIn text-xs">
                  <CheckCircle className="w-5 h-5 text-brand-green shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <div className="text-brand-green font-bold font-mono">Ledger Migration Successful!</div>
                    <p className="text-slate-400">Your classical private key was revoked. Funds were securely swept to a quantum-proof SPHINCS+ ledger state.</p>
                    <div className="text-[10px] text-slate-500 font-mono space-y-0.5 pt-1">
                      <div className="truncate">New PQ Address: <span className="text-brand-cyan select-all">{newPqAddress}</span></div>
                      <div className="truncate">Sweep TxID: <span className="text-white select-all">{migrationTxId}</span></div>
                    </div>
                  </div>
                </div>
              )}

            </div>
          )}

        </div>

      </div>

      {/* 3. Transactions Table */}
      <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
        <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-6">
          <span className="w-1.5 h-4 bg-brand-purple rounded-full" />
          Transaction Log History ({addressTxs.length})
        </h2>

        {addressTxs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 font-mono text-xs">
            No transactions found on this address path.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead>
                <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                  <th className="py-3 px-2">TXID</th>
                  <th className="py-3 px-2">Flow</th>
                  <th className="py-3 px-2">Counterparty</th>
                  <th className="py-3 px-2">Value Amount</th>
                  <th className="py-3 px-2">Time</th>
                  <th className="py-3 px-2 text-right">Protection</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-xs">
                {addressTxs.map((tx) => {
                  const isOutgoing = tx.sender === wallet.address;
                  return (
                    <tr 
                      key={tx.txid}
                      onClick={() => onSelectTx(tx.txid)}
                      className="hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer"
                    >
                      <td className="py-3.5 px-2 font-mono text-brand-purple font-semibold">
                        {formatHash(tx.txid, 10)}
                      </td>
                      <td className="py-3.5 px-2">
                        {tx.isSystemTx ? (
                          <span className="px-2 py-0.5 bg-brand-green/10 text-brand-green text-[10px] rounded font-bold uppercase tracking-wider font-mono">
                            Coinbase
                          </span>
                        ) : isOutgoing ? (
                          <span className="flex items-center gap-1 text-brand-red font-mono font-bold uppercase text-[10px]">
                            <ArrowUpRight className="w-3.5 h-3.5" /> Out
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-brand-green font-mono font-bold uppercase text-[10px]">
                            <ArrowDownLeft className="w-3.5 h-3.5" /> In
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-2 font-mono text-slate-500 hover:text-brand-cyan">
                        {tx.isSystemTx 
                          ? 'Coinbase Engine' 
                          : isOutgoing 
                          ? formatHash(tx.receiver, 10) 
                          : formatHash(tx.sender, 10)
                        }
                      </td>
                      <td className={`py-3.5 px-2 font-mono font-bold ${
                        tx.isSystemTx || !isOutgoing ? 'text-brand-green' : 'text-slate-100'
                      }`}>
                        {isOutgoing && !tx.isSystemTx ? '-' : '+'}{parseFloat(tx.amountSpx).toFixed(4)} SPX
                      </td>
                      <td className="py-3.5 px-2 font-mono text-slate-400">
                        {formatTimeAgo(tx.timestamp)}
                      </td>
                      <td className="py-3.5 px-2 text-right font-mono text-slate-400">
                        {tx.signatureScheme}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
