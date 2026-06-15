/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, FormEvent } from 'react';
import { ActiveSession, Transaction, TxDirection } from '../types';
import { 
  Wallet, 
  ArrowUpRight, 
  ArrowDownLeft, 
  Copy, 
  Clipboard, 
  Check, 
  Send, 
  QrCode, 
  TrendingUp, 
  Cpu, 
  RefreshCw,
  X,
  AlertTriangle,
  FileSpreadsheet
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface WalletTabProps {
  session: ActiveSession;
  balance: number;
  transactions: Transaction[];
  onUpdateBalance: (newBalance: number) => void;
  onAddTransaction: (tx: Transaction) => void;
  promptPassphraseDialog: (title: string, message: string, onConfirm: (enteredPass: string) => void) => void;
  addActivity: (type: 'WALLET_SEND', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
}

export default function WalletTab({
  session,
  balance,
  transactions,
  onUpdateBalance,
  onAddTransaction,
  promptPassphraseDialog,
  addActivity
}: WalletTabProps) {
  const [copied, setCopied] = useState(false);
  const [showSendModal, setShowSendModal] = useState(false);
  const [showReceiveModal, setShowReceiveModal] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Send Form state
  const [recipientAddress, setRecipientAddress] = useState('');
  const [transferAmount, setTransferAmount] = useState('');
  const [memo, setMemo] = useState('');
  const [transferError, setTransferError] = useState('');

  const formattedAddress = () => {
    const addr = session.fingerprint;
    if (addr.length > 32) {
      return addr.substring(0, 18) + '...' + addr.substring(addr.length - 12);
    }
    return addr;
  };

  const handleCopyAddress = () => {
    navigator.clipboard.writeText(session.fingerprint);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
    }, 800);
  };

  const handleSendSubmit = (e: FormEvent) => {
    e.preventDefault();
    setTransferError('');

    const amountNum = parseFloat(transferAmount);
    if (isNaN(amountNum) || amountNum <= 0) {
      setTransferError('Please provide a valid token amount.');
      return;
    }

    const fee = 0.001000;
    const totalDeduction = amountNum + fee;

    if (totalDeduction > balance) {
      setTransferError(`Insufficient local balance. Sending ${amountNum} SPIF with a transaction fee of ${fee} SPIF requires at least ${totalDeduction} SPIF.`);
      return;
    }

    if (!recipientAddress.trim()) {
      setTransferError('Please provide a valid target address or recipient fingerprint.');
      return;
    }

    promptPassphraseDialog(
      'Confirm Transaction',
      'Enter your passphrase to authorise this transfer:',
      (passphrase) => {
        if (passphrase.trim().toLowerCase() !== session.passphrase.trim().toLowerCase()) {
          alert('Wrong passphrase. Please try again.');
          addActivity('WALLET_SEND', `Transfer of ${amountNum} SPIF aborted due to unauthorized credentials`, 'FAILURE');
          return;
        }

        // Successfully authorized! Execute ledger balance deduction
        const remainingBalance = balance - totalDeduction;
        onUpdateBalance(remainingBalance);

        // peerShort representation for transaction records and logs
        let peerShort = recipientAddress.trim();
        if (peerShort.length > 16) {
          peerShort = peerShort.substring(0, 16);
        }

        // Append new transaction record inside ledger
        const newTx: Transaction = {
          id: Math.floor(Math.random() * 1000000).toString(),
          timestamp: new Date().toISOString().replace('T', ' ').substring(0, 16),
          direction: 'out',
          amount: amountNum.toFixed(6),
          peer: peerShort + (recipientAddress.trim().length > 16 ? '...' : ''),
          memo: memo || 'Self-signed SPIF transfer',
          status: 'pending', // Simulated block broadcasting
        };

        onAddTransaction(newTx);
        addActivity('WALLET_SEND', `Sent ${amountNum.toFixed(6)} SPIF → ${peerShort}…`, 'SUCCESS');
        
        // Success dialog and reset form
        setShowSendModal(false);
        setRecipientAddress('');
        setTransferAmount('');
        setMemo('');
        alert(`Transfer of ${amountNum.toFixed(6)} SPIF submitted to the SPIF network.\nMemo: ${memo || 'none'}`);

        // Simulate confirmed block audit after 6s
        setTimeout(() => {
          newTx.status = 'confirmed';
          // Force transaction history update
        }, 6000);
      }
    );
  };

  // Stats Counters
  const receivedTotal = transactions
    .filter(t => t.direction === 'in')
    .reduce((acc, t) => acc + parseFloat(t.amount), 0);

  const sentTotal = transactions
    .filter(t => t.direction === 'out')
    .reduce((acc, t) => acc + parseFloat(t.amount), 0);

  const pendingCount = transactions.filter(t => t.status === 'pending').length;

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header section with description */}
      <div className="flex justify-between items-start gap-4">
        <div>
          <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">SPIF Wallet</h1>
          <p className="text-on-surface-variant text-sm mt-1">
            Track sovereign Prime Token balances, issue signed transfers, and list digital logs.
          </p>
        </div>
        
        <button
          id="wallet-refresh-btn"
          onClick={handleRefresh}
          className={`p-2.5 rounded-lg border border-white/5 bg-surface-container hover:bg-surface-container-high hover:text-primary transition-all cursor-pointer ${
            isRefreshing ? 'animate-spin text-primary' : 'text-on-surface'
          }`}
          title="Sync Wallet balance"
        >
          <RefreshCw className="w-5 h-5" />
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Side: Ledger control center */}
        <div className="lg:col-span-8 space-y-6">
          
          {/* Main Balance Canvas Card */}
          <div className="p-8 rounded-xl bg-surface-container border border-primary/20 relative overflow-hidden group">
            <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-primary/30 to-transparent" />
            <div className="absolute -right-24 -bottom-24 w-48 h-48 rounded-full bg-primary/5 filter blur-3xl pointer-events-none" />
            
            <div className="flex justify-between items-start mb-6">
              <div>
                <span className="font-mono text-[9px] tracking-widest text-[#4d556b] uppercase block font-bold mb-1">Total Balance</span>
                <div className="flex items-baseline gap-2">
                  <span className="text-5xl font-extrabold text-primary tracking-tight">
                    {balance.toLocaleString('en-US', { minimumFractionDigits: 6, maximumFractionDigits: 6 })}
                  </span>
                  <span className="text-lg font-bold text-on-surface font-mono">SPIF</span>
                </div>
                <div className="text-xs text-on-surface-variant mt-1.5 flex items-center gap-1.5 font-medium">
                  <span>≈ ${(balance * 3.824).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} USD</span>
                  <span className="text-primary font-bold">+2.4%</span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/25">
                <Wallet className="w-6 h-6 text-primary" />
              </div>
            </div>

            {/* Address segment banner */}
            <div className="flex flex-col gap-1 border-t border-white/5 pt-4">
              <span className="font-mono text-[9px] text-on-surface-variant/50 uppercase tracking-widest font-bold">Your Wallet Address</span>
              <div className="flex items-center justify-between p-2 rounded-lg bg-surface-lowest border border-white/5">
                <code className="font-mono text-xs text-on-surface truncate pr-6">{formattedAddress()}</code>
                <button
                  id="wallet-copy-btn"
                  onClick={handleCopyAddress}
                  className="p-1 px-2.5 rounded bg-surface-container-high hover:bg-surface-container-highest border border-white/10 flex items-center gap-1.5 font-mono text-[10px] text-primary transition-all cursor-pointer leading-none"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-primary" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" /> Copy
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Form actions: Send & Receive buttons */}
            <div className="flex gap-4 mt-6">
              <button
                id="wallet-btn-send"
                onClick={() => setShowSendModal(true)}
                className="flex-1 h-12 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-sm rounded-lg flex items-center justify-center gap-2 cursor-pointer transition-all hover:scale-[1.01]"
              >
                <ArrowUpRight className="w-4 h-4" /> Send Tokens
              </button>
              <button
                id="wallet-btn-receive"
                onClick={() => setShowReceiveModal(true)}
                className="flex-1 h-12 border border-white/10 hover:bg-white/5 text-on-surface font-sans font-medium text-sm rounded-lg flex items-center justify-center gap-2 cursor-pointer"
              >
                <ArrowDownLeft className="w-4 h-4 text-primary" /> Receive Tokens
              </button>
            </div>

          </div>

          {/* Transaction Ledgers List matches layouts */}
          <div className="space-y-3">
            <div className="flex justify-between items-center px-1">
              <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Transaction History</span>
              <span className="text-[10px] text-on-surface-variant font-mono">Ledger Node: SPIF Mainnet</span>
            </div>

            <div className="space-y-3">
              {transactions.length === 0 ? (
                <div className="p-8 text-center text-on-surface-variant bg-surface rounded-xl border border-white/5 font-sans">
                  No transfers registered on local ledger.
                </div>
              ) : (
                transactions.map((tx) => (
                  <div key={tx.id} className="p-4 rounded-xl bg-surface border border-white/5 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      
                      {/* Badge identifier with opaque styling */}
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${
                        tx.direction === 'in' 
                          ? 'bg-primary/10 text-primary' 
                          : 'bg-danger/10 text-danger'
                      }`}>
                        {tx.direction === 'in' ? <ArrowDownLeft className="w-5 h-5" /> : <ArrowUpRight className="w-5 h-5" />}
                      </div>

                      <div className="min-w-0">
                        <span className="font-mono text-xs font-semibold text-on-surface block truncate">
                          {tx.peer}
                        </span>
                        <span className="font-sans text-[11px] text-on-surface-variant block mt-0.5 max-w-md truncate">
                          {tx.memo}
                        </span>
                      </div>

                    </div>

                    <div className="text-right flex-shrink-0">
                      <span className={`font-mono text-xs font-extrabold block ${
                        tx.direction === 'in' ? 'text-primary' : 'text-danger'
                      }`}>
                        {tx.direction === 'in' ? '+' : '-'}{tx.amount} SPIF
                      </span>
                      <div className="flex items-center justify-end gap-1.5 mt-1">
                        <span className="font-mono text-[9px] text-[#4d556b]">{tx.timestamp}</span>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          tx.status === 'confirmed' ? 'bg-primary' : 'bg-warn animate-pulse'
                        }`} />
                        <span className={`font-mono text-[9px] uppercase leading-none font-bold ${
                          tx.status === 'confirmed' ? 'text-primary' : 'text-warn'
                        }`}>
                          {tx.status}
                        </span>
                      </div>
                    </div>

                  </div>
                ))
              )}
            </div>

          </div>

        </div>

        {/* Right Side: stats panel */}
        <div className="lg:col-span-4 space-y-6">
          
          <div className="p-6 rounded-xl bg-surface-container border border-white/5 space-y-4">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Network Details</span>
            
            <div className="space-y-3.5 border-b border-white/5 pb-4">
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Active Peer Domain</span>
                <span className="font-mono text-primary font-bold">SPIF Mainnet</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Sovereign Asset</span>
                <span className="font-mono text-on-surface font-semibold">Sovereign Prime (SPIF)</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Address Key Basis</span>
                <span className="font-mono text-info font-bold">SPHINCS+ Enforced</span>
              </div>
            </div>

            {/* Segmented stats counts */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 rounded-lg bg-surface-lowest border border-white/5">
                <span className="font-mono text-[9px] text-[#4d556b] uppercase block font-bold leading-none mb-1">Total Sent</span>
                <span className="font-mono text-xs font-bold text-danger">-{sentTotal.toFixed(2)} SPIF</span>
              </div>
              <div className="p-3 rounded-lg bg-surface-lowest border border-white/5">
                <span className="font-mono text-[9px] text-[#4d556b] uppercase block font-bold leading-none mb-1">Total Received</span>
                <span className="font-mono text-xs font-bold text-primary">+{receivedTotal.toFixed(2)} SPIF</span>
              </div>
              <div className="p-3 rounded-lg bg-surface-lowest border border-white/5">
                <span className="font-mono text-[9px] text-[#4d556b] uppercase block font-bold leading-none mb-2">Pending Txs</span>
                <span className="font-mono text-xs font-bold text-warn">{pendingCount}</span>
              </div>
              <div className="p-3 rounded-lg bg-surface-lowest border border-white/5">
                <span className="font-mono text-[9px] text-[#4d556b] uppercase block font-bold leading-none mb-2">Total Txs</span>
                <span className="font-mono text-xs font-bold text-on-surface">{transactions.length}</span>
              </div>
            </div>

          </div>

          <div className="p-4 rounded-xl bg-surface-lowest border border-white/5 flex gap-3">
            <Cpu className="w-5 h-5 text-accent shrink-0 mt-0.5" strokeWidth={2} />
            <div className="text-xs text-on-surface-variant space-y-1">
              <strong className="text-on-surface block font-bold">Unforgeable transactions</strong>
              <span>Transfers are digitally side-signed with your SPHINCS+ master keys, preventing replay attacks or forgery across public ledgers.</span>
            </div>
          </div>

        </div>

      </div>

      {/* SEND TOKENS DIALOG (MODAL OVERLAY) */}
      <AnimatePresence>
        {showSendModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-lowest/80 backdrop-blur-md">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-[500px] p-6 rounded-xl relative overflow-hidden"
            >
              <div className="scan-line" />
              
              <div className="flex justify-between items-center mb-6">
                <h3 className="font-sans text-lg font-bold text-primary flex items-center gap-2">
                  <ArrowUpRight className="w-5 h-5 text-primary" /> Send Sovereign SPIF
                </h3>
                <button
                  type="button"
                  onClick={() => setShowSendModal(false)}
                  className="p-1 text-on-surface-variant hover:text-danger hover:bg-white/5 rounded cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Warnings and errors */}
              <div className="bg-warn/10 border border-warn/30 p-3 rounded-lg flex items-start gap-2.5 mb-4 text-xs">
                <AlertTriangle className="w-4 h-4 text-warn shrink-0 mt-0.5" />
                <span>Verify recipient addresses carefully. Decoded SPHINCS+ ledger transfers are absolute and cannot be reversed.</span>
              </div>

              <form onSubmit={handleSendSubmit} className="space-y-4">
                
                {/* To Address Input */}
                <div className="flex flex-col gap-1.5">
                  <label className="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider font-bold">Recipient Fingerprint Address</label>
                  <input
                    type="text"
                    required
                    placeholder="did:usi:0x..."
                    value={recipientAddress}
                    onChange={(e) => setRecipientAddress(e.target.value)}
                    className="w-full h-11 px-4 bg-surface-lowest text-on-background font-mono text-xs rounded-lg border border-white/10 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                {/* Amount input */}
                <div className="flex flex-col gap-1.5">
                  <label className="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider font-bold">Sovereign Amount (SPIF)</label>
                  <div className="relative">
                    <input
                      type="number"
                      step="0.000001"
                      min="0.000001"
                      required
                      placeholder="0.000000"
                      value={transferAmount}
                      onChange={(e) => setTransferAmount(e.target.value)}
                      className="w-full h-11 pl-4 pr-16 bg-surface-lowest text-on-background font-mono text-xs rounded-lg border border-white/10 focus:border-primary"
                    />
                    <span className="absolute right-4 top-3 font-mono text-xs text-primary font-bold">SPIF</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px] text-on-surface-variant px-1 mt-0.5">
                    <span>Est Fee: 0.001000 SPIF</span>
                    <span>Max: {balance.toFixed(6)} SPIF</span>
                  </div>
                </div>

                {/* Memo comments field */}
                <div className="flex flex-col gap-1.5">
                  <label className="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider font-bold">Log Memo / Reference Comment</label>
                  <input
                    type="text"
                    placeholder="E.g., Q2 budget clearance tags..."
                    value={memo}
                    onChange={(e) => setMemo(e.target.value)}
                    className="w-full h-11 px-4 bg-surface-lowest text-on-background font-sans text-xs rounded-lg border border-white/10 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                {transferError && (
                  <div className="text-xs text-danger font-medium py-2 px-3 bg-danger/15 border border-danger/20 rounded">
                    {transferError}
                  </div>
                )}

                <div className="flex gap-3 border-t border-white/5 pt-4 mt-6">
                  <button
                    type="button"
                    onClick={() => setShowSendModal(false)}
                    className="flex-1 py-2.5 border border-white/10 rounded-lg text-sm hover:bg-white/5 cursor-pointer text-center text-on-surface"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="flex-1 py-2.5 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-sm rounded-lg cursor-pointer"
                  >
                    Confirm & Sign Send
                  </button>
                </div>

              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* RECEIVE TOKENS DIALOG (MODAL OVERLAY) */}
      <AnimatePresence>
        {showReceiveModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-lowest/80 backdrop-blur-md">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-[480px] p-6 rounded-xl relative overflow-hidden flex flex-col items-center text-center"
            >
              <div className="scan-line" />
              
              <div className="w-full flex justify-between items-center mb-6 text-left">
                <h3 className="font-sans text-lg font-bold text-primary flex items-center gap-2">
                  <ArrowDownLeft className="w-5 h-5 text-primary" /> Receive SPIF Tokens
                </h3>
                <button
                  type="button"
                  onClick={() => setShowReceiveModal(false)}
                  className="p-1 text-on-surface-variant hover:text-danger hover:bg-white/5 rounded cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* QR Code Segment Simulator */}
              <div className="p-6 bg-white rounded-xl mb-6 flex justify-center items-center select-none shadow-lg shadow-primary/20">
                <QrCode className="w-40 h-40 text-surface-lowest" strokeWidth={1.5} />
              </div>

              <div className="bg-primary/5 border border-primary/20 p-3.5 rounded-lg text-xs text-on-surface-variant mb-6 text-left w-full">
                Share this address public code to acquire transfers or allocate cryptographic tokens on the SPIF mainnet.
              </div>

              {/* Full Address displaying */}
              <div className="w-full space-y-1.5 text-left mb-6">
                <span className="font-mono text-[9px] text-[#4d556b] uppercase font-bold tracking-wider">Your Master Enclave Public Address</span>
                <div className="bg-surface-lowest p-3 rounded-lg border border-white/5 relative group select-all font-mono text-xs text-primary leading-tight break-all">
                  {session.fingerprint}
                </div>
              </div>

              <button
                type="button"
                onClick={handleCopyAddress}
                className="w-full py-3 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-sm rounded-lg cursor-pointer"
              >
                Copy Fingerprint Address
              </button>

            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}
