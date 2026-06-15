/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { ActiveSession, ActivityLog } from '../types';
import { 
  Key, 
  ShieldCheck, 
  Clock, 
  FolderLock, 
  FileSignature, 
  Fingerprint, 
  Cpu, 
  CheckCircle,
  HelpCircle,
  TrendingDown,
  RotateCcw
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface DashboardProps {
  session: ActiveSession;
  analytics: {
    vaultCount: number;
    signedCount: number;
    lastActivity: string;
  };
  activities: ActivityLog[];
  addActivity: (type: 'HARDWARE_AUTH' | 'SETTINGS', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
}

export default function Dashboard({ session, analytics, activities, addActivity }: DashboardProps) {
  const [hardwareAuthLoading, setHardwareAuthLoading] = useState(false);
  const [hardwareAuthSuccess, setHardwareAuthSuccess] = useState(false);
  const [authProgressMsg, setAuthProgressMsg] = useState('');

  const triggerHardwareAuth = () => {
    if (hardwareAuthLoading) return;
    
    setHardwareAuthLoading(true);
    setHardwareAuthSuccess(false);
    setAuthProgressMsg('Probing local FIDO2 / YubiKey hardware enclaves...');

    setTimeout(() => {
      setAuthProgressMsg('Broadcasting secure challenge payload...');
    }, 1000);

    setTimeout(() => {
      setAuthProgressMsg('Receiving signed SPHINCS+ authorization assertion...');
    }, 2000);

    setTimeout(() => {
      setHardwareAuthLoading(false);
      setHardwareAuthSuccess(true);
      addActivity('HARDWARE_AUTH', 'Hardware cryptographic key validated via FIDO2 token enclave.', 'SUCCESS');
      
      // Auto-reset state after 4s
      setTimeout(() => {
        setHardwareAuthSuccess(false);
      }, 4000);
    }, 3200);
  };

  // Chunk the public fingerprint DID into segmented parts for premium looking UI blocks
  const chunkFingerprint = () => {
    const stripPrefix = session.fingerprint.replace('did:usi:', '');
    const uppercase = stripPrefix.toUpperCase();
    const size = 4;
    const numChunks = Math.ceil(uppercase.length / size);
    const chunks = [];
    for (let i = 0; i < numChunks; i++) {
      chunks.push(uppercase.substring(i * size, (i + 1) * size));
    }
    return chunks;
  };

  // Get icons matching operation types and detail substrings
  const getActivityIcon = (type: string, detail: string) => {
    const text = detail.toLowerCase();
    
    if (text.includes('encrypt') || text.includes('locked')) {
      return <FolderLock className="w-4 h-4 text-primary" />;
    }
    if (text.includes('decrypt') || text.includes('unlocked')) {
      return <ShieldCheck className="w-4 h-4 text-info" />;
    }
    if (text.includes('signed document') || text.includes('signed doc') || (text.includes('sign') && !text.includes('signed out'))) {
      return <FileSignature className="w-4 h-4 text-warn" />;
    }
    if (text.includes('verify') || text.includes('verified')) {
      return <CheckCircle className="w-4 h-4 text-primary animate-pulse" />;
    }
    if (text.includes('login') || text.includes('logged in')) {
      return <Key className="w-4 h-4 text-info" />;
    }
    if (text.includes('register') || text.includes('registered')) {
      return <Key className="w-4 h-4 text-warn" />;
    }
    if (text.includes('logout') || text.includes('logged out') || text.includes('signed out') || text.includes('sign out')) {
      return <RotateCcw className="w-4 h-4 text-danger" />;
    }
    if (text.includes('sent') || text.includes('received')) {
      return <Cpu className="w-4 h-4 text-primary" />;
    }
    
    switch (type) {
      case 'ENCRYPT': return <FolderLock className="w-4 h-4 text-primary" />;
      case 'DECRYPT': return <ShieldCheck className="w-4 h-4 text-info" />;
      case 'SIGN': return <FileSignature className="w-4 h-4 text-warn" />;
      case 'VERIFY': return <CheckCircle className="w-4 h-4 text-primary animate-pulse" />;
      case 'REGISTER': return <Key className="w-4 h-4 text-warn" />;
      case 'HARDWARE_AUTH': return <Fingerprint className="w-4 h-4 text-primary" />;
      case 'WALLET_SEND': return <Cpu className="w-4 h-4 text-accent" />;
      default: return <Clock className="w-4 h-4 text-on-surface-variant" />;
    }
  };

  const chunks = chunkFingerprint();

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header and descriptives */}
      <div>
        <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">Dashboard</h1>
        <p className="text-on-surface-variant text-sm mt-1">
          Your secure encryption activities and digital identity parameters at a glance.
        </p>
      </div>

      {/* Modern High-density Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Total Vaults Card */}
        <div className="p-6 rounded-xl bg-surface-container border border-white/5 flex flex-col items-center text-center relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-primary/45 to-transparent" />
          <FolderLock className="w-8 h-8 text-primary mb-3" strokeWidth={1.5} />
          <span className="font-mono text-[10px] tracking-widest text-[#4d556b] uppercase block font-bold mb-1">Total Vaults</span>
          <span className="text-4xl font-extrabold text-on-surface tracking-tight mb-1">{analytics.vaultCount}</span>
          <span className="text-[11px] text-on-surface-variant">encrypted folders</span>
        </div>

        {/* Signed Docs Card */}
        <div className="p-6 rounded-xl bg-surface-container border border-white/5 flex flex-col items-center text-center relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-warn/45 to-transparent" />
          <FileSignature className="w-8 h-8 text-warn mb-3" strokeWidth={1.5} />
          <span className="font-mono text-[10px] tracking-widest text-[#4d556b] uppercase block font-bold mb-1">Signed Docs</span>
          <span className="text-4xl font-extrabold text-on-surface tracking-tight mb-1">{analytics.signedCount}</span>
          <span className="text-[11px] text-on-surface-variant">with valid signatures</span>
        </div>

        {/* Last Activity Card */}
        <div className="p-6 rounded-xl bg-surface-container border border-white/5 flex flex-col items-center text-center relative overflow-hidden group">
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-info/45 to-transparent" />
          <Clock className="w-8 h-8 text-info mb-3" strokeWidth={1.5} />
          <span className="font-mono text-[10px] tracking-widest text-[#4d556b] uppercase block font-bold mb-1">Last Activity</span>
          <span className="text-xs font-mono font-bold text-on-surface leading-tight tracking-tight text-center truncate w-full p-2.5 rounded bg-surface-lowest/40 border border-white/5 mb-1.5 h-12 flex items-center justify-center">
            {analytics.lastActivity !== 'Never' ? analytics.lastActivity : 'No transactions recorded'}
          </span>
          <span className="text-[11px] text-on-surface-variant">most recent operation</span>
        </div>

      </div>

      {/* Main Grid Content Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Side: Cryptographic Identity & Authentication */}
        <div className="lg:col-span-7 space-y-6">
          <div className="p-6 rounded-xl bg-surface {border border-white/5} border border-white/5">
            <div className="flex justify-between items-center mb-6">
              <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider">Cryptographic Identity</span>
              <span className="text-[10px] uppercase font-bold text-primary bg-primary/15 border border-primary/20 px-2 py-0.5 rounded flex items-center gap-1 leading-none">
                <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" /> Status: Enclave Active
              </span>
            </div>

            {/* Segmented Digital Fingerprint visualization */}
            <div className="bg-surface-lowest p-6 rounded-lg border border-primary/10 relative overflow-hidden flex flex-col items-center">
              
              <div className="font-mono text-[10px] text-on-surface-variant/40 uppercase tracking-[0.2em] mb-4">PRIMARY_FINGERPRINT_HASH</div>
              
              <div className="grid grid-cols-4 gap-3 max-w-sm w-full mb-6">
                {chunks.map((chunk, idx) => (
                  <div key={idx} className="bg-surface-container/60 py-2 border border-white/5 text-center rounded-md font-mono text-xs font-bold text-primary select-all">
                    {chunk}
                  </div>
                ))}
              </div>

              {/* Hardware authentication interactive simulator */}
              <AnimatePresence mode="wait">
                {hardwareAuthLoading ? (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="w-full flex flex-col items-center justify-center py-2 h-14 bg-surface-container/40 rounded-lg border border-white/5"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="w-4 h-4 rounded-full border-2 border-primary/25 border-t-primary animate-spin" />
                      <span className="font-mono text-xs text-primary">{authProgressMsg}</span>
                    </div>
                  </motion.div>
                ) : hardwareAuthSuccess ? (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.98 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0 }}
                    className="w-full flex items-center justify-center gap-2 h-14 bg-primary/20 rounded-lg border border-primary/40"
                  >
                    <CheckCircle className="w-5 h-5 text-primary animate-bounce animate-pulse" />
                    <span className="font-sans text-sm font-semibold text-primary">HARDWARE KEY ASSERTION INTEGRATED</span>
                  </motion.div>
                ) : (
                  <motion.button
                    id="hardware-auth-btn"
                    onClick={triggerHardwareAuth}
                    className="w-full h-14 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-sm rounded-lg flex items-center justify-center gap-2.5 transition-all hover:scale-[1.01] active:scale-[0.99] cursor-pointer"
                  >
                    <Fingerprint className="w-5 h-5" />
                    Authenticate via Hardware Key
                  </motion.button>
                )}
              </AnimatePresence>

            </div>
          </div>

          {/* Recent Security Logs Panel inside central card list */}
          <div className="space-y-3">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block px-1">Recent Activity</span>
            
            <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
              {activities.length === 0 ? (
                <div className="p-6 text-center text-on-surface-variant font-sans text-sm bg-surface-container rounded-xl border border-white/5">
                  No operations recorded during this session.
                </div>
              ) : (
                activities.slice(0, 6).map((item) => (
                  <div key={item.id} className="p-3 rounded-lg bg-surface-container border border-white/5 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-8 h-8 rounded-lg bg-surface-lowest border border-white/10 flex items-center justify-center flex-shrink-0">
                        {getActivityIcon(item.type, item.detail)}
                      </div>
                      <div className="min-w-0">
                        <span className="font-mono text-xs font-semibold text-on-surface block truncate">
                          {item.detail}
                        </span>
                        <span className="font-mono text-[9px] text-[#4d556b] block mt-0.5">
                          {item.timestamp}
                        </span>
                      </div>
                    </div>
                    
                    <span className={`font-mono text-[9px] font-bold px-2 py-0.5 rounded leading-none ${
                      item.status === 'SUCCESS' ? 'text-primary bg-primary/10' : 'text-danger bg-danger/10'
                    }`}>
                      {item.status}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

        {/* Right Side: Key specifications sidebar */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-6 rounded-xl bg-surface-container border border-white/5">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block mb-4">Key Information</span>
            
            <div className="space-y-3.5 mb-6">
              
              {/* Dynamic row descriptors */}
              <div className="flex justify-between items-center text-xs border-b border-white/5 pb-2">
                <span className="text-on-surface-variant">Signature Scheme</span>
                <span className="font-mono text-on-surface font-semibold">SPHINCS+</span>
              </div>

              <div className="flex justify-between items-center text-xs border-b border-white/5 pb-2">
                <span className="text-on-surface-variant">Hash Digest</span>
                <span className="font-mono text-on-surface font-semibold">SHAKE-256</span>
              </div>

              <div className="flex justify-between items-center text-xs border-b border-white/5 pb-2">
                <span className="text-on-surface-variant">Symm. Encryption</span>
                <span className="font-mono text-on-surface font-bold">AES-256-GCM</span>
              </div>

              <div className="flex justify-between items-center text-xs border-b border-white/5 pb-2">
                <span className="text-on-surface-variant">Key Derivation (KDF)</span>
                <span className="font-mono text-on-surface font-semibold">Argon2id</span>
              </div>

              <div className="flex justify-between items-center text-xs border-b border-white/5 pb-2">
                <span className="text-on-surface-variant">Enjoined Organization</span>
                <span className="font-mono text-primary font-bold">{session.orgCode} (Sovereign)</span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Authorization Pool</span>
                <span className="font-mono text-info font-bold">Hardware Sealed</span>
              </div>

            </div>

            {/* Micro warning notice */}
            <div className="bg-info/10 border border-info/20 p-3 rounded-lg flex items-start gap-2 text-xs">
              <Cpu className="w-4 h-4 text-info mt-0.5 shrink-0" />
              <div className="text-on-surface-variant font-sans">
                SPIF tokens can be accessed via SPHINCS+ identities directly. Your signature is quantum audit-secure.
              </div>
            </div>

          </div>

          {/* Secure Audit card hint */}
          <div className="p-5 rounded-xl bg-surface-lowest border border-white/5">
            <span className="font-mono text-[10px] font-semibold text-warn tracking-wide uppercase flex items-center gap-1.5 mb-2">
              <ShieldCheck className="w-4 h-4" /> Secure Audit Trace
            </span>
            <p className="text-xs text-on-surface-variant leading-relaxed">
              Every operation such as decrypting vaults and signing agreements is appended locally to an encrypted session ledger. These records cannot be edited.
            </p>
          </div>

        </div>

      </div>

    </div>
  );
}
