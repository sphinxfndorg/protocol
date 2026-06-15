/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { ActiveSession } from '../types';
import { 
  Key, 
  ShieldCheck, 
  Copy, 
  Check, 
  Info, 
  Lock, 
  Globe, 
  Database 
} from 'lucide-react';

interface KeysTabProps {
  session: ActiveSession;
  analytics: {
    vaultCount: number;
    signedCount: number;
  };
  addActivity: (type: 'SETTINGS', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
}

export default function KeysTab({ session, analytics, addActivity }: KeysTabProps) {
  const [copiedFp, setCopiedFp] = useState(false);
  const [copiedSecToken, setCopiedSecToken] = useState(false);

  const handleCopyFp = () => {
    navigator.clipboard.writeText(session.fingerprint);
    setCopiedFp(true);
    addActivity('SETTINGS', 'Copied full SPHINCS+ public key identifier', 'SUCCESS');
    setTimeout(() => setCopiedFp(false), 2000);
  };

  const handleCopySecToken = () => {
    navigator.clipboard.writeText(`USI_SPHINCS_ENCLAVE_PUB:${btoa(session.fingerprint + ':' + session.orgCode)}`);
    setCopiedSecToken(true);
    addActivity('SETTINGS', 'Exported secure identity token public payload', 'SUCCESS');
    setTimeout(() => setCopiedSecToken(false), 2000);
  };

  // Segments display of full fingerprint hash did:usi:0x... e.g.:
  // did:usi:0x4FB392D6  ·  8F123C4D  ·  9923838E  ·  92938EEA
  const formattedSegmentFingerprint = () => {
    const stripPrefix = session.fingerprint.replace('did:usi:', '');
    const uppercase = stripPrefix.toUpperCase();
    const size = 8;
    const numChunks = Math.ceil(uppercase.length / size);
    const chunks = [];
    for (let i = 0; i < numChunks; i++) {
      chunks.push(uppercase.substring(i * size, (i + 1) * size));
    }
    return `did:usi:${chunks.join(' · ')}`;
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header section */}
      <div>
        <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">My Keys</h1>
        <p className="text-on-surface-variant text-sm mt-1">
          Review, backup, and test your credentials and SPHINCS+ public fingerprint configurations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Side: Key identifiers profiles */}
        <div className="lg:col-span-8 p-6 rounded-xl bg-surface border border-white/5 space-y-6">
          
          {/* Public Fingerprint displaying */}
          <div className="space-y-3">
            <span className="font-mono text-[10px] font-bold text-[#4d556b] uppercase tracking-wider block">Public Fingerprint DID</span>
            
            <div className="bg-surface-lowest p-6 rounded-lg border border-primary/20 relative">
              <div className="absolute top-0 right-0 p-2 text-primary/10">
                <Globe className="w-12 h-12" />
              </div>
              <code className="font-mono text-xs text-primary leading-relaxed block break-all select-all font-semibold mb-4">
                {formattedSegmentFingerprint()}
              </code>
              <button
                id="keys-copy-fp-btn"
                onClick={handleCopyFp}
                className="py-2 px-4 rounded-lg bg-surface-container hover:bg-surface-container-high border border-white/10 font-sans text-xs font-semibold text-primary flex items-center gap-2 transition-all cursor-pointer"
              >
                {copiedFp ? <Check className="w-4 h-4 text-primary animate-pulse" /> : <Copy className="w-4 h-4" />}
                Copy Fingerprint Address
              </button>
            </div>
          </div>

          <hr className="border-white/5" />

          {/* Key Parameters metrics */}
          <div className="space-y-3">
            <span className="font-mono text-[10px] font-bold text-[#4d556b] uppercase tracking-wider block">Key Parameters</span>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              {[
                { label: 'Associated Organization', value: `${session.orgCode} (Sovereign)`, col: 'text-primary' },
                { label: 'Signature Scheme Basis', value: 'SPHINCS+ (Post-Quantum)', col: 'text-on-surface' },
                { label: 'Hash Digest Format', value: 'SHAKE-256 (SHA-3 family)', col: 'text-on-surface' },
                { label: 'Symmetric Cryptography', value: 'AES-256-GCM', col: 'text-info font-bold' },
                { label: 'Key Derivation Function', value: 'Argon2id (Hardened)', col: 'text-on-surface' },
                { label: 'Security Profile State', value: 'Hardware Vault Sealed', col: 'text-primary font-bold' },
              ].map((param, idx) => (
                <div key={idx} className="p-4 rounded-lg bg-surface-lowest border border-white/5">
                  <span className="font-mono text-[9px] uppercase font-bold text-[#4d556b] block mb-1">{param.label}</span>
                  <span className={`text-xs font-bold leading-none ${param.col}`}>{param.value}</span>
                </div>
              ))}

            </div>
          </div>

          <hr className="border-white/5" />

          {/* Key Storage system locations */}
          <div className="p-4 rounded-lg bg-surface-lowest border border-white/5">
            <span className="font-mono text-[10px] font-bold text-primary uppercase tracking-wider block mb-3">Key Storage Context</span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-xs text-on-surface-variant font-mono">
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span>Private key</span>
                <span className="text-on-surface font-semibold">~/.usi/keys/private.key</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span>Public key</span>
                <span className="text-on-surface font-semibold">~/.usi/keys/public.key</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span>Key Directory</span>
                <span className="text-on-surface font-semibold">~/.usi/keys</span>
              </div>
              <div className="flex justify-between">
                <span>Key Seed protection</span>
                <span className="text-primary font-bold">12 Words Passphrase</span>
              </div>
            </div>
          </div>

        </div>

        {/* Right Side: details and security advices */}
        <div className="lg:col-span-4 space-y-6">
          
          <div className="p-6 rounded-xl bg-surface-container border border-white/5 space-y-4">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Identity Statistics</span>
            
            <div className="space-y-3.5">
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Active DID</span>
                <span className="font-mono text-primary font-bold select-all">SPIF Enrolled</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Encrypted Files</span>
                <span className="font-mono text-on-surface">{analytics.vaultCount} Vaults</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Digital Signatures</span>
                <span className="font-mono text-on-surface">{analytics.signedCount} Metasheets</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Hardware Token Binding</span>
                <span className="font-mono text-primary font-semibold flex items-center gap-1.5 leading-none">
                  <ShieldCheck className="w-3.5 h-3.5" /> FIDO2 Ready
                </span>
              </div>
            </div>

            <button
              id="keys-export-token-btn"
              onClick={handleCopySecToken}
              className="mt-2 w-full py-2 bg-surface-lowest hover:bg-surface-container/50 text-xs font-semibold text-primary border border-primary/20 rounded flex justify-center items-center gap-1.5 cursor-pointer"
            >
              {copiedSecToken ? <Check className="w-3.5 h-3.5" /> : <Database className="w-3.5 h-3.5" />}
              Export Public Identity Token
            </button>
          </div>

          <div className="p-4 rounded-xl bg-surface-lowest border border-white/5 flex gap-3">
            <Info className="w-5 h-5 text-info shrink-0 mt-0.5" strokeWidth={2} />
            <div className="text-xs text-on-surface-variant space-y-1">
              <strong className="text-on-surface block font-bold">Quantum secure signatures</strong>
              <span>SPHINCS+ is a stateless post-quantum hash-based signature scheme. Unlike RSA or Elliptic Curves, it is mathematically immune to breakthroughs in quantum computer processors.</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-lowest border border-white/5 flex gap-3">
            <Lock className="w-5 h-5 text-warn shrink-0 mt-0.5" strokeWidth={2} />
            <div className="text-xs text-on-surface-variant space-y-1">
              <strong className="text-on-surface block font-bold">Seed backup safeguard</strong>
              <span>If you damage your recovery seed word sheet copies, there are no remote databases holding backups—we cannot restore your identity folder keys.</span>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
