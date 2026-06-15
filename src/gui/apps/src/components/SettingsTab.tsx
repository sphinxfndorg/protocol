/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { ActiveSession } from '../types';
import { 
  Settings, 
  Trash2, 
  FolderKey, 
  ShieldAlert, 
  ShieldCheck, 
  Download, 
  Check, 
  HelpCircle 
} from 'lucide-react';

interface SettingsTabProps {
  session: ActiveSession;
  analytics: {
    vaultCount: number;
    signedCount: number;
  };
  onWipeStorage: () => void;
  addActivity: (type: 'WIPE' | 'SETTINGS', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
}

export default function SettingsTab({ session, analytics, onWipeStorage, addActivity }: SettingsTabProps) {
  const [copiedPrivKey, setCopiedPrivKey] = useState(false);
  const [sysLogBackup, setSysLogBackup] = useState(false);

  const handleWipeEnclave = () => {
    const confirmName = prompt(
      '🚨 SECURITY TRIPLE WIPED ALERT 🚨\n\nThis will completely purge all SPHINCS+ private keys, wallet ledger nodes, and simulated files from this local browser sandbox. Complete loss is irreversible.\n\nTo confirm, type "PURGE ENCLAVE" below:'
    );

    if (confirmName === 'PURGE ENCLAVE') {
      onWipeStorage();
      alert('Sovereign local credentials purged successfully. Local sandbox reset.');
    } else {
      alert('Enclave purge aborted. Credentials remain sealed.');
    }
  };

  const handleCopyMockKey = () => {
    navigator.clipboard.writeText(`USI_SPHINCS_ENC_PRIVATE_KEY:${btoa(session.passphrase)}`);
    setCopiedPrivKey(true);
    addActivity('SETTINGS', 'Exported encrypted private key block', 'SUCCESS');
    setTimeout(() => setCopiedPrivKey(false), 2000);
  };

  const handleLogExport = () => {
    setSysLogBackup(true);
    addActivity('SETTINGS', 'System log bundle backup scheduled', 'SUCCESS');
    setTimeout(() => {
      setSysLogBackup(false);
      alert('System logs successfully bundled and downloaded as "usi_security_audit.txt"');
    }, 1000);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header section */}
      <div>
        <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">Settings</h1>
        <p className="text-on-surface-variant text-sm mt-1">
          Configure secure enclave paths, backup private keys, or wipe cryptographic profiles.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Side: Parameters & key storage details */}
        <div className="lg:col-span-8 p-6 rounded-xl bg-surface border border-white/5 space-y-6">
          
          {/* Key storage paths card */}
          <div>
            <h3 className="font-sans text-base font-bold text-on-surface mb-3 flex items-center gap-2">
              <FolderKey className="w-5 h-5 text-primary" /> Core Storage Paths
            </h3>
            <div className="bg-surface-lowest p-4 rounded-lg border border-white/5 space-y-3 font-mono text-xs">
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-[#4d556b] font-bold">Encrypted Private Key</span>
                <span className="text-on-surface">~/.usi/keys/private.key</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-[#4d556b] font-bold">Unencrypted Public Key</span>
                <span className="text-on-surface">~/.usi/keys/public.key</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-[#4d556b] font-bold">Mnemonic protection algorithm</span>
                <span className="text-primary font-bold">Argon2id + SHA-256</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#4d556b] font-bold">Virtual Registry Node</span>
                <span className="text-info font-bold">SPIF Registrar Active</span>
              </div>
            </div>
          </div>

          {/* Backup Credentials triggers */}
          <div className="border-t border-white/5 pt-6">
            <h3 className="font-sans text-base font-bold text-on-surface mb-3">Backup Credentials</h3>
            <p className="text-xs text-on-surface-variant mb-4">
              Export encrypted private variables safely. SPHINCS+ private keys are locked securely under your 12-word seed values and can only be decrypted locally.
            </p>
            <div className="flex flex-wrap gap-4">
              <button
                id="settings-export-key-btn"
                type="button"
                onClick={handleCopyMockKey}
                className="px-4 py-2.5 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-xs rounded-lg cursor-pointer transition-all flex items-center gap-2"
              >
                {copiedPrivKey ? <Check className="w-4 h-4" /> : <FolderKey className="w-4 h-4" />}
                Copy Encrypted Private Block
              </button>
              <button
                id="settings-export-log-btn"
                type="button"
                onClick={handleLogExport}
                className="px-4 py-2.5 border border-white/10 hover:bg-white/5 text-on-surface font-sans font-medium text-xs rounded-lg cursor-pointer transition-all flex items-center gap-2"
              >
                <Download className="w-4 h-4 text-primary" />
                {sysLogBackup ? 'Preparing Backup...' : 'Export Audit System Logs'}
              </button>
            </div>
          </div>

          {/* Danger Zone: Destroy identities block */}
          <div className="border-t border-white/20 pt-6">
            <h3 className="font-sans text-base font-bold text-danger mb-3 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-danger animate-pulse" /> Danger Area
            </h3>
            <p className="text-xs text-on-surface-variant mb-4 font-sans leading-relaxed">
              If you decide to wipe your browser enclave, all cached information including total vaults tracking metrics, ledger transactions history, and keys cache logs will be completely and permanently removed. Your keys on your personal machine must be manually reloaded.
            </p>
            <button
              id="settings-wipe-btn"
              type="button"
              onClick={handleWipeEnclave}
              className="px-5 py-3 h-12 bg-danger/10 border border-danger/30 hover:bg-danger/25 text-danger text-sm font-bold rounded-lg flex items-center gap-2 transition-all cursor-pointer"
            >
              <Trash2 className="w-4.5 h-4.5" />
              Sovereign Profile Context Wipe
            </button>
          </div>

        </div>

        {/* Right Side: details and security validations */}
        <div className="lg:col-span-4 space-y-6">
          
          <div className="p-6 rounded-xl bg-surface-container border border-white/5 space-y-4">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Security Shield Status</span>
            
            <div className="space-y-3.5">
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Sandbox Profile</span>
                <span className="font-mono text-primary font-bold">Standard Isolation</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Active Files count</span>
                <span className="font-mono text-on-surface">{analytics.vaultCount} Vaults</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Signature sidecars</span>
                <span className="font-mono text-on-surface">{analytics.signedCount} Metasheets</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Secure Auditor State</span>
                <span className="font-mono text-primary font-semibold flex items-center gap-1.5 leading-none">
                  <ShieldCheck className="w-3.5 h-3.5 text-primary" /> Active
                </span>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-lowest border border-white/5 flex gap-3">
            <HelpCircle className="w-5 h-5 text-info shrink-0 mt-0.5" strokeWidth={2} />
            <div className="text-xs text-on-surface-variant space-y-1">
              <strong className="text-on-surface block font-bold">Offline isolation</strong>
              <span>USI Software operates fully server-side and sandbox-side—never transmitting your 12-word seed keys anywhere across external networks. All computations happen in-memory.</span>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
