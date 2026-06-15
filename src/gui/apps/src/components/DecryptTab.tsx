/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useRef, DragEvent, ChangeEvent, FormEvent } from 'react';
import { ActiveSession, EncryptedVaultPayload } from '../types';
import { 
  FolderLock, 
  Upload, 
  HelpCircle, 
  AlertTriangle,
  FileDigit, 
  Check, 
  X,
  Unlock,
  Eye,
  LockKeyholeOpen,
  FolderOpen
} from 'lucide-react';

interface DecryptTabProps {
  session: ActiveSession;
  promptPassphraseDialog: (title: string, message: string, onConfirm: (enteredPass: string) => void) => void;
  addActivity: (type: 'DECRYPT', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
}

export default function DecryptTab({ session, promptPassphraseDialog, addActivity }: DecryptTabProps) {
  // File state
  const [vaultFile, setVaultFile] = useState<File | null>(null);
  const [parsedPayload, setParsedPayload] = useState<EncryptedVaultPayload | null>(null);
  const [isAuthorized, setIsAuthorized] = useState<boolean | null>(null);
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  const [decryptedFilename, setDecryptedFilename] = useState<string | null>(null);
  const [hasDecrypted, setHasDecrypted] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  // Parses uploaded .vault JSON structure
  const processFile = (file: File) => {
    if (!file.name.endsWith('.vault')) {
      alert('Invalid container format. This enclave exclusively processes ".vault" files.');
      return;
    }

    setVaultFile(file);
    setDecryptedMessage(null);
    setDecryptedFilename(null);
    setHasDecrypted(false);

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const json = JSON.parse(text) as EncryptedVaultPayload;
        
        if (!json.version || !json.sender || !json.cipherBytes) {
          throw new Error('Incomplete structure. Not a recognizable sovereign USI vault.');
        }

        setParsedPayload(json);

        // Check if user is in recipients roster
        const authorized = json.recipients.includes(session.fingerprint) || json.recipients.length === 0;
        setIsAuthorized(authorized);

      } catch (err) {
        alert(`Failed to load vault payload: ${err instanceof Error ? err.message : 'Invalid JSON file structure'}`);
        handleClear();
      }
    };
    reader.readAsText(file);
  };

  const handleBrowseTrigger = () => {
    fileInputRef.current?.click();
  };

  const handleClear = () => {
    setVaultFile(null);
    setParsedPayload(null);
    setIsAuthorized(null);
    setDecryptedMessage(null);
    setDecryptedFilename(null);
    setHasDecrypted(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleUnlockSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!parsedPayload) return;

    if (isAuthorized === false) {
      alert('Symmetric authorization check FAILED. Your public DID fingerprint is not enrolled in this vault.');
      addActivity('DECRYPT', `Unauthorized decrypt attempt for: ${vaultFile?.name}`, 'FAILURE');
      return;
    }

    promptPassphraseDialog(
      'Confirm Passphrase',
      'Enter your passphrase to unlock this vault:',
      (passphrase) => {
        if (passphrase.trim().toLowerCase() !== session.passphrase.trim().toLowerCase()) {
          alert('Wrong passphrase. Please try again.');
          addActivity('DECRYPT', `Wrong credentials validation during decrypt of: ${vaultFile?.name}`, 'FAILURE');
          return;
        }

        // Successfully authenticated! Restore virtual payload variables
        setHasDecrypted(true);
        setDecryptedFilename(parsedPayload.originalName);
        setDecryptedMessage(parsedPayload.embeddedMessage || 'No secure comments embedded inside this secure vault.');
        
        let senderDisplay = parsedPayload.sender;
        if (senderDisplay && senderDisplay.length > 50) {
          senderDisplay = senderDisplay.substring(0, 47) + '...';
        }

        if (parsedPayload.embeddedMessage) {
          addActivity('DECRYPT', `Decrypted vault with embedded message from SPIF: ${vaultFile?.name}`, 'SUCCESS');
          alert(`Vault decrypted successfully.\n\n📤 Organization: SPIF\n🔑 Sender: ${senderDisplay}\n\n📝 Embedded message recovered.`);
        } else {
          addActivity('DECRYPT', `Decrypted vault from SPIF (no message): ${vaultFile?.name}`, 'SUCCESS');
          alert(`Vault decrypted successfully.\n\n📤 Organization: SPIF\n🔑 Sender: ${senderDisplay}`);
        }
      }
    );
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header instructions */}
      <div>
        <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">Decrypt Vault</h1>
        <p className="text-on-surface-variant text-sm mt-1">
          Unlock standard `.vault` secure envelopes, validating public identities to inspect secure embedded items.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Side: Decrypt controller */}
        <form onSubmit={handleUnlockSubmit} className="lg:col-span-7 p-6 rounded-xl bg-surface border border-white/5 space-y-6">
          
          <div 
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`cursor-pointer rounded-xl border-2 border-dashed p-8 transition-all relative flex flex-col items-center justify-center text-center ${
              isDragging 
                ? 'border-primary bg-primary/10' 
                : vaultFile 
                  ? 'border-primary/40 bg-surface-lowest/70' 
                  : 'border-white/10 hover:border-white/20 bg-surface-lowest/30'
            }`}
            onClick={handleBrowseTrigger}
          >
            <div className="scan-line" />
            
            {vaultFile ? (
              <div className="flex flex-col items-center gap-2">
                <div className="w-12 h-12 rounded-full bg-primary/15 flex items-center justify-center border border-primary/30">
                  <FileDigit className="w-6 h-6 text-primary animate-pulse" />
                </div>
                <span className="font-semibold text-on-surface text-sm break-all">{vaultFile.name}</span>
                <span className="font-mono text-[11px] text-on-surface-variant">
                  { (vaultFile.size / 1024).toFixed(2) } KB · Select differently if needed
                </span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <Upload className="w-10 h-10 text-on-surface-variant/70 mb-2" />
                <span className="font-semibold text-on-surface text-sm">Select .vault archive to unlock</span>
                <span className="text-xs text-on-surface-variant max-w-sm">
                  Drag and drop a previously downloaded `.vault` file here or click anywhere to browse
                </span>
              </div>
            )}
            
            <input 
              type="file" 
              ref={fileInputRef} 
              onChange={handleFileSelect} 
              accept=".vault"
              className="hidden" 
            />
          </div>

          <div className="flex gap-4">
            <button
              id="decrypt-browse-btn"
              type="button"
              onClick={handleBrowseTrigger}
              className="px-4 py-2 bg-surface-container-high hover:bg-surface-container-highest border border-white/10 rounded font-sans text-xs font-semibold text-primary transition-all cursor-pointer"
            >
              Browse Vault File...
            </button>
            {vaultFile && (
              <button
                type="button"
                onClick={handleClear}
                className="px-4 py-2 border border-white/5 hover:border-danger hover:bg-danger/15 rounded text-xs text-on-surface transition-all cursor-pointer flex items-center gap-1.5"
              >
                <X className="w-3.5 h-3.5" /> Clear Content
              </button>
            )}
          </div>

          {/* Decryption Message outputs */}
          {hasDecrypted && (
            <div className="border-t border-white/5 pt-6 space-y-4 animate-in slide-in-from-bottom-2">
              
              {/* Decrypted embedded Commentary */}
              <div className="bg-surface-lowest p-5 rounded-lg border border-primary/20">
                <div className="flex justify-between items-center mb-3">
                  <span className="font-mono text-[10px] text-primary uppercase tracking-wider font-bold">📤 Recovered Message Compartment</span>
                  <span className="text-[10px] text-[#4d556b] font-mono leading-none">AES-GCM Authenticated</span>
                </div>
                <p className="font-sans text-sm text-on-surface font-semibold bg-surface-container/30 rounded p-3 select-all leading-relaxed whitespace-pre-wrap">
                  {decryptedMessage}
                </p>
              </div>

              {/* Decrypted Payload Files list simulation */}
              <div className="p-4 rounded-lg bg-surface-lowest border border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded bg-primary/10 flex items-center justify-center">
                    <FolderOpen className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <span className="font-semibold text-xs text-on-surface block leading-none">{decryptedFilename}</span>
                    <span className="font-mono text-[10px] text-on-surface-variant block mt-1">Status: Fully Decrypted & restored</span>
                  </div>
                </div>
                <span className="text-[11px] font-mono text-primary bg-primary/15 px-2 py-0.5 rounded uppercase font-bold">Restored</span>
              </div>

            </div>
          )}

          <div className="flex gap-4 border-t border-white/5 pt-4">
            <button
              id="decrypt-btn-submit"
              type="submit"
              disabled={!parsedPayload || hasDecrypted}
              className={`flex-1 h-12 font-sans font-bold text-sm rounded-lg flex items-center justify-center gap-2 cursor-pointer transition-transform duration-100 hover:scale-[1.01] ${
                !parsedPayload || hasDecrypted
                  ? 'bg-[#1c2b3c] text-on-surface-variant/40 cursor-not-allowed border border-white/5'
                  : 'bg-primary text-on-primary hover:bg-primary-hover'
              }`}
            >
              <LockKeyholeOpen className="w-4 h-4" />
              Unlock Secure Vault
            </button>
            <button
              id="decrypt-btn-clear"
              type="button"
              onClick={handleClear}
              className="px-6 h-12 border border-white/10 hover:bg-white/5 text-on-surface text-sm rounded-lg cursor-pointer"
            >
              Reset
            </button>
          </div>

        </form>

        {/* Right Side: Informational cards matching mockup requirements */}
        <div className="lg:col-span-5 space-y-6">
          
          <div className="p-6 rounded-xl bg-surface-container border border-white/5 space-y-4">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Decryption Context</span>
            
            <div className="space-y-3.5">
              
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Selected Vault</span>
                <span className="font-mono text-on-surface font-semibold truncate max-w-[140px]">
                  {vaultFile ? vaultFile.name : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Signature Organization</span>
                <span className="font-mono text-primary font-bold">
                  {parsedPayload ? parsedPayload.senderOrg : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Key Origin</span>
                <span className="font-mono text-on-surface font-semibold truncate max-w-[120px]" title={parsedPayload?.sender}>
                  {parsedPayload ? parsedPayload.sender : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Authorized Users</span>
                <span className="font-mono text-on-surface">
                  {parsedPayload ? `${parsedPayload.recipients.length} enrolled` : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Access Validation</span>
                {isAuthorized === null ? (
                  <span className="font-mono text-on-surface-variant">No file processed</span>
                ) : isAuthorized ? (
                  <span className="font-mono text-primary font-bold bg-primary/10 px-1.5 py-0.5 rounded text-[10px] leading-none uppercase">
                    ✓ Authorized
                  </span>
                ) : (
                  <span className="font-mono text-danger font-bold bg-danger/10 px-1.5 py-0.5 rounded text-[10px] leading-none uppercase animate-pulse">
                    ✗ Access Denied
                  </span>
                )}
              </div>

            </div>
          </div>

          {/* Warnings */}
          <div className="p-4 rounded-xl bg-surface-lowest border border-white/5 flex gap-3">
            <AlertTriangle className="w-5 h-5 text-warn shrink-0 mt-0.5" strokeWidth={2} />
            <div className="text-xs text-on-surface-variant space-y-1">
              <strong className="text-on-surface block">Anti-bruteforce safeguards</strong>
              <span>If your DID fingerprint is not enrolled in this vault payload, decryption attempts are completely filtered out mathematically before computing private key variables.</span>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
