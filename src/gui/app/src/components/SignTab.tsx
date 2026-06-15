/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useRef, DragEvent, ChangeEvent, FormEvent } from 'react';
import { ActiveSession, SignatureMetadata } from '../types';
import { 
  FileSignature, 
  Upload, 
  HelpCircle, 
  AlertTriangle,
  FileText, 
  Check, 
  X,
  FileCheck,
  CheckCircle2
} from 'lucide-react';

interface SignTabProps {
  session: ActiveSession;
  promptPassphraseDialog: (title: string, message: string, onConfirm: (enteredPass: string) => void) => void;
  addActivity: (type: 'SIGN', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
  onIncrementSigned: () => void;
}

// Generates a mock but structured SPHINCS+ public block signature
function generateSphincsSignatureBlock(hash: string): string {
  const parts = [];
  for (let i = 0; i < 4; i++) {
    let sub = '';
    for (let j = 0; j < 32; j++) {
      sub += Math.floor(Math.random() * 16).toString(16).toUpperCase();
    }
    parts.push(sub);
  }
  return `SPHINCS_SIG_BLOCK:v2_4_SHAKE_256#${parts.join('\n')}`;
}

export default function SignTab({ session, promptPassphraseDialog, addActivity, onIncrementSigned }: SignTabProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileDetails, setFileDetails] = useState<{ size: string; modTime: string } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [hasSigned, setHasSigned] = useState(false);
  const [signatureInfo, setSignatureInfo] = useState<SignatureMetadata | null>(null);

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
      loadDocument(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      loadDocument(e.target.files[0]);
    }
  };

  const loadDocument = (file: File) => {
    setSelectedFile(file);
    setHasSigned(false);
    setSignatureInfo(null);
    
    const sizeMB = (file.size / (1024 * 1024)).toFixed(4);
    const modDate = file.lastModified 
      ? new Date(file.lastModified).toISOString().replace('T', ' ').substring(0, 16)
      : new Date().toISOString().replace('T', ' ').substring(0, 16);

    setFileDetails({
      size: `${sizeMB} MB`,
      modTime: modDate
    });
  };

  const handleBrowseTrigger = () => {
    fileInputRef.current?.click();
  };

  const handleClear = () => {
    setSelectedFile(null);
    setFileDetails(null);
    setHasSigned(false);
    setSignatureInfo(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSignSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!selectedFile || !fileDetails) {
      alert('Please select a local document payload first.');
      return;
    }

    promptPassphraseDialog(
      'Confirm Passphrase',
      'Enter your passphrase to sign this document:',
      (passphrase) => {
        if (passphrase.trim().toLowerCase() !== session.passphrase.trim().toLowerCase()) {
          alert('Wrong passphrase. Please try again.');
          addActivity('SIGN', `Unauthorized digital signing attempt for file: ${selectedFile.name}`, 'FAILURE');
          return;
        }

        // Create SHA-256 equivalent stable hash representation of file
        const hashSeed = `${selectedFile.size}_${selectedFile.name}_${selectedFile.lastModified}`;
        let mockHash = 0;
        for (let i = 0; i < hashSeed.length; i++) {
          mockHash = (mockHash * 31 + hashSeed.charCodeAt(i)) | 0;
        }
        const sha256Equivalent = Math.abs(mockHash).toString(16).padEnd(32, '0').toUpperCase().substring(0, 32);

        const metadata: SignatureMetadata = {
          version: 'v2.4.0-STABLE',
          signer: session.fingerprint,
          orgCode: session.orgCode,
          timestamp: Math.floor(Date.now() / 1000),
          documentTitle: selectedFile.name,
          sha256Hash: sha256Equivalent,
          signatureString: generateSphincsSignatureBlock(sha256Equivalent),
        };

        // File download of digital certificate sidecar .usimeta
        const jsonString = JSON.stringify(metadata, null, 2);
        const element = document.createElement('a');
        const fileBlob = new Blob([jsonString], { type: 'application/json' });
        element.href = URL.createObjectURL(fileBlob);
        element.download = `${selectedFile.name}.usimeta`;
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);

        // Update states
        setHasSigned(true);
        setSignatureInfo(metadata);
        onIncrementSigned();
        addActivity('SIGN', `Signed document: ${selectedFile.name}`, 'SUCCESS');
        alert(`Document signed successfully.\nSignature saved as: ${selectedFile.name}.usimeta`);
      }
    );
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header section with instruction details */}
      <div>
        <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">Sign Document</h1>
        <p className="text-on-surface-variant text-sm mt-1">
          Seal any document structure with your SPHINCS+ quantum-resistant signature, generating readable `.usimeta` sidecars.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        
        {/* Left Side: Drag-drop signing controls */}
        <form onSubmit={handleSignSubmit} className="lg:col-span-7 p-6 rounded-xl bg-surface border border-white/5 space-y-6">
          
          <div 
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`cursor-pointer rounded-xl border-2 border-dashed p-8 transition-all relative flex flex-col items-center justify-center text-center ${
              isDragging 
                ? 'border-primary bg-primary/10' 
                : selectedFile 
                  ? 'border-primary/40 bg-surface-lowest/70' 
                  : 'border-white/10 hover:border-white/20 bg-surface-lowest/30'
            }`}
            onClick={handleBrowseTrigger}
          >
            <div className="scan-line animate-pulse" />
            
            {selectedFile ? (
              <div className="flex flex-col items-center gap-2">
                <div className="w-12 h-12 rounded-full bg-primary/15 flex items-center justify-center border border-primary/30">
                  <FileText className="w-6 h-6 text-primary animate-pulse" />
                </div>
                <span className="font-semibold text-on-surface text-sm break-all">{selectedFile.name}</span>
                <span className="font-mono text-[11px] text-on-surface-variant">
                  { fileDetails ? fileDetails.size : '—' } · Ready to sign
                </span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <Upload className="w-10 h-10 text-on-surface-variant/70 mb-2" />
                <span className="font-semibold text-on-surface text-sm">Select document to sign</span>
                <span className="text-xs text-on-surface-variant max-w-sm">
                  Drag and drop local files (PDF, DOC, TXT, XML, etc.) here or click explorer
                </span>
              </div>
            )}
            
            <input 
              type="file" 
              ref={fileInputRef} 
              onChange={handleFileSelect} 
              className="hidden" 
            />
          </div>

          <div className="flex gap-4">
            <button
              id="sign-browse-btn"
              type="button"
              onClick={handleBrowseTrigger}
              className="px-4 py-2 bg-surface-container-high hover:bg-surface-container-highest border border-white/10 rounded font-sans text-xs font-semibold text-primary transition-all cursor-pointer"
            >
              Browse Document File...
            </button>
            {selectedFile && (
              <button
                type="button"
                onClick={handleClear}
                className="px-4 py-2 border border-white/5 hover:border-danger hover:bg-danger/15 rounded text-xs text-on-surface transition-all cursor-pointer flex items-center gap-1.5"
              >
                <X className="w-3.5 h-3.5" /> Reset Document Selection
              </button>
            )}
          </div>

          {/* SPHINCS+ Metasheet Output Block */}
          {hasSigned && signatureInfo && (
            <div className="border-t border-white/5 pt-6 space-y-4 animate-in slide-in-from-bottom-2">
              <div className="bg-surface-lowest p-5 rounded-lg border border-primary/20 relative">
                
                <div className="flex justify-between items-center mb-4">
                  <span className="font-mono text-[9px] text-[#4d556b] uppercase tracking-wider font-bold">SPHINCS_METADATA_JSON_BLOCK</span>
                  <span className="text-[10px] text-primary bg-primary/10  px-1.5 py-0.5 rounded flex items-center gap-1 leading-none font-bold">
                    <CheckCircle2 className="w-3.5 h-3.5 text-primary" /> Signature Sealed
                  </span>
                </div>

                <div className="space-y-2 font-mono text-[11px] text-on-surface">
                  <div><strong>"version":</strong> "{signatureInfo.version}"</div>
                  <div><strong>"signer":</strong> "{signatureInfo.signer}"</div>
                  <div className="truncate"><strong>"documentSha256":</strong> "{signatureInfo.sha256Hash}"</div>
                  <div className="text-xs font-semibold text-on-surface-variant mt-3 block pb-1 border-b border-white/5 uppercase">Cryptographic Signature String</div>
                  <pre className="text-[10px] text-primary leading-tight overflow-x-auto whitespace-pre p-2 bg-surface-container/30 rounded mt-1 select-all font-mono">
                    {signatureInfo.signatureString}
                  </pre>
                </div>

              </div>
            </div>
          )}

          <div className="flex gap-4 border-t border-white/5 pt-4">
            <button
              id="sign-btn-submit"
              type="submit"
              disabled={!selectedFile || hasSigned}
              className={`flex-1 h-12 font-sans font-bold text-sm rounded-lg flex items-center justify-center gap-2 cursor-pointer transition-transform duration-100 hover:scale-[1.01] ${
                !selectedFile || hasSigned
                  ? 'bg-[#1c2b3c] text-on-surface-variant/40 cursor-not-allowed border border-white/5'
                  : 'bg-primary text-on-primary hover:bg-primary-hover'
              }`}
            >
              <FileCheck className="w-4 h-4" />
              Sign Document Enclave
            </button>
            <button
              id="sign-btn-clear"
              type="button"
              onClick={handleClear}
              className="px-6 h-12 border border-white/10 hover:bg-white/5 text-on-surface text-sm rounded-lg cursor-pointer"
            >
              Clear Form
            </button>
          </div>

        </form>

        {/* Right Side: Informational panels matching mockup and Go code layout */}
        <div className="lg:col-span-5 space-y-6">
          
          <div className="p-6 rounded-xl bg-surface-container border border-white/5 space-y-4">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Signature Details</span>
            
            <div className="space-y-3.5">
              
              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Active File</span>
                <span className="font-mono text-on-surface font-semibold truncate max-w-[124px]">
                  {selectedFile ? selectedFile.name : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">File size</span>
                <span className="font-mono text-on-surface">
                  {fileDetails ? fileDetails.size : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Last Modified</span>
                <span className="font-mono text-on-surface">
                  {fileDetails ? fileDetails.modTime : '—'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant">Identified Signer</span>
                <span className="font-mono text-primary font-bold truncate max-w-[110px]" title={session.fingerprint}>
                  {session.fingerprint}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <span className="text-on-surface-variant font-bold text-accent">Signing Domain</span>
                <span className="font-mono text-primary font-extrabold uppercase">SPIF</span>
              </div>

            </div>
          </div>

          {/* Scheme features info row */}
          <div className="p-6 rounded-xl bg-surface-container border border-white/5 space-y-3">
            <span className="font-mono text-[11px] font-bold text-[#4d556b] uppercase tracking-wider block">Signature Algorithm</span>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-on-surface-variant">Cryptoscheme</span>
                <span className="font-mono text-on-surface">SPHINCS+</span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant">Digest</span>
                <span className="font-mono text-on-surface">SHAKE-256</span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant">Sign File Type</span>
                <span className="font-mono text-primary font-bold">.usimeta Sidecar</span>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-surface-lowest border border-white/5 flex gap-3">
            <AlertTriangle className="w-5 h-5 text-warn shrink-0 mt-0.5" strokeWidth={2} />
            <div className="text-xs text-on-surface-variant space-y-1">
              <strong className="text-on-surface block font-bold">Sign once constraint</strong>
              <span>A signature confirms a documents state at a exact point in time. Re-signing or editing files breaks audit records immediately.</span>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
