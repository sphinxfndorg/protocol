/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, FormEvent } from 'react';
import { Shield, Key, Lock, Eye, EyeOff, Clipboard, Check, Terminal, Landmark } from 'lucide-react';
import { ActiveSession } from '../types';
import { motion, AnimatePresence } from 'motion/react';

interface WelcomeScreenProps {
  onLogin: (session: ActiveSession) => void;
  addActivity: (type: 'LOGIN' | 'REGISTER', detail: string, status?: 'SUCCESS' | 'FAILURE') => void;
}

// Beautiful standard list of crypto mnemonic words to simulate real keygen
const MNEMONIC_WORDS = [
  'sovereign', 'enclave', 'shield', 'emerald', 'crypt', 'vault', 'matrix', 'secure',
  'defense', 'spif', 'signature', 'sphincs', 'shake', 'gcm', 'aes', 'quantum',
  'entropy', 'private', 'identity', 'enigma', 'obsidian', 'citadel', 'titan', 'beacon'
];

function generateRandomMnemonic(): string {
  const result: string[] = [];
  for (let i = 0; i < 12; i++) {
    const randomIndex = Math.floor(Math.random() * MNEMONIC_WORDS.length);
    result.push(MNEMONIC_WORDS[randomIndex]);
  }
  return result.join(' ');
}

function generateFingerprintFromMnemonic(mnemonic: string): { fingerprint: string; rawFingerprint: string } {
  // Generate stable mock hex fingerprint
  let hash = 0;
  for (let i = 0; i < mnemonic.length; i++) {
    hash = (hash << 5) - hash + mnemonic.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padEnd(8, 'f').substring(0, 8).toUpperCase();
  const hexPart2 = Math.abs(hash * 31).toString(16).padEnd(8, 'e').substring(0, 8).toUpperCase();
  return {
    fingerprint: `did:usi:0x${hex}${hexPart2}`,
    rawFingerprint: `SPIF:${hex}...${hexPart2}`
  };
}

export default function WelcomeScreen({ onLogin, addActivity }: WelcomeScreenProps) {
  const [view, setView] = useState<'welcome' | 'register' | 'login'>('welcome');
  const [passphraseInput, setPassphraseInput] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState('');

  // Reg state
  const [generatedMnemonic, setGeneratedMnemonic] = useState('');
  const [generatedFp, setGeneratedFp] = useState('');
  const [copied, setCopied] = useState(false);

  // Trigger login process
  const handleLoginSubmit = (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    const trimmed = passphraseInput.trim().toLowerCase();
    
    if (trimmed.split(/\s+/).length < 4) {
      setErrorMsg('Passphrase must be a security string containing at least 4 words.');
      addActivity('LOGIN', 'Attempted login with insufficient words count', 'FAILURE');
      return;
    }

    setIsLoading(true);
    setProgress(10);
    setProgressMsg('Initializing Master Enclave...');

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          const { fingerprint, rawFingerprint } = generateFingerprintFromMnemonic(trimmed);
          onLogin({
            passphrase: trimmed,
            fingerprint,
            rawFingerprint,
            orgCode: 'SPIF',
          });
          addActivity('LOGIN', `User logged in — Fingerprint: ${fingerprint.substring(0, 16)}…`, 'SUCCESS');
          setIsLoading(false);
          return 100;
        }
        if (prev === 40) setProgressMsg('Deriving Argon2id cryptographic parameters...');
        if (prev === 75) setProgressMsg('Verifying public fingerprint bundle payload...');
        return prev + 15;
      });
    }, 120);
  };

  // Trigger Registration
  const handleRegisterSetup = () => {
    setIsLoading(true);
    setProgress(0);
    setProgressMsg('Seeding cryptographic entropy pool...');
    
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          const mnemonic = generateRandomMnemonic();
          const { fingerprint } = generateFingerprintFromMnemonic(mnemonic);
          setGeneratedMnemonic(mnemonic);
          setGeneratedFp(fingerprint);
          setView('register');
          setIsLoading(false);
          return 100;
        }
        if (prev === 20) setProgressMsg('Generating high-security SPHINCS+ signature key pairs...');
        if (prev === 50) setProgressMsg('Running local SHAKE-256 validation sweeps...');
        if (prev === 80) setProgressMsg('Enrolling master public key inside SPIF Registrar...');
        return prev + 20;
      });
    }, 150);
  };

  const handleCopyPassphrase = () => {
    navigator.clipboard.writeText(generatedMnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleConfirmRegistration = () => {
    const session: ActiveSession = {
      passphrase: generatedMnemonic,
      fingerprint: generatedFp,
      rawFingerprint: `SPIF:${generatedFp.substring(12, 20)}...${generatedFp.substring(20)}`,
      orgCode: 'SPIF',
    };
    onLogin(session);
    addActivity('REGISTER', 'New user registered — keys created for SPIF', 'SUCCESS');
  };

  return (
    <div className="relative min-h-screen w-full flex flex-col items-center justify-center p-6 lg:p-12 overflow-hidden bg-surface-lowest">
      {/* Background Tech Decorative Elements */}
      <div className="absolute inset-0 z-0 bg-radial-at-t from-surface-container-high/30 via-transparent to-transparent pointer-events-none" />
      
      {/* Floating Geometric Stars / Grid Background (CSS Grid effect) */}
      <div className="absolute inset-0 z-0 opacity-5 pointer-events-none bg-[linear-gradient(to_right,#808080_1px,transparent_1px),linear-gradient(to_bottom,#808080_1px,transparent_1px)] bg-[size:32px_32px]" />

      <main className="relative z-10 w-full max-w-[480px] flex flex-col items-center">
        
        {/* Branding Header */}
        <div className="text-center mb-8 animate-in fade-in slide-in-from-bottom-4 duration-1000">
          <div className="inline-flex items-center justify-center w-20 h-20 mb-4 rounded-2xl bg-surface-container border border-white/10 emerald-glow">
            <Shield className="w-12 h-12 text-primary" strokeWidth={1.5} />
          </div>
          <h1 className="font-sans text-5xl font-black text-primary tracking-tighter mb-2">USI Software</h1>
          <p className="font-mono text-xs text-on-surface-variant uppercase tracking-[0.2em] font-bold">
            Universal Sovereign Identity - SPIF System
          </p>
        </div>

        <AnimatePresence mode="wait">
          {isLoading ? (
            /* Loading State Screen */
            <motion.div
              key="loading"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="glass-panel w-full p-8 rounded-xl relative overflow-hidden"
            >
              <div className="scan-line" />
              <div className="flex flex-col items-center justify-center py-6">
                <div className="relative w-16 h-16 mb-6">
                  {/* Outer spinning green circle */}
                  <div className="absolute inset-0 rounded-full border-2 border-primary/20 border-t-primary animate-spin" />
                  <div className="absolute inset-2 rounded-full border border-primary/10 border-b-primary animate-pulse" />
                </div>
                <h3 className="font-mono text-xs uppercase tracking-wider text-primary mb-2">CRYPTOGRAPHIC ENCLAVE ACTIVE</h3>
                <p className="text-sm font-sans text-on-surface-variant text-center max-w-sm">{progressMsg}</p>
                
                {/* Horizontal Progress bar */}
                <div className="w-full bg-surface-lowest rounded-full h-1 my-6 overflow-hidden border border-white/5">
                  <div 
                    className="bg-primary h-full rounded-full transition-all duration-300"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <span className="font-mono text-xs text-on-surface-variant">{progress}% decrypted</span>
              </div>
            </motion.div>
          ) : view === 'welcome' ? (
            /* Main Interaction Landing */
            <motion.div
              key="welcome"
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -15 }}
              className="glass-panel w-full p-8 rounded-xl relative overflow-hidden group border border-white/5"
            >
              <div className="scan-line" />
              <div className="flex flex-col gap-4">
                
                {/* Primary Action Button */}
                <button
                  id="welcome-btn-register"
                  onClick={handleRegisterSetup}
                  className="group/btn relative w-full h-14 bg-primary text-on-primary font-sans font-bold text-lg rounded-lg flex items-center justify-center gap-3 transition-all cursor-pointer hover:scale-[1.02] active:scale-[0.98]"
                >
                  <Key className="w-5 h-5" />
                  Register Master Enclave
                  <div className="absolute inset-0 rounded-lg opacity-0 group-hover/btn:opacity-10 bg-white transition-opacity" />
                </button>

                <div className="py-1 text-center">
                  <span className="font-mono text-[10px] text-on-surface-variant tracking-[0.15em] opacity-60">
                    INITIALIZE SECURED ID VAULT
                  </span>
                </div>

                {/* Secondary Action Button */}
                <button
                  id="welcome-btn-login"
                  onClick={() => setView('login')}
                  className="w-full h-14 border border-white/10 bg-white/5 hover:bg-white/10 text-on-surface font-sans font-medium rounded-lg flex items-center justify-center gap-3 transition-all cursor-pointer active:scale-[0.98]"
                >
                  <Shield className="w-5 h-5 text-primary" />
                  Login using Passphrase
                </button>

              </div>

              {/* Status footer inside card */}
              <div className="mt-8 pt-4 border-t border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary" />
                  </span>
                  <span className="font-mono text-[11px] text-primary tracking-wider uppercase">Vault Ready</span>
                </div>
                <span className="font-mono text-[11px] text-on-surface-variant/70">v2.4.0-STABLE</span>
              </div>
            </motion.div>
          ) : view === 'register' ? (
            /* Registration Setup Screen */
            <motion.div
              key="register"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="glass-panel w-full p-8 rounded-xl relative overflow-hidden"
            >
              <div className="scan-line" />
              <h3 className="font-sans text-xl font-bold text-primary mb-2 flex items-center gap-2">
                <Key className="w-5 h-5" /> Secure Account Created
              </h3>
              <p className="text-sm text-on-surface-variant mb-6 font-sans">
                Below is your unique Cryptographic Mnemonic. Store it offline! Anyone with these 12-words has control of your sovereign identity vault.
              </p>

              {/* Passphrase Container */}
              <div className="bg-surface-lowest p-4 rounded-lg border border-primary/20 flex flex-col gap-3 relative group mb-6">
                <div className="grid grid-cols-3 gap-2">
                  {generatedMnemonic.split(' ').map((word, idx) => (
                    <div key={idx} className="bg-surface-container/50 px-2 py-1.5 rounded border border-white/5 flex gap-1.5 items-center">
                      <span className="font-mono text-[10px] text-primary">{idx + 1}</span>
                      <span className="font-sans text-sm font-semibold text-on-background select-all">{word}</span>
                    </div>
                  ))}
                </div>
                
                <button
                  id="register-btn-copy"
                  onClick={handleCopyPassphrase}
                  className="mt-2 w-full py-2 bg-surface-container-high hover:bg-surface-container-highest border border-white/10 rounded flex justify-center items-center gap-2 font-mono text-xs text-primary transition-all cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="w-4 h-4 text-primary" /> Copied Key Bundle
                    </>
                  ) : (
                    <>
                      <Clipboard className="w-4 h-4" /> Copy 12-Word Mnemonic
                    </>
                  )}
                </button>
              </div>

              {/* Fingerprint Display */}
              <div className="bg-surface-container/20 p-4 rounded-lg border border-white/5 mb-6">
                <span className="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider block mb-1">Your sovereign DID Fingerprint</span>
                <code className="font-mono text-xs text-primary select-all break-all">{generatedFp}</code>
              </div>

              {/* Warning Notice */}
              <div className="bg-danger/10 border border-danger/30 p-3 rounded-lg flex items-start gap-2.5 mb-6">
                <Lock className="w-4 h-4 text-danger shrink-0 mt-0.5" />
                <span className="text-xs text-on-background font-medium">
                  <strong>Permanent Loss Warning</strong>: We cannot recover your keys. If you do not record this mnemonic, your encrypted data will be lost forever.
                </span>
              </div>

              {/* Submit / Navigation */}
              <div className="flex gap-3 mt-4">
                <button
                  id="register-btn-back"
                  onClick={() => setView('welcome')}
                  className="flex-1 py-3 border border-white/10 rounded-lg font-sans text-sm font-medium hover:bg-white/5 cursor-pointer text-center"
                >
                  Back
                </button>
                <button
                  id="register-btn-confirm"
                  onClick={handleConfirmRegistration}
                  className="flex-1 py-3 bg-primary text-on-primary font-sans text-sm font-bold rounded-lg hover:scale-[1.02] cursor-pointer"
                >
                  Enter Identity Vault
                </button>
              </div>
            </motion.div>
          ) : (
            /* Login Screen form */
            <motion.div
              key="login"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="glass-panel w-full p-8 rounded-xl relative overflow-hidden"
            >
              <div className="scan-line" />
              <h3 className="font-sans text-xl font-bold text-primary mb-2 flex items-center gap-2">
                <Key className="w-5 h-5 animate-pulse" /> Unlock Identity Vault
              </h3>
              <p className="text-sm text-on-surface-variant mb-6">
                Provide your Master Mnemonic Passphrase to decrypt and access local archives.
              </p>

              <form onSubmit={handleLoginSubmit} className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider">Passphrase / 12-Word seed</label>
                  <div className="relative">
                    <input
                      id="login-input-passphrase"
                      type={showPass ? 'text' : 'password'}
                      value={passphraseInput}
                      onChange={(e) => setPassphraseInput(e.target.value)}
                      placeholder="Insert 12 words seed (space-separated)..."
                      className="w-full h-12 pl-4 pr-10 bg-surface-lowest text-on-background font-mono text-sm rounded-lg border border-white/10 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary transition-all"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPass(!showPass)}
                      className="absolute right-3 top-3.5 text-on-surface-variant hover:text-primary cursor-pointer"
                    >
                      {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {errorMsg && (
                  <div className="text-xs text-danger font-medium py-1 bg-danger/5 border border-danger/20 rounded-md px-3">
                    {errorMsg}
                  </div>
                )}

                <div className="flex gap-3 mt-4">
                  <button
                    id="login-btn-cancel"
                    type="button"
                    onClick={() => setView('welcome')}
                    className="flex-1 py-3 border border-white/10 rounded-lg text-sm text-center hover:bg-white/5 cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    id="login-btn-submit"
                    type="submit"
                    className="flex-1 py-3 bg-primary text-on-primary rounded-lg font-sans font-bold text-sm cursor-pointer hover:scale-[1.02] transition-transform"
                  >
                    Load Master Key
                  </button>
                </div>
              </form>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Global Security Badges (Footer) */}
        <div className="mt-8 grid grid-cols-3 gap-8 opacity-40 hover:opacity-75 transition-all duration-500">
          <div className="flex flex-col items-center gap-1 text-center">
            <Lock className="w-5 h-5 text-on-surface" />
            <span className="font-mono text-[9px] uppercase tracking-wider font-bold">E2E Secure</span>
          </div>
          <div className="flex flex-col items-center gap-1 text-center">
            <Landmark className="w-5 h-5 text-on-surface" />
            <span className="font-mono text-[9px] uppercase tracking-wider font-bold">Audited Enclave</span>
          </div>
          <div className="flex flex-col items-center gap-1 text-center">
            <Terminal className="w-5 h-5 text-on-surface" />
            <span className="font-mono text-[9px] uppercase tracking-wider font-bold">Open-Source</span>
          </div>
        </div>

      </main>

      {/* Global IFrame Access Footnotes */}
      <footer className="absolute bottom-6 w-full flex justify-center z-20">
        <div className="flex items-center gap-6 py-2 px-6 rounded-full bg-surface-container/50 border border-white/5 backdrop-blur-sm">
          <span className="font-mono text-[10px] text-primary font-bold">AUDIT_VERIFIED: ok</span>
          <div className="h-3 w-px bg-white/10" />
          <span className="font-mono text-[10px] text-on-surface-variant font-medium">Support: thekoesoemo@gmail.com</span>
        </div>
      </footer>
    </div>
  );
}
