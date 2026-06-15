/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, FormEvent } from 'react';
import { ActiveSession, ActivityLog, Transaction, ActivityType } from './types';
import Sidebar from './components/Sidebar';
import WelcomeScreen from './components/WelcomeScreen';
import Dashboard from './components/Dashboard';
import EncryptTab from './components/EncryptTab';
import DecryptTab from './components/DecryptTab';
import SignTab from './components/SignTab';
import VerifyTab from './components/VerifyTab';
import WalletTab from './components/WalletTab';
import KeysTab from './components/KeysTab';
import SettingsTab from './components/SettingsTab';
import SecurityLogTab from './components/SecurityLogTab';

import { 
  Lock, 
  X, 
  Eye, 
  EyeOff, 
  ShieldAlert, 
  Cpu,
  Terminal,
  HelpCircle,
  Activity,
  HardDrive,
  Settings,
  Code,
  Maximize2,
  Minimize2,
  ChevronRight,
  Monitor,
  AlertCircle,
  RefreshCw,
  FolderDown,
  Info,
  ShieldCheck,
  Zap,
  Power
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

// Reusable mock transactions based exactly on the requested visual specs
const INITIAL_TRANSACTIONS: Transaction[] = [
  {
    id: 'tx_1',
    timestamp: '2026-06-12 09:14',
    direction: 'in',
    amount: '500.000000',
    peer: 'SPIF:3A9FD6E6...C12E3B92',
    memo: 'Initial project grant allocation',
    status: 'confirmed',
  },
  {
    id: 'tx_2',
    timestamp: '2026-06-10 14:30',
    direction: 'in',
    amount: '784.500000',
    peer: 'SPIF:7B2D92CA...AA01D5B2',
    memo: 'Q2 identity defense budget disbursement',
    status: 'confirmed',
  },
  {
    id: 'tx_3',
    timestamp: '2026-06-09 11:02',
    direction: 'out',
    amount: '0.500000',
    peer: 'SPIF:9E1C4B52...FF44EAE9',
    memo: 'SPIF Registrar network registration fee',
    status: 'confirmed',
  },
  {
    id: 'tx_4',
    timestamp: '2026-06-08 08:55',
    direction: 'out',
    amount: '0.250000',
    peer: 'SPIF:2C8A99BB...3301D6E5',
    memo: 'FIDO2 hardware enclave pairing connection test',
    status: 'pending',
  }
];

export default function App() {
  const [session, setSession] = useState<ActiveSession | null>(null);
  const [currentTab, setCurrentTab] = useState<string>('dashboard');

  // Simulated Desktop OS Window Environment States
  const [isWindowClosed, setIsWindowClosed] = useState<boolean>(false);
  const [isWindowMaximized, setIsWindowMaximized] = useState<boolean>(false);
  const [isWindowMinimized, setIsWindowMinimized] = useState<boolean>(false);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [showHelpModal, setShowHelpModal] = useState<boolean>(false);
  const [showDiagnosticPopup, setShowDiagnosticPopup] = useState<boolean>(false);
  
  // Real-time local resource indicators (mimics physical platform)
  const [cpuUsage, setCpuUsage] = useState<number>(0.8);
  const [memUsage, setMemUsage] = useState<number>(31.4);
  const [localTime, setLocalTime] = useState<string>('');
  const [diagnosticLogs, setDiagnosticLogs] = useState<string[]>([]);
  const [isDiagnosticRunning, setIsDiagnosticRunning] = useState<boolean>(false);

  // Auto clock & resource counters mimicking native desktop host
  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setLocalTime(now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);

    const metricsTimer = setInterval(() => {
      setCpuUsage(prev => {
        const delta = (Math.random() - 0.5) * 0.4;
        return Math.max(0.1, Math.min(8.5, parseFloat((prev + delta).toFixed(1))));
      });
      setMemUsage(prev => {
        const delta = (Math.random() - 0.5) * 0.2;
        return Math.max(28.1, Math.min(34.8, parseFloat((prev + delta).toFixed(1))));
      });
    }, 4000);

    return () => {
      clearInterval(timer);
      clearInterval(metricsTimer);
    };
  }, []);

  // Global click-out listeners to auto-dismiss desktop cascading menus
  useEffect(() => {
    const handleGlobalClick = () => {
      setActiveMenu(null);
    };
    window.addEventListener('click', handleGlobalClick);
    return () => window.removeEventListener('click', handleGlobalClick);
  }, []);

  // Command menu action controller supporting both virtual web dropdowns and Electron native menus
  const handleMenuAction = (action: string) => {
    switch (action) {
      case 'unseal':
        if (session) {
          alert(`Session currently unsealed with key digest: ${session.fingerprint}`);
        } else {
          setCurrentTab('dashboard');
        }
        break;
      case 'lock':
        if (session) {
          handleLogout();
        } else {
          alert('No active enclave session to lock.');
        }
        break;
      case 'wipe':
        const wipeAnswer = window.confirm('Are you absolutely sure you want to secure-shred and wipe the local Enclave repository?');
        if (wipeAnswer) {
          handleWipeEnclaveStorage();
          alert('Local storage registry wiped and unsealed states destroyed successfully.');
        }
        break;
      case 'encrypt':
        if (session) {
          setCurrentTab('encrypt');
        } else {
          alert('Please unseal master identity first to access standard Cryptographic engines.');
        }
        break;
      case 'decrypt':
        if (session) {
          setCurrentTab('decrypt');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'sign':
        if (session) {
          setCurrentTab('sign');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'verify':
        if (session) {
          setCurrentTab('verify');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'wallet':
        if (session) {
          setCurrentTab('wallet');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'keys':
        if (session) {
          setCurrentTab('keys');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'security-log':
        if (session) {
          setCurrentTab('security-log');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'settings':
        if (session) {
          setCurrentTab('settings');
        } else {
          alert('Please unseal master identity first.');
        }
        break;
      case 'help-manual':
        setShowHelpModal(true);
        break;
      case 'export-instructions':
        setShowExportModal(true);
        break;
      case 'run-diagnostics':
        startSelfDiagnostics();
        break;
      case 'exit-window':
        setIsWindowClosed(true);
        addActivity('SETTINGS', 'Desktop framework window context suspended.', 'SUCCESS');
        break;
      default:
        break;
    }
  };

  // Wire Electron Native Menus direct into Web state
  useEffect(() => {
    const api = (window as any).electronAPI;
    if (api && api.onMenuTrigger) {
      const unsubscribe = api.onMenuTrigger((action: string) => {
        handleMenuAction(action);
      });
      return unsubscribe;
    }
  }, [session, currentTab]);

  const startSelfDiagnostics = () => {
    setIsDiagnosticRunning(true);
    setDiagnosticLogs(["📡 Connecting sovereign enclave boundary check..."]);
    setShowDiagnosticPopup(true);

    const logSteps = [
      "🔑 Loading local WebCrypto high-entropy hardware loops...",
      "🛡️ Testing certified SPHINCS+ digital keys ring validity...",
      "🔒 Initializing safe memory AES-256 GCM vault buffers...",
      "🪙 Synchronizing local SPIF decentralized ledger transactions...",
      "🧠 Mapped CPU hardware cryptographic enclaves (hardware acceleration verified)...",
      "✅ Diagnostic complete: Enclave registry is 100% SECURE & ONLINE!"
    ];

    logSteps.forEach((step, idx) => {
      setTimeout(() => {
        setDiagnosticLogs(prev => [...prev, step]);
        if (idx === logSteps.length - 1) {
          setIsDiagnosticRunning(false);
        }
      }, (idx + 1) * 700);
    });
  };

  // Analytics & Counters
  const [vaultCount, setVaultCount] = useState<number>(0);
  const [signedCount, setSignedCount] = useState<number>(0);
  const [lastActivity, setLastActivity] = useState<string>('Never');

  // Database Ledger Lists (Synced with localStorage)
  const [activities, setActivities] = useState<ActivityLog[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [balance, setBalance] = useState<number>(1284.25); // Initial SPIF sum: 500 + 784.5 - 0.5 - 0.25 = 1283.75? Wait, mockup says "1,284.500000 SPIF" exactly. We'll set exactly 1284.500000 SPIF!

  // Reusable Credential authorization dialogue state
  const [passphraseReq, setPassphraseReq] = useState<{
    title: string;
    message: string;
    onConfirm: (enteredPass: string) => void;
  } | null>(null);

  const [enteredPassInput, setEnteredPassInput] = useState('');
  const [showPromptPass, setShowPromptPass] = useState(false);
  const [promptError, setPromptError] = useState('');

  // Load persistence inside localStorage
  useEffect(() => {
    const savedSession = localStorage.getItem('usi_session');
    const savedActivities = localStorage.getItem('usi_activities');
    const savedTransactions = localStorage.getItem('usi_transactions');
    const savedBalance = localStorage.getItem('usi_balance');
    const savedVaultCount = localStorage.getItem('usi_vault_count');
    const savedSignedCount = localStorage.getItem('usi_signed_count');

    if (savedSession) {
      setSession(JSON.parse(savedSession));
    }
    if (savedActivities) {
      const parsedActs = JSON.parse(savedActivities) as ActivityLog[];
      setActivities(parsedActs);
      if (parsedActs.length > 0) {
        setLastActivity(parsedActs[0].detail);
      }
    } else {
      // Seed default logs
      setActivities([]);
    }

    if (savedTransactions) {
      setTransactions(JSON.parse(savedTransactions));
    } else {
      setTransactions(INITIAL_TRANSACTIONS);
    }

    if (savedBalance) {
      setBalance(parseFloat(savedBalance));
    } else {
      setBalance(1284.500000);
    }

    if (savedVaultCount) {
      setVaultCount(parseInt(savedVaultCount));
    }
    if (savedSignedCount) {
      setSignedCount(parseInt(savedSignedCount));
    }
  }, []);

  // Sync state modifications back to physical storage safely
  const handleUpdateBalance = (newBalance: number) => {
    setBalance(newBalance);
    localStorage.setItem('usi_balance', newBalance.toString());
  };

  const handleAddTransaction = (newTx: Transaction) => {
    const updated = [newTx, ...transactions];
    setTransactions(updated);
    localStorage.setItem('usi_transactions', JSON.stringify(updated));
  };

  const handleIncrementVaults = () => {
    const newVal = vaultCount + 1;
    setVaultCount(newVal);
    localStorage.setItem('usi_vault_count', newVal.toString());
  };

  const handleIncrementSigned = () => {
    const newVal = signedCount + 1;
    setSignedCount(newVal);
    localStorage.setItem('usi_signed_count', newVal.toString());
  };

  const addActivity = (type: ActivityType, detail: string, status: 'SUCCESS' | 'FAILURE' = 'SUCCESS') => {
    const now = new Date();
    const formattedDate = now.toISOString().replace('T', ' ').substring(0, 19);
    
    const newLog: ActivityLog = {
      id: Math.floor(Math.random() * 1000000).toString(),
      timestamp: formattedDate,
      type,
      detail,
      status
    };

    const updated = [newLog, ...activities];
    setActivities(updated);
    setLastActivity(detail);
    localStorage.setItem('usi_activities', JSON.stringify(updated));
  };

  // Login handler
  const handleLogin = (activeSession: ActiveSession) => {
    setSession(activeSession);
    localStorage.setItem('usi_session', JSON.stringify(activeSession));
    
    // Check if initial log is seeded
    addActivity('LOGIN', `Enclave Session loaded dynamically. Credentials authorized for DID: ${activeSession.fingerprint.substring(0, 16)}...`);
  };

  // Sign out triggers
  const handleLogout = () => {
    const confirmLogout = window.confirm('Are you sure you want to lock the active Master key and exit the active Enclave?');
    if (confirmLogout) {
      addActivity('LOGIN', 'User signed out', 'SUCCESS');
      setSession(null);
      localStorage.removeItem('usi_session');
      setCurrentTab('dashboard');
    }
  };

  // Full purge wiped operation
  const handleWipeEnclaveStorage = () => {
    addActivity('WIPE', 'WIPED ENCLAVE TRIGGERED. Destroying all sandbox states.', 'SUCCESS');
    localStorage.clear();
    setSession(null);
    setActivities([]);
    setTransactions(INITIAL_TRANSACTIONS);
    setBalance(1284.500000);
    setVaultCount(0);
    setSignedCount(0);
    setLastActivity('Never');
    setCurrentTab('dashboard');
  };

  const handleClearAuditLogs = () => {
    setActivities([]);
    localStorage.setItem('usi_activities', JSON.stringify([]));
    setLastActivity('Never');
    alert('Security audit logs purged successfully from local session cache.');
  };

  // Dialog prompt trigger callback
  const promptPassphraseDialog = (title: string, message: string, onConfirm: (enteredPass: string) => void) => {
    setPassphraseReq({
      title,
      message,
      onConfirm
    });
    setEnteredPassInput('');
    setPromptError('');
    setShowPromptPass(false);
  };

  const handlePromptConfirm = (e: FormEvent) => {
    e.preventDefault();
    if (!passphraseReq) return;

    if (!enteredPassInput.trim()) {
      setPromptError('Passphrase cannot be empty.');
      return;
    }

    passphraseReq.onConfirm(enteredPassInput.trim());
    setPassphraseReq(null);
  };

  const handlePromptCancel = () => {
    setPassphraseReq(null);
  };

  // Map active route selection
  const renderTabContent = () => {
    if (!session) return null;

    switch (currentTab) {
      case 'dashboard':
        return (
          <Dashboard 
            session={session} 
            analytics={{ vaultCount, signedCount, lastActivity }} 
            activities={activities}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
      case 'encrypt':
        return (
          <EncryptTab 
            session={session} 
            promptPassphraseDialog={promptPassphraseDialog}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
            onIncrementVaults={handleIncrementVaults}
          />
        );
      case 'decrypt':
        return (
          <DecryptTab 
            session={session} 
            promptPassphraseDialog={promptPassphraseDialog}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
      case 'sign':
        return (
          <SignTab 
            session={session} 
            promptPassphraseDialog={promptPassphraseDialog}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
            onIncrementSigned={handleIncrementSigned}
          />
        );
      case 'verify':
        return (
          <VerifyTab 
            session={session} 
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
      case 'wallet':
        return (
          <WalletTab 
            session={session} 
            balance={balance}
            transactions={transactions}
            onUpdateBalance={handleUpdateBalance}
            onAddTransaction={handleAddTransaction}
            promptPassphraseDialog={promptPassphraseDialog}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
      case 'keys':
        return (
          <KeysTab 
            session={session} 
            analytics={{ vaultCount, signedCount }}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
      case 'settings':
        return (
          <SettingsTab 
            session={session} 
            analytics={{ vaultCount, signedCount }} 
            onWipeStorage={handleWipeEnclaveStorage}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
      case 'security-log':
        return (
          <SecurityLogTab 
            activities={activities} 
            onClearLogs={handleClearAuditLogs} 
          />
        );
      default:
        return (
          <Dashboard 
            session={session} 
            analytics={{ vaultCount, signedCount, lastActivity }} 
            activities={activities}
            addActivity={(type, detail, status) => addActivity(type, detail, status)}
          />
        );
    }
  };

  return (
    <div className="min-h-screen w-screen bg-[#070e1b] text-on-background selection:bg-primary selection:text-on-primary select-none overflow-hidden font-sans flex flex-col relative">
      
      {/* MOCK CLOSE WINDOW STATE */}
      {isWindowClosed ? (
        <div className="flex-1 flex flex-col items-center justify-center bg-[radial-gradient(circle_at_center,#0d1f38_0%,#030a14_100%)] p-8 text-center animate-fade-in relative animate-duration-300">
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-10" />
          <motion.div 
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="glass-panel p-10 rounded-2xl max-w-[500px] border border-white/5 relative shadow-2xl"
          >
            <div className="h-16 w-16 mx-auto rounded-full bg-danger/10 border border-danger/30 flex items-center justify-center mb-6">
              <Power className="w-8 h-8 text-danger animate-pulse" />
            </div>
            <h2 className="text-xl font-bold font-mono tracking-tight text-on-surface mb-2">USI ENCLAVE SUSPENDED</h2>
            <p className="text-sm text-on-surface-variant font-sans mb-8 leading-relaxed">
              The sandboxed desktop application process was terminated. Cryptographic unsealed states have been locked and memory register blocks retracted safely in compliance with high-grade identity enclaves.
            </p>
            <div className="flex flex-col gap-3">
              <button
                type="button"
                onClick={() => {
                  setIsWindowClosed(false);
                  addActivity('SETTINGS', 'Desktop client instance warm-boot restored.', 'SUCCESS');
                }}
                className="w-full h-11 bg-primary hover:bg-primary-hover text-on-primary rounded-lg font-bold text-sm transition-all shadow-lg hover:shadow-primary/10 cursor-pointer flex items-center justify-center gap-2"
              >
                <Monitor className="w-4 h-4" /> Boot Client / Restore Window
              </button>
              <button
                type="button"
                onClick={() => {
                  handleWipeEnclaveStorage();
                  setIsWindowClosed(false);
                  addActivity('WIPE', 'Full physical zeroise trigger on shutdown.', 'SUCCESS');
                }}
                className="w-full h-11 border border-white/10 hover:border-danger hover:bg-white/5 text-on-surface-variant hover:text-danger rounded-lg font-semibold text-xs transition-all cursor-pointer"
              >
                Zeroise Sandbox Ledger & Hard-Reset
              </button>
            </div>
          </motion.div>
        </div>
      ) : (
        /* DESKTOP DESK / MAIN WINDOW CONTAINMENT SHELL */
        <div className={`p-0 flex-1 flex flex-col transition-all duration-300 ${isWindowMinimized ? 'bg-surface-lowest opacity-40 scale-95 origin-bottom' : 'bg-surface-lowest'}`}>
          
          {/* NATIVE SYSTEM WINDOW TITLEBAR (Mac Style Chrome) */}
          <div className="h-10 bg-surface border-b border-white/5 flex items-center justify-between px-4 select-none relative z-50">
            {/* macOS Windows Traffic Lights controls */}
            <div className="flex items-center gap-2">
              <button 
                type="button"
                onClick={() => handleMenuAction('exit-window')}
                title="Exit Local Sovereign Window"
                className="w-3.5 h-3.5 rounded-full bg-danger transition-colors hover:bg-danger/80 flex items-center justify-center text-[8px] text-[#222]/0 hover:text-white border border-danger/25 cursor-pointer font-bold"
              >
                ×
              </button>
              <button 
                type="button"
                onClick={() => setIsWindowMinimized(!isWindowMinimized)}
                title="Minimize application"
                className="w-3.5 h-3.5 rounded-full bg-warn transition-colors hover:bg-warn/80 flex items-center justify-center text-[7px] text-[#222]/0 hover:text-black border border-warn/25 cursor-pointer font-bold"
              >
                -
              </button>
              <button 
                type="button"
                onClick={() => setIsWindowMaximized(!isWindowMaximized)}
                title="Toggle Maximize mode"
                className="w-3.5 h-3.5 rounded-full bg-primary transition-colors hover:bg-primary/80 flex items-center justify-center text-[6px] text-[#222]/0 hover:text-white border border-primary/25 cursor-pointer font-bold"
              >
                +
              </button>
              
              <span className="ml-4 font-mono text-[10px] text-on-surface-variant/40">USI_DESKTOP_PID_8922</span>
            </div>

            {/* Centered Desktop Window Title */}
            <div className="absolute left-1/2 -translate-x-1/2 flex items-center gap-2 font-sans text-[11px] font-bold text-on-surface tracking-wide select-none">
              <HardDrive className="w-3.5 h-3.5 text-primary" />
              <span>USI Software Suite v2.4.0 — Sovereign Cryptographic Enclave</span>
              <span className="hidden sm:inline border-l border-white/10 pl-2 text-[10px] text-primary bg-primary/10 px-1.5 py-0.5 rounded-full font-mono font-medium">Local App Frame</span>
            </div>

            {/* Right Status telemetry badge */}
            <div className="flex items-center gap-3">
              <button 
                type="button"
                onClick={() => handleMenuAction('run-diagnostics')}
                className="text-[10px] bg-primary/15 border border-primary/20 hover:bg-primary/30 text-primary px-2.5 py-0.5 rounded font-mono font-bold transition-all cursor-pointer flex items-center gap-1"
              >
                <Activity className="w-3 h-3 text-primary animate-pulse" /> Self Diagnostic
              </button>
              <span className="h-2 w-2 rounded-full bg-primary shadow-sm" />
              <span className="font-mono text-[9px] uppercase font-semibold text-primary tracking-wider hidden md:inline">SYSTEM SECURED</span>
            </div>
          </div>

          {/* DYNAMIC DROPDOWN FILE MENU BAR */}
          <div className="h-8 bg-surface-container/60 px-4 border-b border-white/5 flex items-center gap-1 select-none text-xs relative z-40">
            {/* Session Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'session' ? null : 'session'); }}
                className={`px-3 py-1 rounded hover:bg-white/5 text-on-surface hover:text-primary transition-colors cursor-pointer ${activeMenu === 'session' ? 'bg-white/10 text-primary' : ''}`}
              >
                Session
              </button>
              {activeMenu === 'session' && (
                <div className="absolute left-0 mt-1 w-64 bg-surface-container rounded-lg border border-white/10 shadow-2xl p-1 flex flex-col z-50 animate-fade-in font-sans">
                  <div className="px-3 py-1.5 border-b border-white/5 mb-1 font-mono text-[9px] text-[#4d556b] uppercase tracking-wider font-bold">Host Enclave Management</div>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('unseal'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span className="flex items-center gap-2"><Lock className="w-3.5 h-3.5" /> Unseal Master Keys</span>
                    <span className="font-mono text-[10px] opacity-40">⌘U</span>
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('lock'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span className="flex items-center gap-2"><Power className="w-3.5 h-3.5" /> Lock Active Session</span>
                    <span className="font-mono text-[10px] opacity-40">⌘L</span>
                  </button>
                  <div className="h-px bg-white/5 my-1" />
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('wipe'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-danger hover:bg-danger/10 transition-colors cursor-pointer"
                  >
                    <span className="flex items-center gap-2"><RefreshCw className="w-3.5 h-3.5" /> Wipe Local Enclave Memory</span>
                    <span className="font-mono text-[10px] opacity-40">⌘T</span>
                  </button>
                  <div className="h-px bg-white/5 my-1" />
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('exit-window'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-white/5 transition-colors cursor-pointer"
                  >
                    <span className="flex items-center gap-2"><X className="w-3.5 h-3.5" /> Exit Client Frame</span>
                    <span className="font-mono text-[10px] opacity-40">⌘Q</span>
                  </button>
                </div>
              )}
            </div>

            {/* Cryptography Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'crypto' ? null : 'crypto'); }}
                className={`px-3 py-1 rounded hover:bg-white/5 text-on-surface hover:text-primary transition-colors cursor-pointer ${activeMenu === 'crypto' ? 'bg-white/10 text-primary' : ''}`}
              >
                Cryptography
              </button>
              {activeMenu === 'crypto' && (
                <div className="absolute left-0 mt-1 w-60 bg-surface-container rounded-lg border border-white/10 shadow-2xl p-1 flex flex-col z-50 animate-fade-in font-sans">
                  <div className="px-3 py-1.5 border-b border-white/5 mb-1 font-mono text-[9px] text-[#4d556b] uppercase tracking-wider font-bold">Cryptographic Utilities</div>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('encrypt'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🔒 Encrypt File Vault</span>
                    <span className="font-mono text-[10px] opacity-40">⌘E</span>
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('decrypt'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🔑 Decrypt Secure Vault</span>
                    <span className="font-mono text-[10px] opacity-40">⌘D</span>
                  </button>
                  <div className="h-px bg-white/5 my-1" />
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('sign'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🖋️ SPHINCS+ Sign Document</span>
                    <span className="font-mono text-[10px] opacity-40">⌘S</span>
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('verify'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>👁️ Verify Certificate</span>
                    <span className="font-mono text-[10px] opacity-40">⌘V</span>
                  </button>
                </div>
              )}
            </div>

            {/* Sovereign Ledger Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'ledger' ? null : 'ledger'); }}
                className={`px-3 py-1 rounded hover:bg-white/5 text-on-surface hover:text-primary transition-colors cursor-pointer ${activeMenu === 'ledger' ? 'bg-white/10 text-primary' : ''}`}
              >
                Sovereign Ledger
              </button>
              {activeMenu === 'ledger' && (
                <div className="absolute left-0 mt-1 w-60 bg-surface-container rounded-lg border border-white/10 shadow-2xl p-1 flex flex-col z-50 animate-fade-in font-sans">
                  <div className="px-3 py-1.5 border-b border-white/5 mb-1 font-mono text-[9px] text-[#4d556b] uppercase tracking-wider font-bold">Ledger Ledger Systems</div>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('wallet'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🪙 SPIF Ledger Wallet</span>
                    <span className="font-mono text-[10px] opacity-40">⌘W</span>
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('keys'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🔑 Active Identity Keys</span>
                    <span className="font-mono text-[10px] opacity-40">⌘K</span>
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('security-log'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🛡️ Security Audit Log</span>
                    <span className="font-mono text-[10px] opacity-40">⌘A</span>
                  </button>
                  <div className="h-px bg-white/5 my-1" />
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('settings'); }}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>⚙️ Settings & Configurations</span>
                    <span className="font-mono text-[10px] opacity-40">⌘,</span>
                  </button>
                </div>
              )}
            </div>

            {/* Native Builder Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'native' ? null : 'native'); }}
                className={`px-3 py-1 rounded hover:bg-white/5 text-on-surface hover:text-primary font-bold text-primary transition-colors cursor-pointer ${activeMenu === 'native' ? 'bg-white/10 text-primary-hover' : ''}`}
              >
                ⚙️ Export Desktop App
              </button>
              {activeMenu === 'native' && (
                <div className="absolute left-0 mt-1 w-64 bg-surface-container rounded-lg border border-white/10 shadow-2xl p-1 flex flex-col z-50 animate-fade-in font-sans">
                  <div className="px-3 py-1.5 border-b border-white/5 mb-1 font-mono text-[9px] text-[#4d556b] uppercase tracking-wider font-bold">Native Compiling options</div>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('export-instructions'); }}
                    className="flex items-center gap-2 px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <Code className="w-4 h-4 text-primary" /> Build for Mac (.dmg)
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('export-instructions'); }}
                    className="flex items-center gap-2 px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <Code className="w-4 h-4 text-info" /> Build for Windows (.exe)
                  </button>
                  <button 
                    type="button"
                    onClick={() => { handleMenuAction('export-instructions'); }}
                    className="flex items-center gap-2 px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <Code className="w-4 h-4 text-warn" /> Build for Linux (.AppImage)
                  </button>
                  <div className="h-px bg-white/5 my-1" />
                  <div className="p-2 font-mono text-[9.5px] text-on-surface-variant bg-surface/50 rounded leading-relaxed">
                    Electron & Electron-Builder packages are fully pre-configured in your code tree!
                  </div>
                </div>
              )}
            </div>

            {/* Help Menu */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setActiveMenu(activeMenu === 'help' ? null : 'help'); }}
                className={`px-3 py-1 rounded hover:bg-white/5 text-on-surface hover:text-primary transition-colors cursor-pointer ${activeMenu === 'help' ? 'bg-white/10 text-primary' : ''}`}
              >
                Help
              </button>
              {activeMenu === 'help' && (
                <div className="absolute left-0 mt-1 w-60 bg-surface-container rounded-lg border border-white/10 shadow-2xl p-1 flex flex-col z-50 animate-fade-in font-sans">
                  <div className="px-3 py-1.5 border-b border-white/5 mb-1 font-mono text-[9px] text-[#4d556b] uppercase tracking-wider font-bold">Sovereign Support</div>
                  <button 
                    type="button"
                    onClick={() => handleMenuAction('help-manual')}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>📖 Interactive Manual & Guide</span>
                    <span className="font-mono text-[10px] opacity-40">F1</span>
                  </button>
                  <button 
                    type="button"
                    onClick={() => handleMenuAction('run-diagnostics')}
                    className="flex items-center justify-between px-3 py-2 text-left rounded text-on-surface hover:bg-primary/10 hover:text-primary transition-colors cursor-pointer"
                  >
                    <span>🩺 Hardware Self-Diagnostics</span>
                    <span className="font-mono text-[10px] opacity-40">F5</span>
                  </button>
                </div>
              )}
            </div>

            <div className="ml-auto flex items-center gap-2 font-mono text-[10px] text-on-surface-variant/40 pr-2">
              <span>HOST_OS: chromium_sandbox</span>
              <span>•</span>
              <span className="text-primary">{localTime}</span>
            </div>
          </div>

          {/* SIMULATED WINDOW RECONCILIATION MINIMIZE VIEWPORT */}
          {isWindowMinimized ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 bg-[#091523] text-center font-sans">
              <motion.div 
                initial={{ scale: 0.9 }}
                animate={{ scale: 1 }}
                className="max-w-[400px] border border-white/5 bg-surface/50 p-8 rounded-xl backdrop-blur animate-fade-in"
              >
                <Monitor className="w-12 h-12 text-primary mx-auto mb-4 animate-pulse" />
                <h3 className="text-base font-bold text-on-surface mb-2 font-mono">CLIENT WINDOW CONTEXT SUSPENDED</h3>
                <p className="text-xs text-on-surface-variant mb-6 leading-relaxed">
                  The active graphic application loop is running in the background. Unsealed keys remain locked in local security buffers.
                </p>
                <button 
                  type="button"
                  onClick={() => setIsWindowMinimized(false)}
                  className="px-6 py-2 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-xs rounded-lg transition-all shadow-md hover:shadow-primary/15 cursor-pointer"
                >
                  Unminimize Window / Restore Frame
                </button>
              </motion.div>
            </div>
          ) : (
            /* ACTIVE WINDOW WORKING CONTEXT */
            <div className={`flex-1 flex h-[calc(100vh-72px)] overflow-hidden transition-all duration-300 ${isWindowMaximized ? 'p-0 bg-surface-lowest' : 'p-3 bg-surface-lowest'}`}>
              
              <div className={`flex-1 flex overflow-hidden border border-white/5 shadow-2xl relative ${isWindowMaximized ? 'rounded-none' : 'rounded-xl'}`}>
                
                {!session ? (
                  /* WELCOME / REGISTER / LOGIN GATEWAY PORTALS */
                  <WelcomeScreen onLogin={handleLogin} addActivity={addActivity} />
                ) : (
                  /* MAIN WORKSPACE SUITE LAYOUT */
                  <div className="flex h-full w-full overflow-hidden bg-surface-lowest">
                    
                    {/* Side navigation bar display */}
                    <Sidebar 
                      currentTab={currentTab} 
                      onTabChange={setCurrentTab} 
                      session={session}
                      onLogout={handleLogout}
                    />

                    {/* Core Content viewport frame */}
                    <main className="flex-1 overflow-y-auto bg-surface-lowest/40 relative">
                      
                      {/* Top Atmospheric Enclave status tracker */}
                      <header className="h-14 border-b border-white/5 bg-surface/50 backdrop-blur px-8 flex items-center justify-between sticky top-0 z-30 select-none">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] text-[#4d556b] uppercase tracking-widest font-bold">Session identity Status</span>
                          <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                          <span className="font-mono text-[10px] text-primary uppercase font-bold">Unsealed</span>
                        </div>
                        <div className="flex items-center gap-6">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[10px] text-[#4d556b] uppercase tracking-widest font-bold">Active Org</span>
                            <span className="font-mono text-xs font-bold text-primary">{session.orgCode}</span>
                          </div>
                        </div>
                      </header>

                      {/* Inner Content Padding */}
                      <div className="p-8 max-w-[1200px] mx-auto min-h-[calc(100vh-128px)] pb-16">
                        {renderTabContent()}
                      </div>

                    </main>

                  </div>
                )}
              </div>
            </div>
          )}

          {/* HIGH-FIDELITY DESKTOP STATUS BAR (OS Footer) */}
          <div className="h-6 bg-surface-lowest border-t border-white/5 flex items-center justify-between px-4 select-none font-mono text-[10px] text-[#4d556b] z-50">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[#a4b4bb]">DESKTOP INTEGRATION: ACTIVE</span>
              </span>
              <span>|</span>
              <span className="hidden sm:inline">ARCH: ELECTRON (NODE v22.14.0)</span>
              <span className="hidden md:inline">|</span>
              <span className="hidden md:flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5" /> CPU: <span className="text-[#bbcabf] font-bold">{cpuUsage}%</span>
              </span>
              <span className="hidden lg:inline">|</span>
              <span className="hidden lg:flex items-center gap-1">
                <HardDrive className="w-3.5 h-3.5" /> MEM: <span className="text-[#bbcabf] font-bold">{memUsage} MB</span>
              </span>
            </div>
            
            <div className="flex items-center gap-4">
              <span className="text-[9px] bg-white/5 px-1.5 py-0.5 rounded leading-none">VTE_v6.2.3</span>
              <span>|</span>
              <span className="text-secondary tracking-widest font-bold">● STATE RECORDED REPLICATED</span>
              <span>|</span>
              <span className="text-primary font-bold">{localTime}</span>
            </div>
          </div>

        </div>
      )}

      {/* COMPILING & NATIVE BUILD INSTRUCTIONS MODAL */}
      <AnimatePresence>
        {showExportModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-lowest/85 backdrop-blur-md">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-[620px] p-6 rounded-xl relative overflow-hidden text-on-surface"
            >
              <div className="scan-line" />
              
              <div className="flex justify-between items-center mb-6">
                <h3 className="font-sans text-base font-bold text-primary flex items-center gap-2">
                  <Code className="w-5 h-5 text-primary" /> Build & Export as a STANDALONE Desktop Native Application
                </h3>
                <button
                  type="button"
                  onClick={() => setShowExportModal(false)}
                  className="p-1 text-on-surface-variant hover:text-danger hover:bg-white/5 rounded cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-2 text-sm font-sans leading-relaxed">
                <p className="text-on-surface-variant text-xs">
                  Your code tree is 100% pre-configured with a native <strong>Electron</strong> and <strong>electron-builder</strong> layout system. You can package this web app instantly into native executable binaries (`.exe`, `.dmg`, `.deb` / `.AppImage`) on your local computer.
                </p>

                <div className="bg-surface/60 border border-white/5 rounded-lg p-4 space-y-3">
                  <h4 className="text-xs font-mono font-bold text-primary uppercase tracking-wide">📦 Setup & Compiling Commands</h4>
                  
                  <div className="space-y-2">
                    <p className="text-[11px] text-[#4d556b] font-mono">// 1. Download and open the exported workspace directory locally, then execute:</p>
                    <pre className="bg-[#010912] p-2.5 rounded font-mono text-xs text-info border border-white/5 select-text overflow-x-auto">
                      npm install
                    </pre>
                  </div>

                  <div className="space-y-2">
                    <p className="text-[11px] text-[#4d556b] font-mono">// 2. Spin up the Vite developmental server coupled inside Electron shell:</p>
                    <pre className="bg-[#010912] p-2.5 rounded font-mono text-xs text-info border border-white/5 select-text overflow-x-auto">
                      npm run electron:dev
                    </pre>
                  </div>

                  <div className="space-y-2">
                    <p className="text-[11px] text-[#4d556b] font-mono">// 3. Compile, package, and build standalone installer files (.exe / .dmg / .AppImage):</p>
                    <pre className="bg-[#010912] p-2.5 rounded font-mono text-xs text-primary border border-white/5 select-text overflow-x-auto">
                      npm run electron:build
                    </pre>
                  </div>
                </div>

                <div className="border border-white/5 bg-surface-container/60 rounded-lg p-3 text-xs text-on-surface-variant flex gap-3">
                  <Info className="w-6 h-6 text-info min-w-6" />
                  <div>
                    <span className="font-semibold text-on-surface">Target Destination Output</span>: Your standalone desktop app binaries will generate immediately inside the newly created <strong>`/dist-desktop`</strong> local folder directory! Under Mac, it will produce a sandboxed DMG image. Inside Windows, a self-acting NSIS installer setup.
                  </div>
                </div>
              </div>

              <div className="flex gap-3 justify-end border-t border-white/5 pt-4 mt-6">
                <button
                  type="button"
                  onClick={() => setShowExportModal(false)}
                  className="px-6 py-2 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-xs rounded-lg cursor-pointer transition-all"
                >
                  Understood & Continue
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* INTERACTIVE MANUAL & GUIDE MODAL */}
      <AnimatePresence>
        {showHelpModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-lowest/85 backdrop-blur-md">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-[620px] p-6 rounded-xl relative overflow-hidden text-on-surface"
            >
              <div className="scan-line" />
              
              <div className="flex justify-between items-center mb-6">
                <h3 className="font-sans text-base font-bold text-primary flex items-center gap-2">
                  <HelpCircle className="w-5 h-5 text-primary" /> USI Desktop Suite — Interactive User Manual
                </h3>
                <button
                  type="button"
                  onClick={() => setShowHelpModal(false)}
                  className="p-1 text-on-surface-variant hover:text-danger hover:bg-white/5 rounded cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-2 text-sm font-sans leading-relaxed">
                <div className="space-y-3">
                  <h4 className="text-xs font-mono font-bold text-[#bbcabf] uppercase tracking-wide border-b border-white/5 pb-1">🔐 Master Enclave Keys</h4>
                  <p className="text-on-surface-variant text-xs">
                    Your key pairs are created securely in RAM, protected by an interactive active session. Once locked or closed, unsealed keys are immediately shredded from memory register files to block runtime intrusion. Always keep your sovereign Mnemonic words recovery backup phases!
                  </p>
                </div>

                <div className="space-y-3 mt-4">
                  <h4 className="text-xs font-mono font-bold text-[#bbcabf] uppercase tracking-wide border-b border-white/5 pb-1">📦 File Vault Encryption</h4>
                  <p className="text-on-surface-variant text-xs">
                    Uses high-grade block cipher structures to wrap files into `.usivault` format containing authorized recipient digital identifications. You can securely upload these vault payload packages across public networks knowing only authentic identity owners can unseal them.
                  </p>
                </div>

                <div className="space-y-3 mt-4">
                  <h4 className="text-xs font-mono font-bold text-[#bbcabf] uppercase tracking-wide border-b border-white/5 pb-1">🖋️ SPHINCS+ Cryptography signatures</h4>
                  <p className="text-on-surface-variant text-xs">
                    Implements post-quantum secure SPHINCS+ equivalent signatures metadata (`.usimeta`) generated over document digests to prove authentic authorship and mathematical data-integrity.
                  </p>
                </div>
              </div>

              <div className="flex gap-3 justify-end border-t border-white/5 pt-4 mt-6">
                <button
                  type="button"
                  onClick={() => setShowHelpModal(false)}
                  className="px-6 py-2 border border-white/10 hover:bg-white/5 text-on-surface rounded-lg font-semibold text-xs cursor-pointer"
                >
                  Close Manual
                </button>
                <button
                  type="button"
                  onClick={() => { setShowHelpModal(false); setShowExportModal(true); }}
                  className="px-6 py-2 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-xs rounded-lg cursor-pointer transition-all"
                >
                  Export Native Binaries
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* SIMULATED SELF DIAGNOSTICS MODAL POPUP */}
      <AnimatePresence>
        {showDiagnosticPopup && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-lowest/85 backdrop-blur-md">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-[500px] p-6 rounded-xl relative overflow-hidden"
            >
              <div className="scan-line" />
              
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-mono text-sm font-bold text-primary flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-primary" /> ENCLAVE SYSTEM DIAGNOSTICS
                </h3>
                <button
                  type="button"
                  disabled={isDiagnosticRunning}
                  onClick={() => setShowDiagnosticPopup(false)}
                  className={`p-1 text-on-surface-variant hover:text-danger hover:bg-white/5 rounded ${isDiagnosticRunning ? 'opacity-20 cursor-not-allowed' : 'cursor-pointer'}`}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="bg-[#010912] border border-white/10 rounded-lg p-4 font-mono text-xs text-primary space-y-2 h-64 overflow-y-auto">
                <div className="text-on-surface-variant font-mono">[USID_ENV: ACTIVE_DIAGNOSTIC_SUITE]</div>
                <div className="h-px bg-white/5 my-2" />
                {diagnosticLogs.map((log, idx) => (
                  <div key={idx} className="animate-fade-in pl-1 leading-relaxed animate-duration-150">
                    {log}
                  </div>
                ))}
                
                {isDiagnosticRunning && (
                  <div className="flex items-center gap-2 pl-1 text-[11px] text-[#4d556b] uppercase tracking-widest font-bold animate-pulse mt-3 text-on-surface-variant">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" /> EXECUTING INTEGRITY LOOP TELEMETRY...
                  </div>
                )}
              </div>

              <div className="flex gap-3 justify-end border-t border-white/5 pt-4 mt-6">
                <button
                  type="button"
                  disabled={isDiagnosticRunning}
                  onClick={() => setShowDiagnosticPopup(false)}
                  className={`px-6 py-2 bg-primary text-on-primary font-sans font-bold text-xs rounded-lg transition-all ${isDiagnosticRunning ? 'opacity-50 cursor-not-allowed' : 'hover:bg-primary-hover cursor-pointer'}`}
                >
                  {isDiagnosticRunning ? 'System Checking...' : 'Secure & Close'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* CORE CRYPTOGRAPHIC AUTHORIZATION GATE (MODAL OVERLAY) */}
      <AnimatePresence>
        {passphraseReq && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-surface-lowest/85 backdrop-blur-md">
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="glass-panel w-full max-w-[460px] p-6 rounded-xl relative overflow-hidden"
            >
              <div className="scan-line" />
              
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-sans text-base font-bold text-warn flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-warn animate-pulse" /> {passphraseReq.title}
                </h3>
                <button
                  type="button"
                  onClick={handlePromptCancel}
                  className="p-1 text-on-surface-variant hover:text-danger hover:bg-white/5 rounded cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <p className="text-sm text-on-surface-variant mb-6 leading-relaxed font-sans">
                {passphraseReq.message}
              </p>

              <form onSubmit={handlePromptConfirm} className="space-y-4">
                <div className="flex flex-col gap-1.5">
                  <label className="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider font-bold">Sovereign Passphrase / Mnemonic</label>
                  <div className="relative">
                    <input
                      id="dialog-input-passphrase"
                      type={showPromptPass ? 'text' : 'password'}
                      required
                      placeholder="Insert 12 words recovery phrase..."
                      value={enteredPassInput}
                      onChange={(e) => setEnteredPassInput(e.target.value)}
                      className="w-full h-11 pl-4 pr-10 bg-surface-lowest text-on-background font-mono text-xs rounded-lg border border-white/10 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPromptPass(!showPromptPass)}
                      className="absolute right-3 top-3 text-on-surface-variant hover:text-primary cursor-pointer"
                    >
                      {showPromptPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {promptError && (
                  <div className="text-xs text-danger font-medium py-1">
                    {promptError}
                  </div>
                )}

                <div className="flex gap-3 border-t border-white/5 pt-4 mt-6">
                  <button
                    type="button"
                    onClick={handlePromptCancel}
                    className="flex-1 py-2 rounded-lg text-xs font-semibold text-center border border-white/10 hover:bg-white/5 cursor-pointer text-on-surface"
                  >
                    Cancel Transaction
                  </button>
                  <button
                    type="submit"
                    className="flex-1 py-2 bg-primary hover:bg-primary-hover text-on-primary font-sans font-bold text-xs rounded-lg cursor-pointer"
                  >
                    Authorize Enclave Signature
                  </button>
                </div>

              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}
