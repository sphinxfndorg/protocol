/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { 
  Shield, 
  LayoutDashboard, 
  Lock, 
  Unlock, 
  FileSignature, 
  FileCheck, 
  Wallet, 
  Key, 
  Settings, 
  FileCode, 
  LogOut,
  User,
  Clipboard,
  Check
} from 'lucide-react';
import { ActiveSession } from '../types';
import { useState } from 'react';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  session: ActiveSession;
  onLogout: () => void;
}

export default function Sidebar({ currentTab, onTabChange, session, onLogout }: SidebarProps) {
  const [copied, setCopied] = useState(false);

  // Shorten DID fingerprint for clean screen layout e.g. did:usi:0x4FB...3B92
  const formattedFingerprint = () => {
    const fp = session.fingerprint;
    if (fp.length > 20) {
      return fp.substring(0, 11) + '...' + fp.substring(fp.length - 6);
    }
    return fp;
  };

  const handleCopyFingerprint = () => {
    navigator.clipboard.writeText(session.fingerprint);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'encrypt', label: 'Encrypt Folder', icon: Lock },
    { id: 'decrypt', label: 'Decrypt Vault', icon: Unlock },
    { id: 'sign', label: 'Sign Document', icon: FileSignature },
    { id: 'verify', label: 'Verify Signature', icon: FileCheck },
    { id: 'wallet', label: 'Spif Wallet', icon: Wallet },
    { id: 'keys', label: 'My Keys', icon: Key },
  ];

  const adminItems = [
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'security-log', label: 'Security Log', icon: FileCode },
  ];

  return (
    <div className="w-[260px] h-screen bg-surface flex flex-col border-r border-white/5 flex-shrink-0">
      
      {/* Upper Brand panel */}
      <div className="p-6 border-b border-white/5 bg-surface-container/20">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-surface-container border border-white/10 flex items-center justify-center">
            <Shield className="w-6 h-6 text-primary" strokeWidth={2} />
          </div>
          <div>
            <h2 className="font-sans text-xl font-bold text-on-surface tracking-tight flex items-center gap-1.5">
              USI <span className="text-[10px] bg-primary/15 text-primary px-1.5 py-0.5 rounded uppercase font-semibold font-mono">v2.4</span>
            </h2>
            <p className="font-mono text-[9px] uppercase tracking-wider text-primary/75 font-semibold">Identity Defense Active</p>
          </div>
        </div>
      </div>

      {/* Identity Profile Badge */}
      <div className="mx-4 my-4 p-3 rounded-xl bg-surface-container border border-white/5 flex items-center gap-3 relative overflow-hidden group">
        <div className="absolute top-0 right-0 w-8 h-8 rounded-full bg-primary/5 filter blur-lg transition-all group-hover:bg-primary/10" />
        <div className="w-10 h-10 rounded-lg bg-surface-container-high border border-white/10 flex items-center justify-center text-primary relative">
          <User className="w-5 h-5" />
          <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-primary border border-surface-container" />
        </div>
        <div className="min-w-0">
          <h4 className="text-xs font-bold text-on-surface truncate">Sovereign Profile</h4>
          <span className="font-mono text-[10px] text-on-surface-variant/80 block uppercase leading-none mt-0.5">Secure Enclave</span>
        </div>
      </div>

      {/* Main Navigation links */}
      <div className="flex-1 overflow-y-auto px-4 py-2 space-y-6">
        
        {/* Core Operations and Workspace section */}
        <div className="space-y-1">
          <span className="font-mono text-[9px] uppercase font-bold text-on-surface-variant/50 px-3 tracking-widest block mb-2">Workspace</span>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                id={`sidebar-tab-${item.id}`}
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 cursor-pointer text-left ${
                  isActive 
                    ? 'bg-primary/10 text-primary border border-primary/20 shadow-sm' 
                    : 'text-on-surface-variant hover:text-on-background hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon className={`w-[18px] h-[18px] ${isActive ? 'text-primary' : 'text-on-surface-variant'}`} />
                {item.label}
              </button>
            );
          })}
        </div>

        {/* Administration and audit lists section */}
        <div className="space-y-1">
          <span className="font-mono text-[9px] uppercase font-bold text-on-surface-variant/50 px-3 tracking-widest block mb-2">Systems</span>
          {adminItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                id={`sidebar-tab-${item.id}`}
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 cursor-pointer text-left ${
                  isActive 
                    ? 'bg-primary/10 text-primary border border-primary/20 shadow-sm' 
                    : 'text-on-surface-variant hover:text-on-background hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon className={`w-[18px] h-[18px] ${isActive ? 'text-primary' : 'text-on-surface-variant'}`} />
                {item.label}
              </button>
            );
          })}
        </div>

      </div>

      {/* Bottom Identity Control Panel */}
      <div className="p-4 border-t border-white/5 bg-surface-lowest">
        
        {/* Compact active address bar with copy feedback */}
        <div className="mb-3 flex items-center justify-between p-2 rounded-lg bg-surface-container border border-white/10">
          <div className="flex items-center gap-2 min-w-0">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse flex-shrink-0" />
            <span className="font-mono text-[11px] text-primary select-all truncate">
              {formattedFingerprint()}
            </span>
          </div>
          <button
            id="sidebar-copy-address"
            onClick={handleCopyFingerprint}
            className="text-on-surface-variant hover:text-primary p-1 rounded hover:bg-white/5 cursor-pointer text-right flex-shrink-0"
            title="Copy Key Identifier"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-primary" /> : <Clipboard className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Switched Profile or Signout operations */}
        <button
          id="sidebar-logout"
          onClick={onLogout}
          className="w-full h-10 border border-white/10 hover:border-danger/30 bg-white/5 hover:bg-danger/10 text-on-surface hover:text-danger-active font-sans text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all cursor-pointer"
        >
          <LogOut className="w-4 h-4" />
          Switch Identity Enclave
        </button>

      </div>

    </div>
  );
}
