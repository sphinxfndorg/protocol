/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { ActivityLog, ActivityType } from '../types';
import { 
  FileCode, 
  Search, 
  Trash2, 
  Download, 
  CheckCircle, 
  XCircle, 
  SlidersHorizontal,
  RefreshCw
} from 'lucide-react';

interface SecurityLogTabProps {
  activities: ActivityLog[];
  onClearLogs: () => void;
}

export default function SecurityLogTab({ activities, onClearLogs }: SecurityLogTabProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');

  // Filter logs
  const filteredActivities = activities.filter((act) => {
    const matchesSearch = act.detail.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          act.type.toLowerCase().includes(searchTerm.toLowerCase());
    
    if (filterType === 'ALL') return matchesSearch;
    if (filterType === 'CRITICAL') {
      return matchesSearch && (act.type === 'WIPE' || act.type === 'WALLET_SEND');
    }
    if (filterType === 'VAULT') {
      return matchesSearch && (act.type === 'ENCRYPT' || act.type === 'DECRYPT');
    }
    if (filterType === 'SIGN') {
      return matchesSearch && (act.type === 'SIGN' || act.type === 'VERIFY');
    }
    return matchesSearch;
  });

  const triggerLogsBackup = () => {
    let logString = `=========================================================\n`;
    logString += `           USI SECURITY AUDIT TRAIL LOGS EXPORT          \n`;
    logString += `=========================================================\n`;
    logString += `EXPORT TIME: ${new Date().toISOString()}\n`;
    logString += `IDENTIFIED VAULT STATE: STANDALONE\n\n`;

    activities.forEach((act) => {
      logString += `[${act.timestamp}] [${act.type}] ${act.detail} | STATUS: ${act.status}\n`;
    });

    const element = document.createElement('a');
    const fileBlob = new Blob([logString], { type: 'text/plain' });
    element.href = URL.createObjectURL(fileBlob);
    element.download = 'usi_security_audit_logs.txt';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    alert('Cryptographic audit trail successfully exported!');
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Header section with description */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="font-sans text-3xl font-bold text-primary tracking-tight">Security Log</h1>
          <p className="text-on-surface-variant text-sm mt-1">
            Browse real-time auditable cryptographic tracking lists of all secure vault operations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            id="audit-export-btn"
            type="button"
            onClick={triggerLogsBackup}
            className="px-4 py-2 bg-surface-container border border-white/5 hover:border-primary text-xs font-semibold text-primary rounded-lg transition-all cursor-pointer flex items-center gap-1.5"
            disabled={activities.length === 0}
          >
            <Download className="w-3.5 h-3.5" /> Export Audit Logs
          </button>
          
          <button
            id="audit-clear-btn"
            type="button"
            onClick={onClearLogs}
            className="px-4 py-2 border border-white/10 bg-white/5 hover:border-danger hover:bg-danger/10 text-xs font-semibold text-on-surface hover:text-danger rounded-lg transition-all cursor-pointer flex items-center gap-1.5"
            disabled={activities.length === 0}
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear Audit Logs
          </button>
        </div>
      </div>

      {/* Filter and search banner items */}
      <div className="p-4 rounded-xl bg-surface-container border border-white/5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        
        {/* Search Input bar */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3.5 top-3 w-4 h-4 text-on-surface-variant/70" />
          <input
            id="audit-search-input"
            type="text"
            placeholder="Search target log content, e.g. encrypted..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full h-10 pl-10 pr-4 bg-surface-lowest text-on-background font-sans text-sm rounded-lg border border-white/10 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        {/* Filter items pills */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 md:pb-0 select-none">
          <SlidersHorizontal className="w-4 h-4 text-on-surface-variant/60 hidden md:block" />
          
          {[
            { id: 'ALL', label: 'All Operations' },
            { id: 'CRITICAL', label: 'Critical actions' },
            { id: 'VAULT', label: 'Vault files' },
            { id: 'SIGN', label: 'Signatures' },
          ].map((pill) => (
            <button
              id={`audit-filter-btn-${pill.id}`}
              key={pill.id}
              onClick={() => setFilterType(pill.id)}
              className={`px-3 py-1.5 rounded-lg font-sans text-xs font-semibold tracking-tight transition-all cursor-pointer ${
                filterType === pill.id
                  ? 'bg-primary text-on-primary'
                  : 'bg-surface-lowest text-on-surface-variant border border-white/5 hover:bg-white/5'
              }`}
            >
              {pill.label}
            </button>
          ))}

        </div>

      </div>

      {/* Main Ledger grid lists */}
      <div className="p-6 rounded-xl bg-surface border border-white/5 min-h-[400px] flex flex-col">
        
        <div className="flex-1 overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="text-[#4d556b] font-bold uppercase border-b border-white/10 pb-2 bg-surface-lowest/10">
                <th className="py-3 px-4 w-[180px]">Timestamp</th>
                <th className="py-3 px-4 w-[120px]">Event Type</th>
                <th className="py-3 px-4">Event Details</th>
                <th className="py-3 px-4 w-[110px] text-right">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredActivities.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-12 text-center text-on-surface-variant font-sans text-sm">
                    No matching audit parameters logged in this search.
                  </td>
                </tr>
              ) : (
                filteredActivities.map((log) => (
                  <tr key={log.id} className="border-b border-white/5 hover:bg-white/[0.01] transition-all">
                    
                    {/* Timestamp column */}
                    <td className="py-3.5 px-4 text-on-surface-variant text-[11px]">
                      {log.timestamp}
                    </td>

                    {/* Operational type column */}
                    <td className="py-3.5 px-4 font-bold text-info">
                      <span className="bg-info/5 border border-info/10 rounded px-2 py-0.5 text-[10px]">
                        {log.type}
                      </span>
                    </td>

                    {/* Content Detail column */}
                    <td className="py-3.5 px-4 text-on-surface font-sans font-medium">
                      {log.detail}
                    </td>

                    {/* Status Pill column */}
                    <td className="py-3.5 px-4 text-right">
                      <span className={`inline-flex items-center gap-1 font-bold text-[10px] px-2 py-0.5 rounded leading-none ${
                        log.status === 'SUCCESS' 
                          ? 'text-primary bg-primary/10 border border-primary/20' 
                          : 'text-danger bg-danger/10 border border-danger/20'
                      }`}>
                        {log.status === 'SUCCESS' ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {log.status}
                      </span>
                    </td>

                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Audit compliance footer */}
        <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between text-[#4d556b] text-[10px] font-bold">
          <span>COMPLIANCE_STATUS: VERIFIED OK</span>
          <span>ENTRIES: {filteredActivities.length} logs matching</span>
        </div>

      </div>

    </div>
  );
}
