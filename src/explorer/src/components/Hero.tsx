/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, FormEvent } from 'react';
import { Shield, Search } from 'lucide-react';

export default function Hero({ onSearch }: { onSearch: (query: string) => void }) {
  const [query, setQuery] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      onSearch(query.trim());
    }
  };

  return (
    <div className="relative mb-12 py-12" id="hero-section">
      {/* Background radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-brand-cyan/5 rounded-full blur-3xl pointer-events-none" />

      {/* Main Container */}
      <div className="max-w-3xl mx-auto text-center flex flex-col items-center justify-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-brand-cyan/10 border border-brand-cyan/20 rounded-full text-brand-cyan text-xs font-mono mb-6 w-fit animate-pulse shadow-[0_0_15px_rgba(0,240,255,0.1)]">
          <Shield className="w-3.5 h-3.5" />
          POST-QUANTUM SPHINCS+ PROTOCOL ACTIVE
        </div>

        <h1 className="text-4xl md:text-5xl lg:text-6xl font-sans font-bold tracking-tight text-white mb-8 leading-tight">
          Sphinx <br />
          <span className="bg-gradient-to-r from-brand-cyan via-brand-purple to-brand-green bg-clip-text text-transparent">
            Ledger Explorer
          </span>
        </h1>

        {/* Global Search form in Hero */}
        <form onSubmit={handleSubmit} className="w-full max-w-xl relative group px-4">
          <div className="relative flex items-center bg-slate-950/80 border border-white/10 focus-within:border-brand-cyan/50 rounded-2xl p-1 shadow-[0_0_20px_rgba(0,0,0,0.5)] transition duration-300">
            <div className="pl-4 pr-2 py-3 flex items-center pointer-events-none text-slate-500 group-focus-within:text-brand-cyan transition-colors">
              <Search className="w-5 h-5" />
            </div>
            <input
              type="text"
              placeholder="Search by block height, hash, txid, or address..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-transparent border-none outline-none focus:ring-0 text-sm md:text-base text-white font-mono placeholder:text-slate-600 py-2.5 pr-4"
            />
            <button
              type="submit"
              className="px-5 py-2.5 bg-gradient-to-r from-brand-cyan to-brand-purple text-slate-950 font-semibold text-xs md:text-sm rounded-xl transition duration-300 hover:shadow-[0_0_15px_rgba(0,240,255,0.3)] cursor-pointer active:scale-95"
            >
              Search
            </button>
          </div>
          <div className="mt-3 text-xs text-slate-500 font-mono">
            Protip: Enter a block height (e.g., <span className="text-brand-cyan">1</span>) or any public address starting with <span className="text-brand-purple">spif1_</span>
          </div>
        </form>
      </div>
    </div>
  );
}
