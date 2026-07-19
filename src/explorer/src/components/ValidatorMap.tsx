/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
import { Validator } from '../types';
import { Globe, Radio, Shield, Users, Server, Cpu, Navigation } from 'lucide-react';
import { formatHash } from '../utils/formatters';

interface ValidatorMapProps {
  validators: Validator[];
  onSelectAddress: (address: string) => void;
}

export default function ValidatorMap({ validators, onSelectAddress }: ValidatorMapProps) {
  const [hoveredNode, setHoveredNode] = useState<Validator | null>(null);
  const [selectedNode, setSelectedNode] = useState<Validator | null>(null);

  // Projection dimensions
  const mapWidth = 900;
  const mapHeight = 440;

  // Convert Latitude / Longitude to SVG 2D plane
  const getXY = (lat: number, lon: number) => {
    // Equirectangular projection
    const x = ((lon + 180) * mapWidth) / 360;
    const y = ((90 - lat) * mapHeight) / 180;
    return { x, y };
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-brand-green border-brand-green/30 text-brand-green';
      case 'slashed': return 'bg-brand-red border-brand-red/30 text-brand-red';
      default: return 'bg-slate-500 border-white/5 text-slate-400';
    }
  };

  const getStatusText = (status: string) => {
    if (status === 'active') return 'Attesting';
    if (status === 'slashed') return 'Slashed (Jailed)';
    return 'Exited';
  };

  const totalStake = validators.reduce((acc, val) => acc + parseFloat(val.stakeSpx), 0);

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* 1. Page Header */}
      <div className="border-b border-white/5 pb-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="text-[10px] text-brand-cyan font-mono bg-brand-cyan/10 border border-brand-cyan/20 px-2.5 py-0.5 rounded-full uppercase tracking-wider font-bold">
            Consensus Layer
          </span>
          <h1 className="text-2xl md:text-3xl font-bold text-white mt-1">
            Global Validator Infrastructure
          </h1>
        </div>
        <div className="flex items-center gap-1.5 bg-slate-900 border border-white/5 px-3.5 py-1.5 rounded-xl text-xs font-mono text-slate-400">
          <Globe className="w-4 h-4 text-brand-cyan animate-spin-slow" />
          {validators.filter(v => v.status === 'active').length} Nodes Online
        </div>
      </div>

      {/* 2. Global stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/40 border border-white/5 rounded-2xl p-4 backdrop-blur-md">
          <div className="text-[10px] text-slate-500 font-mono uppercase">Total Network Stake</div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {totalStake.toLocaleString(undefined, { maximumFractionDigits: 0 })}
            <span className="text-xs text-slate-500 ml-1">SPX</span>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-white/5 rounded-2xl p-4 backdrop-blur-md">
          <div className="text-[10px] text-slate-500 font-mono uppercase">Active Nodes</div>
          <div className="text-xl font-bold font-mono text-brand-green mt-1">
            {validators.filter(v => v.status === 'active').length}
            <span className="text-xs text-slate-500 ml-1">Nodes</span>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-white/5 rounded-2xl p-4 backdrop-blur-md">
          <div className="text-[10px] text-slate-500 font-mono uppercase">Epoch Length</div>
          <div className="text-xl font-bold font-mono text-brand-purple mt-1">
            2,400
            <span className="text-xs text-slate-500 ml-1">Slots</span>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-white/5 rounded-2xl p-4 backdrop-blur-md">
          <div className="text-[10px] text-slate-500 font-mono uppercase">Slashed Jailed</div>
          <div className="text-xl font-bold font-mono text-brand-red mt-1">
            {validators.filter(v => v.status === 'slashed').length}
            <span className="text-xs text-slate-500 ml-1">Offline</span>
          </div>
        </div>
      </div>

      {/* 3. Global SVG Geographic Visualizer Map */}
      <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <span className="w-1.5 h-4 bg-brand-cyan rounded-full" />
              NIST-Attested Node Matrix Map
            </h2>
            <p className="text-xs text-slate-500 font-mono mt-1">
              Interactive geographic map of SPHINCS+ post-quantum validation layers
            </p>
          </div>
          <div className="text-xs text-slate-400 font-mono hidden sm:block">
            Hover dots for node telemetry
          </div>
        </div>

        {/* Outer SVG Container */}
        <div className="relative border border-white/5 bg-slate-950/80 rounded-2xl overflow-hidden shadow-[inset_0_2px_15px_rgba(0,0,0,0.8)]">
          <div className="overflow-x-auto">
            <svg 
              viewBox={`0 0 ${mapWidth} ${mapHeight}`}
              className="w-full h-auto min-w-[700px] text-slate-800"
            >
              {/* Subtle visual grid lines */}
              <defs>
                <pattern id="map-grid" width="30" height="30" patternUnits="userSpaceOnUse">
                  <path d="M 30 0 L 0 0 0 30" fill="none" stroke="rgba(0, 240, 255, 0.015)" strokeWidth="0.8" />
                </pattern>
                
                {/* Radial Glow Filters */}
                <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="5" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <filter id="glow-purple" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="5" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Background Grid Layer */}
              <rect width={mapWidth} height={mapHeight} fill="url(#map-grid)" />

              {/* Abstract World Outlines (subtle lines) */}
              <rect x="10%" y="20%" width="15%" height="30%" rx="30" fill="none" stroke="rgba(255,255,255,0.01)" strokeWidth="1.5" />
              <rect x="40%" y="15%" width="20%" height="45%" rx="40" fill="none" stroke="rgba(255,255,255,0.01)" strokeWidth="1.5" />
              <rect x="70%" y="40%" width="18%" height="35%" rx="35" fill="none" stroke="rgba(255,255,255,0.01)" strokeWidth="1.5" />

              {/* Draw connections lines between key nodes (Alpha - Zurich - Tokyo - SF) */}
              {validators.filter(v => v.status === 'active').length >= 4 && (
                <g opacity="0.15">
                  {/* SF to Tokyo */}
                  {(() => {
                    const sf = getXY(37.7749, -122.4194);
                    const tokyo = getXY(35.6762, 139.6503);
                    const zurich = getXY(47.3769, 8.5417);
                    const sing = getXY(1.3521, 103.8198);
                    return (
                      <>
                        <path 
                          d={`M ${sf.x} ${sf.y} Q ${(sf.x + tokyo.x) / 2} ${(sf.y + tokyo.y) / 2 - 40} ${tokyo.x} ${tokyo.y}`} 
                          fill="none" stroke="#00f0ff" strokeWidth="1.2" strokeDasharray="4 4"
                        />
                        <path 
                          d={`M ${tokyo.x} ${tokyo.y} Q ${(tokyo.x + sing.x) / 2} ${(tokyo.y + sing.y) / 2 - 30} ${sing.x} ${sing.y}`} 
                          fill="none" stroke="#a855f7" strokeWidth="1.2"
                        />
                        <path 
                          d={`M ${sing.x} ${sing.y} Q ${(sing.x + zurich.x) / 2} ${(sing.y + zurich.y) / 2 - 40} ${zurich.x} ${zurich.y}`} 
                          fill="none" stroke="#00f0ff" strokeWidth="1.2" strokeDasharray="3 3"
                        />
                        <path 
                          d={`M ${zurich.x} ${zurich.y} Q ${(zurich.x + sf.x) / 2} ${(zurich.y + sf.y) / 2 - 60} ${sf.x} ${sf.y}`} 
                          fill="none" stroke="#22ff88" strokeWidth="1"
                        />
                      </>
                    );
                  })()}
                </g>
              )}

              {/* Draw Nodes */}
              {validators.map((val) => {
                const { x, y } = getXY(val.latitude, val.longitude);
                const isActive = val.status === 'active';
                const isSlashed = val.status === 'slashed';
                const isHovered = hoveredNode?.id === val.id;
                const isSelected = selectedNode?.id === val.id;

                let color = '#555577'; // default
                let filterGlow = '';
                if (isActive) {
                  color = '#22ff88';
                } else if (isSlashed) {
                  color = '#ff3366';
                }

                return (
                  <g 
                    key={val.id}
                    onMouseEnter={() => setHoveredNode(val)}
                    onMouseLeave={() => setHoveredNode(null)}
                    onClick={() => setSelectedNode(val === selectedNode ? null : val)}
                    className="cursor-pointer"
                  >
                    {/* Pulsing ring around active nodes */}
                    {isActive && (
                      <circle
                        cx={x}
                        cy={y}
                        r={isHovered || isSelected ? 16 : 8}
                        fill="none"
                        stroke={color}
                        strokeWidth="1"
                        className="animate-ping"
                        style={{ transformOrigin: `${x}px ${y}px`, animationDuration: '3s' }}
                        opacity="0.25"
                      />
                    )}

                    {/* Outer hover ring */}
                    {(isHovered || isSelected) && (
                      <circle
                        cx={x}
                        cy={y}
                        r="14"
                        fill="none"
                        stroke="#00f0ff"
                        strokeWidth="1.5"
                        strokeDasharray="3 3"
                      />
                    )}

                    {/* Main Node Point */}
                    <circle
                      cx={x}
                      cy={y}
                      r={isHovered || isSelected ? 6 : 4}
                      fill={color}
                      stroke="#060714"
                      strokeWidth="1.5"
                    />
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Map Popover (Node details HUD) */}
          {(hoveredNode || selectedNode) && (
            <div className="absolute bottom-4 left-4 right-4 sm:right-auto bg-slate-900/95 border border-white/10 hover:border-brand-cyan/20 rounded-xl p-4 w-auto sm:w-80 backdrop-blur-md shadow-2xl animate-fadeIn space-y-3 z-10">
              {(() => {
                const node = hoveredNode || selectedNode;
                if (!node) return null;
                const isNodeActive = node.status === 'active';
                
                return (
                  <>
                    <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <div className="flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${
                          isNodeActive ? 'bg-brand-green animate-pulse' : (node.status === 'slashed' ? 'bg-brand-red' : 'bg-slate-500')
                        }`} />
                        <h4 className="text-white text-xs font-bold font-mono">
                          {formatHash(node.id, 8)}
                        </h4>
                      </div>
                      <span className="text-[9px] font-mono text-slate-500 uppercase">
                        {node.city}, {node.country}
                      </span>
                    </div>

                    <div className="text-[11px] font-mono space-y-1.5 text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Validator IP:</span>
                        <span>{node.ip}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Total Stake:</span>
                        <span className="text-white font-semibold">{parseFloat(node.stakeSpx).toLocaleString()} SPX</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Voting Power:</span>
                        <span className="text-brand-cyan font-bold">{node.stakePercent.toFixed(2)}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Last Block Cert:</span>
                        <span className="text-brand-purple">#{node.lastAttested.toLocaleString()}</span>
                      </div>
                    </div>

                    <div className="pt-2 text-[10px] text-slate-500 flex justify-between items-center border-t border-white/5">
                      <span>NIST STATUS:</span>
                      <span className={isNodeActive ? 'text-brand-green font-bold' : 'text-brand-red font-bold uppercase'}>
                        {getStatusText(node.status)}
                      </span>
                    </div>
                  </>
                );
              })()}
            </div>
          )}

        </div>
      </div>

      {/* 4. Validator Directory List */}
      <div className="bg-slate-900/30 border border-white/5 rounded-2xl p-6 backdrop-blur-md">
        <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-6">
          <span className="w-1.5 h-4 bg-brand-purple rounded-full" />
          Active Validator Directory Register ({validators.length})
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead>
              <tr className="border-b border-white/5 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                <th className="py-3 px-2">Node ID Signature</th>
                <th className="py-3 px-2">IP Location</th>
                <th className="py-3 px-2">Stake SPX</th>
                <th className="py-3 px-2">Voting power</th>
                <th className="py-3 px-2">Reward Path</th>
                <th className="py-3 px-2 text-right">Attestation Mode</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-xs">
              {validators.map((val) => {
                const isSelected = selectedNode?.id === val.id;
                return (
                  <tr 
                    key={val.id}
                    onClick={() => setSelectedNode(val === selectedNode ? null : val)}
                    className={`hover:bg-white/[0.02] active:bg-white/[0.04] transition duration-150 cursor-pointer ${
                      isSelected ? 'bg-brand-cyan/5 border-l border-brand-cyan' : ''
                    }`}
                  >
                    <td className="py-3.5 px-2 font-mono text-brand-purple font-semibold flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${
                        val.status === 'active' ? 'bg-brand-green' : (val.status === 'slashed' ? 'bg-brand-red' : 'bg-slate-500')
                      }`} />
                      {val.id}
                    </td>
                    <td className="py-3.5 px-2 font-mono text-slate-400">
                      📍 {val.city}, {val.country}
                    </td>
                    <td className="py-3.5 px-2 font-mono text-white font-bold">
                      {parseFloat(val.stakeSpx).toLocaleString()} SPX
                    </td>
                    <td className="py-3.5 px-2 font-mono text-brand-cyan font-bold">
                      {val.stakePercent.toFixed(2)}%
                    </td>
                    <td className="py-3.5 px-2 font-mono text-slate-500 hover:text-brand-cyan">
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAddress(val.rewardAddress);
                        }}
                        className="hover:underline text-left"
                      >
                        {formatHash(val.rewardAddress, 8)}
                      </button>
                    </td>
                    <td className="py-3.5 px-2 text-right font-mono font-bold text-slate-400">
                      {val.status === 'active' ? 'SPHINCS+ SECURE' : (val.status === 'slashed' ? 'SLASHED / JAILED' : 'OFFLINE')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
