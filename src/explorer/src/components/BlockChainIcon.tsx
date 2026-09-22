/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dedicated 3D Isometric Box-Shaped Block & Interlocking Physical Chain Links Component.
 * Inspired by the iconic mempool.space block visualization:
 * - 3D isometric box with transaction capacity fill
 * - Heavy physical interlocking chain links structurally binding adjacent blocks
 * - Produced / Mempool (Amber-Orange) vs Confirmed / Mined (Indigo-Purple-Emerald)
 */

import { useState, useEffect } from 'react';
import { CheckCircle } from 'lucide-react';

export type BlockState = 'produced' | 'confirmed' | 'pending' | 'finalized' | 'idle';

export interface BlockChainIconProps {
  /** Visual dimension in pixels or predefined size token */
  size?: 'sm' | 'md' | 'lg' | 'hero' | number;
  /** State of the block: produced (mempool/orange) vs confirmed (mined/purple-indigo) */
  state?: BlockState;
  /** Block height number to engrave on the isometric face */
  height?: number;
  /** Transaction count or fullness percentage (0-100) */
  fullness?: number;
  /** Whether to enable subtle ambient animations */
  animated?: boolean;
  /** Custom className */
  className?: string;
  /** Optional interactive switch between produced & confirmed for showcase */
  showControls?: boolean;
  /** Optional trigger key to trigger subtle state transition */
  triggerKey?: number | string;
  /** Whether to show status badge below icon (default: true for size >= 64) */
  showBadge?: boolean;
}

export default function BlockChainIcon({
  size = 'md',
  state = 'confirmed',
  height,
  fullness = 82,
  animated = true,
  className = '',
  showControls = false,
  triggerKey,
  showBadge = true,
}: BlockChainIconProps) {
  const [internalState, setInternalState] = useState<BlockState>(state);

  useEffect(() => {
    setInternalState(state);
  }, [state, triggerKey]);

  const activeState = showControls ? internalState : state;

  const dim = typeof size === 'number'
    ? size
    : size === 'sm' ? 36
    : size === 'md' ? 64
    : size === 'lg' ? 140
    : 220;

  const isProduced = activeState === 'produced' || activeState === 'pending';
  const isConfirmed = activeState === 'confirmed' || activeState === 'finalized';

  // Mempool.space signature palette:
  // - Produced / Mempool: warm amber, fiery orange, golden specular highlights
  // - Confirmed / Mined: signature mempool deep indigo/purple, violet edge, emerald seal
  const colors = isProduced
    ? {
        accent: '#f97316',
        accentGlow: 'rgba(249, 115, 22, 0.45)',
        topCap: '#fb923c',
        topCapDark: '#ea580c',
        leftFace: '#9a3412',
        leftFaceDark: '#431407',
        rightFace: '#c2410c',
        rightFaceDark: '#7c2d12',
        fillLeft: '#ea580c',
        fillRight: '#f97316',
        fillTop: '#fde047',
        chainGradStart: '#ffedd5',
        chainGradMid: '#f97316',
        chainGradEnd: '#7c2d12',
        chainBorder: '#fb923c',
        badgeClass: 'text-amber-400 border-amber-500/30 bg-amber-500/10 shadow-[0_0_12px_rgba(245,158,11,0.2)]',
        badgeLabel: 'PRODUCED · MEMPOOL',
      }
    : {
        accent: '#818cf8',
        accentGlow: 'rgba(99, 102, 241, 0.45)',
        topCap: '#6366f1',
        topCapDark: '#3730a3',
        leftFace: '#1e1b4b',
        leftFaceDark: '#0f172a',
        rightFace: '#312e81',
        rightFaceDark: '#1e1b4b',
        fillLeft: '#3730a3',
        fillRight: '#4f46e5',
        fillTop: '#22ff88',
        chainGradStart: '#e0e7ff',
        chainGradMid: '#6366f1',
        chainGradEnd: '#1e1b4b',
        chainBorder: '#a5b4fc',
        badgeClass: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10 shadow-[0_0_12px_rgba(16,185,129,0.2)]',
        badgeLabel: 'CONFIRMED · MINED',
      };

  // Calculate isometric fill height (from y=160 bottom to y=93 middle)
  // Fill fraction ranges 0.3 to 0.95
  const fillFrac = Math.min(0.95, Math.max(0.3, fullness / 100));
  const fillY = 160 - (160 - 93) * fillFrac;
  const fillLeftY = 127 - (127 - 59) * fillFrac;
  const fillRightY = 127 - (127 - 59) * fillFrac;

  return (
    <div className={`inline-flex flex-col items-center justify-center select-none ${className}`}>
      {/* 3D Isometric Box-Shaped Block & Interlocking Physical Chain Links */}
      <svg
        width={dim}
        height={dim}
        viewBox="0 0 200 200"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className={`transition-all duration-300 ${animated ? 'hover:scale-[1.03]' : ''}`}
      >
        <defs>
          {/* Top Diamond Face Gradient */}
          <linearGradient id={`mempool-top-${dim}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={colors.topCap} />
            <stop offset="100%" stopColor={colors.topCapDark} />
          </linearGradient>

          {/* Left Isometric Face Gradient */}
          <linearGradient id={`mempool-left-${dim}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={colors.leftFace} />
            <stop offset="100%" stopColor={colors.leftFaceDark} />
          </linearGradient>

          {/* Right Isometric Face Gradient */}
          <linearGradient id={`mempool-right-${dim}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={colors.rightFace} />
            <stop offset="100%" stopColor={colors.rightFaceDark} />
          </linearGradient>

          {/* Transaction Capacity Fill Gradients (Mempool-style fill level) */}
          <linearGradient id={`fill-left-${dim}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={colors.fillLeft} />
            <stop offset="100%" stopColor={colors.leftFaceDark} />
          </linearGradient>
          <linearGradient id={`fill-right-${dim}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={colors.fillRight} />
            <stop offset="100%" stopColor={colors.rightFaceDark} />
          </linearGradient>
          <linearGradient id={`fill-top-${dim}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={colors.fillTop} stopOpacity="0.8" />
            <stop offset="100%" stopColor={colors.accent} stopOpacity="0.4" />
          </linearGradient>

          {/* Physical Chain Link Metallic Gradients */}
          <linearGradient id={`chain-h-${dim}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={colors.chainGradStart} />
            <stop offset="35%" stopColor={colors.chainGradMid} />
            <stop offset="70%" stopColor={colors.chainGradEnd} />
            <stop offset="100%" stopColor={colors.chainGradMid} />
          </linearGradient>

          <linearGradient id={`chain-v-${dim}`} x1="1" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={colors.chainGradStart} />
            <stop offset="35%" stopColor={colors.chainGradMid} />
            <stop offset="70%" stopColor={colors.chainGradEnd} />
            <stop offset="100%" stopColor={colors.chainGradMid} />
          </linearGradient>

          {/* Ground Ambient Reflection */}
          <radialGradient id={`shadow-${dim}`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={colors.accent} stopOpacity={isProduced ? '0.45' : '0.3'} />
            <stop offset="65%" stopColor={colors.accent} stopOpacity="0.08" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>

          {/* Subtle Bloom Glow */}
          <filter id={`bloom-${dim}`} x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2.5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* 1. Ground Shadow & Isometric Base Grid */}
        <ellipse cx="100" cy="172" rx="72" ry="20" fill={`url(#shadow-${dim})`} />

        {/* 2. REAR INTERLOCKING PHYSICAL CHAIN LINKS (Entering Left Shackle) */}
        <g id="rear-interlocking-chain" className={animated ? (isProduced ? 'animate-chain-left-thread' : 'animate-chain-tension-latch') : ''}>
          {/* Link 1 (Horizontal Link connecting from predecessor block) */}
          <path
            d="M 4 120 C 4 110, 20 102, 38 110 L 48 115 C 58 120, 60 134, 48 140 L 38 145 C 20 153, 4 142, 4 128 Z"
            fill={`url(#chain-h-${dim})`}
            stroke={colors.chainBorder}
            strokeWidth="1.6"
          />
          {/* Link 1 Inner Opening */}
          <path
            d="M 14 122 C 14 118, 24 114, 32 118 L 38 121 C 44 124, 44 132, 38 135 L 32 138 C 24 142, 14 136, 14 128 Z"
            fill="#060913"
            stroke={colors.chainBorder}
            strokeWidth="1"
            strokeOpacity="0.6"
          />

          {/* Link 2 (Vertical Link interlocking into Link 1 and passing into the block anchor) */}
          <path
            d="M 32 126 C 32 112, 50 102, 66 110 L 76 115 C 88 121, 88 135, 76 141 L 66 146 C 50 154, 32 142, 32 128 Z"
            fill={`url(#chain-v-${dim})`}
            stroke={colors.chainBorder}
            strokeWidth="1.6"
          />
          {/* Link 2 Inner Opening */}
          <path
            d="M 42 126 C 42 120, 52 114, 60 118 L 66 121 C 72 124, 72 132, 66 135 L 60 138 C 52 142, 42 136, 42 128 Z"
            fill="#060913"
            stroke={colors.chainBorder}
            strokeWidth="1"
            strokeOpacity="0.6"
          />
        </g>

        {/* 3. 3D ISOMETRIC BOX-SHAPED BLOCK (MEMPOOL.SPACE CUBE) */}
        
        {/* Left Isometric Face Base */}
        <polygon
          points="42,59 100,93 100,160 42,127"
          fill={`url(#mempool-left-${dim})`}
          stroke={colors.accent}
          strokeWidth="1.8"
          strokeLinejoin="round"
          className={animated && isProduced ? 'animate-facet-left' : ''}
        />

        {/* Left Face Capacity Fill (Mempool-style transaction density) */}
        <polygon
          points={`42,${fillLeftY} 100,${fillY} 100,160 42,127`}
          fill={`url(#fill-left-${dim})`}
          opacity="0.85"
        />

        {/* Left Face Sub-dividers (Transaction Rows) */}
        <g stroke={colors.accent} strokeWidth="1" opacity="0.35">
          <line x1="42" y1="82" x2="100" y2="116" strokeDasharray="3 3" />
          <line x1="42" y1="104" x2="100" y2="138" strokeDasharray="3 3" />
        </g>

        {/* Right Isometric Face Base */}
        <polygon
          points="100,93 158,59 158,127 100,160"
          fill={`url(#mempool-right-${dim})`}
          stroke={colors.accent}
          strokeWidth="1.8"
          strokeLinejoin="round"
          className={animated && isProduced ? 'animate-facet-right' : ''}
        />

        {/* Right Face Capacity Fill */}
        <polygon
          points={`100,${fillY} 158,${fillRightY} 158,127 100,160`}
          fill={`url(#fill-right-${dim})`}
          opacity="0.85"
        />

        {/* Right Face Sub-dividers (SPHINCS+ / Merkle Lattice Rows) */}
        <g stroke={colors.accent} strokeWidth="1" opacity="0.35">
          <line x1="100" y1="116" x2="158" y2="82" strokeDasharray="3 3" />
          <line x1="100" y1="138" x2="158" y2="104" strokeDasharray="3 3" />
        </g>

        {/* Transaction Fill Meniscus (Internal Top Diamond Surface) */}
        <polygon
          points={`100,${fillY - 34} 158,${fillRightY} 100,${fillY} 42,${fillLeftY}`}
          fill={`url(#fill-top-${dim})`}
          stroke={colors.accent}
          strokeWidth="1"
          strokeOpacity="0.7"
        />

        {/* Top Isometric Diamond Cap */}
        <polygon
          points="100,26 158,59 100,93 42,59"
          fill={`url(#mempool-top-${dim})`}
          stroke={colors.accent}
          strokeWidth="2"
          strokeLinejoin="round"
          className={animated && isProduced ? 'animate-facet-top' : ''}
        />

        {/* Top Face Inner Inset Diamond */}
        <polygon
          points="100,38 140,60 100,81 60,60"
          fill="none"
          stroke={colors.chainBorder}
          strokeWidth="1.2"
          strokeDasharray={isProduced ? '4 3' : 'none'}
          opacity="0.75"
        />

        {/* Central Vertical Isometric Ridge */}
        <line
          x1="100"
          y1="93"
          x2="100"
          y2="160"
          stroke={colors.accent}
          strokeWidth="2.4"
          strokeLinecap="round"
          filter={`url(#bloom-${dim})`}
          className={animated && isProduced ? 'animate-ridge-scan' : ''}
        />

        {/* 4. PHYSICAL ANCHOR SHACKLES (Heavy Metal Eyelets Welded to Block) */}
        {/* Left Shackle Eyelet */}
        <path
          d="M 40 120 C 35 123, 35 131, 40 134 L 46 137 C 50 139, 53 135, 51 131 L 47 124 C 45 121, 42 119, 40 120 Z"
          fill={`url(#chain-h-${dim})`}
          stroke={colors.chainBorder}
          strokeWidth="1.4"
        />

        {/* Right Shackle Eyelet */}
        <path
          d="M 160 120 C 165 123, 165 131, 160 134 L 154 137 C 150 139, 147 135, 149 131 L 153 124 C 155 121, 158 119, 160 120 Z"
          fill={`url(#chain-h-${dim})`}
          stroke={colors.chainBorder}
          strokeWidth="1.4"
        />

        {/* 5. FOREGROUND INTERLOCKING PHYSICAL CHAIN LINKS (Exiting Right Shackle) */}
        <g id="foreground-interlocking-chain" className={animated ? (isProduced ? 'animate-chain-right-thread' : 'animate-chain-tension-latch') : ''}>
          {/* Link 3 (Horizontal link passing through the Right Shackle) */}
          <path
            d="M 132 118 C 122 114, 124 102, 142 108 L 156 113 C 170 119, 172 131, 160 137 L 146 142 C 130 148, 122 136, 132 118 Z"
            fill={`url(#chain-h-${dim})`}
            stroke={colors.chainBorder}
            strokeWidth="1.6"
          />
          <path
            d="M 138 120 C 134 118, 136 112, 146 115 L 153 118 C 160 121, 161 127, 154 130 L 147 133 C 139 136, 135 129, 138 120 Z"
            fill="#060913"
            stroke={colors.chainBorder}
            strokeWidth="1"
            strokeOpacity="0.6"
          />

          {/* Link 4 (Vertical link extending toward successor block) */}
          <path
            d="M 152 122 C 146 108, 166 98, 182 106 L 194 112 C 206 118, 204 132, 192 138 L 180 144 C 164 151, 148 138, 152 122 Z"
            fill={`url(#chain-v-${dim})`}
            stroke={colors.chainBorder}
            strokeWidth="1.6"
          />
          <path
            d="M 160 123 C 158 116, 168 111, 176 115 L 184 119 C 191 122, 192 129, 185 132 L 177 136 C 169 139, 160 133, 160 123 Z"
            fill="#060913"
            stroke={colors.chainBorder}
            strokeWidth="1"
            strokeOpacity="0.6"
          />
        </g>

        {/* 6. Engraved Mempool Block Height Badge (on Left Face) */}
        {height !== undefined && (
          <g>
            <rect
              x="52"
              y="94"
              width="40"
              height="16"
              rx="3"
              fill="#060b14"
              fillOpacity="0.88"
              stroke={colors.accent}
              strokeWidth="0.9"
            />
            <text
              x="72"
              y="106"
              fill={colors.accent}
              fontSize="9"
              fontFamily="monospace"
              fontWeight="bold"
              textAnchor="middle"
            >
              #{height}
            </text>
          </g>
        )}

        {/* 7. Confirmation Status Seal (on Right Face) */}
        <g transform="translate(112, 94)">
          {isConfirmed ? (
            <g className={animated ? 'animate-padlock-engage' : ''}>
              <circle cx="16" cy="14" r="12" fill="#061a12" stroke="#22ff88" strokeWidth="1.2" />
              <path
                d="M 12 12 L 12 9 C 12 6.8, 20 6.8, 20 9 L 20 12"
                fill="none"
                stroke="#22ff88"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
              <rect x="10" y="11" width="12" height="9" rx="1.5" fill="#22ff88" />
              <circle cx="16" cy="15.5" r="1.2" fill="#061a12" />
            </g>
          ) : (
            <g className={animated ? 'animate-spin-slow origin-center' : ''}>
              <circle cx="16" cy="14" r="12" fill="#2a1205" stroke="#f97316" strokeWidth="1.2" strokeDasharray="3 3" />
              <polygon points="16,6 23,18 9,18" fill="none" stroke="#f97316" strokeWidth="1.2" />
            </g>
          )}
        </g>
      </svg>

      {/* Clean Status Badge */}
      {showBadge && dim >= 64 && (
        <div className="mt-2.5 flex items-center gap-1.5 transition-all duration-200">
          <div className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wider border ${colors.badgeClass} flex items-center gap-1.5`}>
            {isConfirmed ? (
              <CheckCircle className="w-3 h-3 text-emerald-400 shrink-0" />
            ) : (
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0 animate-ping" />
            )}
            <span>{colors.badgeLabel}</span>
          </div>
        </div>
      )}

      {/* Clean 2-State Switch (for interactive showcase) */}
      {showControls && (
        <div className="mt-3 flex items-center gap-1 p-1 bg-slate-900/90 border border-white/10 rounded-xl">
          <button
            onClick={() => setInternalState('produced')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition cursor-pointer ${
              activeState === 'produced'
                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30 shadow-[0_0_8px_rgba(245,158,11,0.25)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Produced
          </button>
          <button
            onClick={() => setInternalState('confirmed')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition cursor-pointer ${
              activeState === 'confirmed'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 shadow-[0_0_8px_rgba(34,255,136,0.25)]'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Confirmed
          </button>
        </div>
      )}
    </div>
  );
}
