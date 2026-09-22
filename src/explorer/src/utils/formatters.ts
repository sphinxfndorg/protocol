/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Formats a raw hex address (40 or 64 chars) into SPIF display format:
 * "SPIF XXXX XXXX XXXX ..." (groups of 4 hex characters).
 * If the address already has a SPIF prefix, it returns it unchanged.
 */
export function formatSPIFAddress(addr: string): string {
  if (!addr) return '';

  // If already in SPIF/DEAD format with spaces, return as-is
  if (addr.startsWith('SPIF ') || addr.startsWith('DEAD ')) return addr;

  // If starts with 'spif1_' (old mock format), return as-is for backward compat
  if (addr.startsWith('spif1_')) return addr;

  // Raw hex: normalize and format
  let raw = addr.replace(/\s+/g, '').toLowerCase();

  // Validate hex
  if (!/^[0-9a-f]+$/.test(raw)) return addr;

  // Accept 40-char (legacy 20-byte) or 64-char (SPHINCS+ 32-byte) addresses
  if (raw.length !== 40 && raw.length !== 64) return addr;

  const groups: string[] = [];
  for (let i = 0; i < raw.length; i += 4) {
    groups.push(raw.substring(i, i + 4).toUpperCase());
  }
  return 'SPIF ' + groups.join(' ');
}

/**
 * Formats a raw hex address (40 or 64 chars) into DEAD burn display format:
 * "DEAD XXXX XXXX XXXX ..." (groups of 4 hex characters).
 * DEAD addresses are provably-unspendable burn addresses derived from real
 * SPHINCS+ keys whose private material was destroyed in a burn ceremony.
 */
export function formatDEADAddress(addr: string): string {
  if (!addr) return '';

  if (addr.startsWith('DEAD ')) return addr;

  let raw = addr.replace(/\s+/g, '').replace(/-/g, '');
  if (/^dead/i.test(raw)) raw = raw.slice(4);
  else if (/^spif/i.test(raw)) raw = raw.slice(4);
  raw = raw.toLowerCase();

  if (!/^[0-9a-f]+$/.test(raw)) return addr;
  if (raw.length !== 40 && raw.length !== 64) return addr;

  const groups: string[] = [];
  for (let i = 0; i < raw.length; i += 4) {
    groups.push(raw.substring(i, i + 4).toUpperCase());
  }
  return 'DEAD ' + groups.join(' ');
}

/**
 * Reports whether an address is a DEAD burn address (receive-only).
 */
export function isBurnAddress(addr: string): boolean {
  if (!addr) return false;
  const t = addr.trim();
  if (/^dead[\s-]/i.test(t)) return true;
  // Canonical raw hex of the protocol default burn address also counts.
  const raw = t.replace(/\s+/g, '').replace(/-/g, '').toUpperCase();
  const stripped = raw.replace(/^(SPIF|DEAD)/, '');
  return (
    stripped === '262C098D17D0D99F315CD9B7C4D9AEDA685A65FD8630DEFDCE21F98460B1FA30'
  );
}

/** The protocol default burn address (provably unspendable). */
export const DEFAULT_BURN_ADDRESS =
  'DEAD 262C 098D 17D0 D99F 315C D9B7 C4D9 AEDA 685A 65FD 8630 DEFD CE21 F984 60B1 FA30';

/**
 * Strips "SPIF" prefix, spaces, and hyphens from a SPIF address,
 * returning the raw lower-case hex string.
 * Returns the input unchanged if it doesn't look like a SPIF address.
 */
export function normalizeSPIFAddress(addr: string): string {
  if (!addr) return '';

  let raw = addr.trim();
  if (raw.startsWith('SPIF ')) {
    raw = raw.replace('SPIF ', '').replace(/\s+/g, '').replace(/-/g, '');
    return raw.toLowerCase();
  }

  // Already raw hex or unknown format — just lowercase
  return raw.toLowerCase();
}

export function formatTimeAgo(timestamp: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;
  if (diff < 5) return 'Just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/**
 * Renders a unix timestamp as an absolute UTC date-time. The explorer shows
 * relative ages for scanning and absolute times for auditing; both come from
 * the same block header timestamp.
 */
export function formatFullTimestamp(timestamp: number): string {
  if (!timestamp) return '—';
  return new Date(timestamp * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

/**
 * Formats a confirmation depth. Zero confirmations means the transaction is
 * still pending in the mempool, which is materially different from "1
 * confirmation" and must not be rendered as such.
 */
export function formatConfirmations(confirmations: number): string {
  if (!confirmations || confirmations <= 0) return 'Unconfirmed';
  if (confirmations === 1) return '1 confirmation';
  return `${confirmations.toLocaleString()} confirmations`;
}

/**
 * Renders an SPX amount with enough precision to show the smallest unit (1
 * nSPX = 1e-18 SPX) without collapsing small values to "0", which is what
 * parseFloat().toFixed(4) does to fee-sized amounts.
 */
export function formatSPXAmount(amount: string | number): string {
  const n = typeof amount === 'string' ? parseFloat(amount) : amount;
  if (!Number.isFinite(n) || n === 0) return '0 SPX';

  const abs = Math.abs(n);
  if (abs >= 1000000) return `${(n / 1000000).toLocaleString(undefined, { maximumFractionDigits: 4 })}M SPX`;
  if (abs >= 1) return `${n.toLocaleString(undefined, { maximumFractionDigits: 8 })} SPX`;
  if (abs >= 1e-9) return `${n.toFixed(12)} SPX`;
  // Sub-nSPX-scale values keep 18 decimals: this is the nSPX floor.
  return `${n.toFixed(18)} SPX`;
}

/** Renders an nSPX integer string as a grouped decimal number of nSPX. */
export function formatNSPX(amount: string): string {
  if (!amount) return '0 nSPX';
  try {
    return `${BigInt(amount).toLocaleString()} nSPX`;
  } catch {
    return `${amount} nSPX`;
  }
}

/** Renders a block height as a clickable-looking label, e.g. "#1,204". */
export function formatHeight(height: number): string {
  if (height === undefined || height === null) return '—';
  return `#${height.toLocaleString()}`;
}

export function formatHash(hash: string | undefined, len: number = 8): string {
  if (!hash) return '';
  if (hash.length <= len * 2 + 3) return hash;

  // For SPIF/DEAD addresses, format them first then truncate
  if (hash.startsWith('SPIF ') || hash.startsWith('DEAD ')) {
    return `${hash.substring(0, len + 5)}...${hash.substring(hash.length - len)}`;
  }
  return `${hash.substring(0, len)}...${hash.substring(hash.length - len)}`;
}

export function formatNumber(n: number): string {
  if (n === undefined || n === null) return '0';
  if (n >= 1000000000) return (n / 1000000000).toFixed(2) + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(2) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(2) + 'K';
  return n.toLocaleString();
}

export function formatSPX(amount: string | number): string {
  if (!amount) return '0 SPX';
  const n = typeof amount === 'string' ? parseFloat(amount) : amount;
  if (n === 0) return '0 SPX';
  if (n >= 1000000) return (n / 1000000).toFixed(2) + 'M SPX';
  if (n >= 1) return n.toFixed(4) + ' SPX';
  if (n >= 0.001) return n.toFixed(6) + ' SPX';
  return n.toFixed(8) + ' SPX';
}
