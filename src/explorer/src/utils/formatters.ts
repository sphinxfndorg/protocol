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

  // If already in SPIF format with spaces, return as-is
  if (addr.startsWith('SPIF ')) return addr;

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

export function formatHash(hash: string, len: number = 8): string {
  if (!hash) return '';
  if (hash.length <= len * 2 + 3) return hash;

  // For SPIF addresses, format them first then truncate
  if (hash.startsWith('SPIF ')) {
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