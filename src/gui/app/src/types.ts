/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface ActiveSession {
  passphrase: string;
  fingerprint: string; // did:usi:0x4F...3B92
  rawFingerprint: string; // hash representation
  orgCode: string; // "SPIF"
}

export type ActivityType =
  | 'ENCRYPT'
  | 'DECRYPT'
  | 'SIGN'
  | 'VERIFY'
  | 'LOGIN'
  | 'REGISTER'
  | 'WALLET_SEND'
  | 'WIPE'
  | 'HARDWARE_AUTH'
  | 'SETTINGS';

export interface ActivityLog {
  id: string;
  timestamp: string; // formatted time e.g., "2026-06-15 13:00:15"
  type: ActivityType;
  detail: string;
  status: 'SUCCESS' | 'FAILURE';
}

export type TxDirection = 'in' | 'out';
export type TxStatus = 'confirmed' | 'pending' | 'failed';

export interface Transaction {
  id: string;
  timestamp: string;
  direction: TxDirection;
  amount: string;
  peer: string;
  memo: string;
  status: TxStatus;
}

export interface EncryptedVaultPayload {
  version: string; // v2.4.0-STABLE
  sender: string; // public fingerprint of creator
  senderOrg: string; // e.g. SPIF
  recipients: string[]; // authorized recipient DIDs
  embeddedMessage?: string; // encrypted secure message
  originalName: string; // file/folder source name
  cipherBytes: string; // mock encryption payload
}

export interface SignatureMetadata {
  version: string; // v2.4.0-STABLE
  signer: string; // SPHINCS+ signer DID
  orgCode: string; // original organization code
  timestamp: number; // unix timestamp of signature
  documentTitle: string; // filename associated with
  sha256Hash: string; // SHA-256 of original data
  signatureString: string; // mock SPHINCS+ key signature block
}
