/**
 * GNS Vault — Ed25519 Key Management
 *
 * Identity keypair generation, signing, and verification.
 * The Ed25519 keypair serves triple duty:
 *   1. GNS Protocol identity (public key = identity)
 *   2. Vault encryption master key (derived via HKDF)
 *   3. Stellar wallet address (Ed25519 is Stellar's native scheme)
 *
 * Reference: RFC 8032 (Ed25519)
 *
 * @module @gns-vault/core/keys
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';
import type { GnsIdentity, SignatureResult, AuthChallenge, AuthResponse, BadgeTier } from './types.js';

// Ed25519 requires sha512 — configure noble
ed.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

// ============================================================
// KEY GENERATION
// ============================================================

/**
 * Generate a new GNS identity (Ed25519 keypair).
 *
 * This is the moment a new human identity is born on the GNS Protocol.
 * The private key MUST be stored in the platform's secure enclave
 * (Keychain, Keystore, OS credential store).
 *
 * @returns A new GNS identity with Ed25519 keypair
 */
export function generateIdentity(): GnsIdentity {
  const privateKeyBytes = randomBytes(32);
  const publicKeyBytes = ed.getPublicKey(privateKeyBytes);

  return {
    publicKey: bytesToHex(publicKeyBytes),
    privateKey: bytesToHex(privateKeyBytes),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Derive the public key from a private key.
 * Useful for reconstructing identity from a recovered private key.
 *
 * @param privateKeyHex - Ed25519 private key (32 bytes, hex)
 * @returns Public key (32 bytes, hex)
 */
export function derivePublicKey(privateKeyHex: string): string {
  const privateKey = hexToBytes(privateKeyHex);
  const publicKey = ed.getPublicKey(privateKey);
  return bytesToHex(publicKey);
}

// ============================================================
// SIGNING
// ============================================================

/**
 * Sign a message with the user's Ed25519 private key.
 *
 * Used for:
 *   - GNS Auth challenge-response (proving identity to websites)
 *   - Breadcrumb signing (TrIP — Trajectory Recognition Identity Protocol)
 *   - Message signing (GNS encrypted messaging)
 *
 * @param message - Message to sign (UTF-8 string or hex)
 * @param privateKeyHex - Ed25519 private key (hex)
 * @returns Signature result with signature, public key, and message
 */
export function sign(message: string, privateKeyHex: string): SignatureResult {
  const messageBytes = new TextEncoder().encode(message);
  const privateKey = hexToBytes(privateKeyHex);
  const signature = ed.sign(messageBytes, privateKey);
  const publicKey = ed.getPublicKey(privateKey);

  return {
    signature: bytesToHex(signature),
    publicKey: bytesToHex(publicKey),
    message,
  };
}

/**
 * Sign raw bytes with Ed25519.
 *
 * @param data - Raw bytes to sign
 * @param privateKeyHex - Ed25519 private key (hex)
 * @returns Signature bytes (64 bytes)
 */
export function signBytes(data: Uint8Array, privateKeyHex: string): Uint8Array {
  const privateKey = hexToBytes(privateKeyHex);
  return ed.sign(data, privateKey);
}

// ============================================================
// VERIFICATION
// ============================================================

/**
 * Verify an Ed25519 signature.
 *
 * @param signature - Signature to verify (hex)
 * @param message - Original message (UTF-8 string)
 * @param publicKeyHex - Signer's public key (hex)
 * @returns true if the signature is valid
 */
export function verify(
  signature: string,
  message: string,
  publicKeyHex: string
): boolean {
  try {
    const signatureBytes = hexToBytes(signature);
    const messageBytes = new TextEncoder().encode(message);
    const publicKey = hexToBytes(publicKeyHex);
    return ed.verify(signatureBytes, messageBytes, publicKey);
  } catch {
    return false;
  }
}

/**
 * Verify a signature on raw bytes.
 *
 * @param signature - Signature bytes (64 bytes)
 * @param data - Original data bytes
 * @param publicKeyHex - Signer's public key (hex)
 * @returns true if the signature is valid
 */
export function verifyBytes(
  signature: Uint8Array,
  data: Uint8Array,
  publicKeyHex: string
): boolean {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    return ed.verify(signature, data, publicKey);
  } catch {
    return false;
  }
}

// ============================================================
// GNS AUTH CHALLENGE-RESPONSE
// ============================================================

/**
 * Sign a GNS Auth challenge from a website.
 *
 * The challenge-response protocol:
 *   1. Website sends: { nonce, origin, timestamp, expiresIn }
 *   2. Extension signs: nonce || origin || timestamp
 *   3. Extension returns: { signature, publicKey, trustScore, badgeTier }
 *   4. Website verifies signature against registered public key
 *
 * This replaces password authentication entirely — nothing secret is transmitted.
 *
 * @param challenge - Auth challenge from the website
 * @param privateKeyHex - User's Ed25519 private key
 * @param trustScore - User's current TrIP trust score
 * @param badgeTier - User's current badge tier
 * @param handle - User's @handle (optional)
 * @returns Signed auth response
 */
export function signAuthChallenge(
  challenge: AuthChallenge,
  privateKeyHex: string,
  trustScore: number,
  badgeTier: BadgeTier,
  handle?: string
): AuthResponse {
  // Validate challenge hasn't expired
  const challengeTime = new Date(challenge.timestamp).getTime();
  const now = Date.now();
  if (now - challengeTime > challenge.expiresIn * 1000) {
    throw new Error('Auth challenge has expired');
  }

  // Construct the canonical message: nonce || origin || timestamp
  const canonicalMessage = `${challenge.nonce}|${challenge.origin}|${challenge.timestamp}`;
  const { signature, publicKey } = sign(canonicalMessage, privateKeyHex);

  return {
    nonce: challenge.nonce,
    publicKey,
    signature,
    trustScore,
    badgeTier,
    handle,
  };
}

/**
 * Verify a GNS Auth response (server-side).
 *
 * @param response - Auth response from the user
 * @param challenge - Original challenge that was issued
 * @returns true if the response is valid
 */
export function verifyAuthResponse(
  response: AuthResponse,
  challenge: AuthChallenge
): boolean {
  // Verify nonce matches
  if (response.nonce !== challenge.nonce) return false;

  // Reconstruct canonical message
  const canonicalMessage = `${challenge.nonce}|${challenge.origin}|${challenge.timestamp}`;

  // Verify Ed25519 signature
  return verify(response.signature, canonicalMessage, response.publicKey);
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/** Convert bytes to hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert hex string to bytes */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Generate cryptographically secure random bytes */
export function secureRandom(length: number): Uint8Array {
  return randomBytes(length);
}

/** Generate a UUID v4 */
export function uuid(): string {
  const bytes = randomBytes(16);
  // Set version (4) and variant (RFC 4122)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}
