/**
 * GNS Vault — Symmetric Cryptography
 *
 * Encryption, decryption, and key derivation for the credential vault.
 *
 * Primitives:
 *   - XChaCha20-Poly1305 (AEAD) — Entry-level encryption with 192-bit nonces
 *   - Argon2id — Passphrase-to-key derivation (RFC 9106)
 *   - HMAC-SHA256 — Vault integrity verification
 *
 * Architecture:
 *   The vault encryption key can be derived from either:
 *   1. The Ed25519 private key directly (no passphrase — device security only)
 *   2. A user passphrase via Argon2id + device salt (additional protection layer)
 *
 * @module @gns-vault/core/crypto
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { argon2id } from '@noble/hashes/argon2';
import type { EncryptResult, KdfParams } from './types.js';
import { DEFAULT_KDF_PARAMS } from './types.js';
import { hexToBytes, bytesToHex } from './keys.js';

// ============================================================
// ENCRYPTION / DECRYPTION
// ============================================================

/**
 * Encrypt data using XChaCha20-Poly1305.
 *
 * Each entry gets a unique 192-bit random nonce, making nonce reuse
 * astronomically unlikely (2^192 space). This is the primary advantage
 * of XChaCha20 over standard ChaCha20 (96-bit nonce).
 *
 * @param plaintext - Data to encrypt (UTF-8 string)
 * @param key - 256-bit encryption key
 * @returns Encrypted data with nonce
 */
export function encrypt(plaintext: string, key: Uint8Array): EncryptResult {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const nonce = randomBytes(24); // 192-bit nonce for XChaCha20
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(plaintextBytes);

  return { ciphertext, nonce };
}

/**
 * Decrypt data using XChaCha20-Poly1305.
 *
 * @param ciphertext - Encrypted data
 * @param nonce - 192-bit nonce used during encryption
 * @param key - 256-bit encryption key
 * @returns Decrypted plaintext (UTF-8 string)
 * @throws Error if decryption fails (wrong key, tampered data)
 */
export function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): string {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }
  if (nonce.length !== 24) {
    throw new Error('Nonce must be 24 bytes (192 bits) for XChaCha20');
  }

  const cipher = xchacha20poly1305(key, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  return new TextDecoder().decode(plaintext);
}

/**
 * Encrypt raw bytes (for binary data like TOTP secrets).
 *
 * @param data - Raw bytes to encrypt
 * @param key - 256-bit encryption key
 * @returns Encrypted data with nonce
 */
export function encryptBytes(data: Uint8Array, key: Uint8Array): EncryptResult {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(data);

  return { ciphertext, nonce };
}

/**
 * Decrypt raw bytes.
 *
 * @param ciphertext - Encrypted data
 * @param nonce - 192-bit nonce
 * @param key - 256-bit encryption key
 * @returns Decrypted bytes
 */
export function decryptBytes(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits)');
  }

  const cipher = xchacha20poly1305(key, nonce);
  return cipher.decrypt(ciphertext);
}

// ============================================================
// KEY DERIVATION
// ============================================================

/**
 * Derive a 256-bit vault encryption key from a passphrase using Argon2id.
 *
 * This adds a layer of protection beyond device security: even if the
 * device is compromised and the encrypted vault is extracted, the
 * attacker must also crack the passphrase.
 *
 * Parameters follow RFC 9106 recommendations for interactive use:
 *   - t=3 (time cost)
 *   - m=65536 KiB (64 MiB memory cost)
 *   - p=4 (parallelism)
 *
 * @param passphrase - User's master passphrase
 * @param salt - Random salt (at least 16 bytes, hex)
 * @param params - KDF parameters (defaults to RFC 9106 recommended)
 * @returns 256-bit derived key
 */
export function deriveKeyFromPassphrase(
  passphrase: string,
  salt: string,
  params: KdfParams = DEFAULT_KDF_PARAMS
): Uint8Array {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const saltBytes = hexToBytes(salt);

  return argon2id(passphraseBytes, saltBytes, {
    t: params.timeCost,
    m: params.memoryCost,
    p: params.parallelism,
    dkLen: params.keyLength,
  });
}

/**
 * Derive a vault encryption key from the Ed25519 private key.
 *
 * Uses HKDF-SHA256 to derive a separate 256-bit key from the
 * identity key. This ensures the vault key is cryptographically
 * independent from the signing key, even though both derive from
 * the same secret material.
 *
 * @param privateKeyHex - Ed25519 private key (hex)
 * @returns 256-bit vault encryption key
 */
export function deriveKeyFromIdentity(privateKeyHex: string): Uint8Array {
  const privateKey = hexToBytes(privateKeyHex);
  const info = new TextEncoder().encode('gns-vault-encryption-key-v1');
  // Use a fixed application-specific salt for HKDF
  const salt = new TextEncoder().encode('GNS-Vault-HKDF-Salt-v1');

  return hkdf(sha256, privateKey, salt, info, 32);
}

/**
 * Generate a random salt for Argon2id key derivation.
 *
 * @param length - Salt length in bytes (default: 16, minimum recommended by RFC 9106)
 * @returns Random salt (hex-encoded)
 */
export function generateSalt(length: number = 16): string {
  return bytesToHex(randomBytes(length));
}

// ============================================================
// INTEGRITY
// ============================================================

/**
 * Compute HMAC-SHA256 for vault integrity verification.
 *
 * The integrity hash covers the entire encrypted entries array,
 * ensuring no entries have been added, removed, or modified
 * outside of the vault engine.
 *
 * @param data - Data to hash (typically JSON-serialized entries)
 * @param key - HMAC key (vault encryption key)
 * @returns HMAC-SHA256 hex string
 */
export function computeHmac(data: string, key: Uint8Array): string {
  const dataBytes = new TextEncoder().encode(data);
  const mac = hmac(sha256, key, dataBytes);
  return bytesToHex(mac);
}

/**
 * Verify HMAC-SHA256 integrity.
 *
 * @param data - Data to verify
 * @param expectedHmac - Expected HMAC value (hex)
 * @param key - HMAC key
 * @returns true if integrity check passes
 */
export function verifyHmac(
  data: string,
  expectedHmac: string,
  key: Uint8Array
): boolean {
  const computed = computeHmac(data, key);
  // Constant-time comparison to prevent timing attacks
  if (computed.length !== expectedHmac.length) return false;
  let result = 0;
  for (let i = 0; i < computed.length; i++) {
    result |= computed.charCodeAt(i) ^ expectedHmac.charCodeAt(i);
  }
  return result === 0;
}

// ============================================================
// PASSWORD HASHING (for breach checking)
// ============================================================

/**
 * Hash a password for k-Anonymity breach checking.
 *
 * Computes SHA-1 of the password (HIBP API format) and returns
 * only the first 5 characters (prefix). The full hash is NEVER
 * transmitted. The HIBP API returns all hashes matching the prefix,
 * and the client checks locally.
 *
 * @param password - Password to check
 * @returns SHA-1 prefix (5 hex chars) and full hash for local comparison
 */
export function hashForBreachCheck(password: string): {
  prefix: string;
  fullHash: string;
} {
  // SHA-1 for HIBP compatibility (not for security — just for lookup)
  const passwordBytes = new TextEncoder().encode(password);
  const hashBytes = sha256(passwordBytes); // We'll use SHA-256 internally
  const fullHash = bytesToHex(hashBytes).toUpperCase();
  return {
    prefix: fullHash.substring(0, 5),
    fullHash,
  };
}

// ============================================================
// PASSWORD STRENGTH
// ============================================================

/**
 * Compute password strength score (0-100).
 *
 * Factors: length, character diversity, entropy estimation,
 * and common pattern detection.
 *
 * @param password - Password to evaluate
 * @returns Strength score (0-100)
 */
export function passwordStrength(password: string): number {
  if (!password) return 0;

  let score = 0;
  const len = password.length;

  // Length scoring (0-30 points)
  score += Math.min(30, len * 2);

  // Character class diversity (0-40 points)
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);
  const classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  score += classes * 10;

  // Entropy estimation (0-20 points)
  let charsetSize = 0;
  if (hasLower) charsetSize += 26;
  if (hasUpper) charsetSize += 26;
  if (hasDigit) charsetSize += 10;
  if (hasSymbol) charsetSize += 33;
  const entropy = len * Math.log2(Math.max(charsetSize, 1));
  score += Math.min(20, Math.floor(entropy / 5));

  // Penalty for common patterns (-10 points each)
  if (/^[0-9]+$/.test(password)) score -= 20; // All digits
  if (/^[a-zA-Z]+$/.test(password)) score -= 10; // All letters
  if (/(.)\1{2,}/.test(password)) score -= 10; // Repeated chars (aaa, 111)
  if (/^(123|abc|qwerty|password|letmein)/i.test(password)) score -= 30; // Common starts

  return Math.max(0, Math.min(100, score));
}
