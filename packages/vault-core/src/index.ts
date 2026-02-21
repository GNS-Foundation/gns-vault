/**
 * @gns-vault/core
 *
 * Cryptographic vault engine with Ed25519 identity for the GNS Protocol.
 *
 * ## Quick Start
 *
 * ```typescript
 * import {
 *   generateIdentity,
 *   Vault,
 *   generatePassword,
 *   importCredentials,
 * } from '@gns-vault/core';
 *
 * // 1. Generate a GNS identity
 * const identity = generateIdentity();
 * console.log('Your GNS Identity:', identity.publicKey);
 *
 * // 2. Create a vault secured by this identity
 * const vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);
 *
 * // 3. Add credentials
 * vault.addEntry({
 *   type: 'login',
 *   name: 'My Website',
 *   urls: ['https://example.com'],
 *   username: 'user@example.com',
 *   password: generatePassword({ length: 24 }),
 * });
 *
 * // 4. Encrypt for storage
 * const encrypted = vault.serialize();
 * // Save `encrypted` to disk (IndexedDB, filesystem, etc.)
 *
 * // 5. Later: unlock and use
 * const restored = Vault.unlockWithIdentity(encrypted, identity.privateKey);
 * const entries = restored.findByUrl('https://example.com');
 * ```
 *
 * @module @gns-vault/core
 */

// === Identity & Keys ===
export {
  generateIdentity,
  derivePublicKey,
  sign,
  signBytes,
  verify,
  verifyBytes,
  signAuthChallenge,
  verifyAuthResponse,
  bytesToHex,
  hexToBytes,
  secureRandom,
  uuid,
} from './keys.js';

// === Symmetric Crypto ===
export {
  encrypt,
  decrypt,
  encryptBytes,
  decryptBytes,
  deriveKeyFromPassphrase,
  deriveKeyFromIdentity,
  generateSalt,
  computeHmac,
  verifyHmac,
  passwordStrength,
  hashForBreachCheck,
} from './crypto.js';

// === Vault Engine ===
export { Vault, generatePassword } from './vault.js';

// === Import / Export ===
export { importCredentials, exportCredentials } from './import-export.js';

// === P2P Sync ===
export {
  deriveSyncTopic,
  sealEnvelope,
  unsealEnvelope,
  createFullSyncPayload,
  createEntryAddPayload,
  createEntryUpdatePayload,
  createEntryDeletePayload,
  createPairRequestPayload,
  RelayClient,
  DEFAULT_RELAY_URL,
} from './sync.js';

export type {
  SyncEnvelope,
  SyncPayload,
  DeviceInfo,
  SyncSession,
  RelayClientHandlers,
} from './sync.js';

export { SyncMessageType } from './sync.js';

// === Types ===
export type {
  GnsIdentity,
  TrustScore,
  VaultEntry,
  EncryptedEntry,
  EncryptedVault,
  KdfParams,
  EncryptResult,
  SignatureResult,
  AuthChallenge,
  AuthResponse,
  PasswordGenOptions,
  ImportResult,
  ExportOptions,
  CustomField,
} from './types.js';

export {
  BadgeTier,
  EntryType,
  ImportFormat,
  DEFAULT_KDF_PARAMS,
  DEFAULT_PASSWORD_OPTIONS,
} from './types.js';
