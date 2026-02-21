/**
 * GNS Vault — Vault Engine
 *
 * The core vault management system. Handles:
 *   - Creating and unlocking vaults
 *   - CRUD operations on credential entries
 *   - Encrypting entries for storage
 *   - Decrypting entries for use
 *   - Password generation
 *   - Vault integrity verification
 *
 * All plaintext credentials exist ONLY in memory. At rest, every
 * entry is individually encrypted with XChaCha20-Poly1305 using
 * a unique nonce.
 *
 * @module @gns-vault/core/vault
 */

import type {
  VaultEntry,
  EncryptedEntry,
  EncryptedVault,
  PasswordGenOptions,
} from './types.js';
import {
  DEFAULT_KDF_PARAMS,
  DEFAULT_PASSWORD_OPTIONS,
} from './types.js';
import {
  encrypt,
  decrypt,
  deriveKeyFromPassphrase,
  deriveKeyFromIdentity,
  generateSalt,
  computeHmac,
  verifyHmac,
  passwordStrength,
} from './crypto.js';
import { bytesToHex, hexToBytes, uuid, secureRandom } from './keys.js';

// ============================================================
// VAULT CLASS
// ============================================================

/**
 * The GNS Vault.
 *
 * Manages encrypted credential storage with full CRUD operations.
 * The vault key is held in memory only while the vault is unlocked.
 * When locked, no plaintext data is accessible.
 */
export class Vault {
  private entries: Map<string, VaultEntry> = new Map();
  private vaultKey: Uint8Array | null = null;
  private ownerPublicKey: string;
  private kdfSalt: string;

  constructor(ownerPublicKey: string) {
    this.ownerPublicKey = ownerPublicKey;
    this.kdfSalt = generateSalt();
  }

  // ==========================================================
  // LIFECYCLE
  // ==========================================================

  /**
   * Create a new vault, unlocked with the identity key.
   *
   * This is the default mode: the vault is secured by the device's
   * secure enclave (where the Ed25519 private key is stored).
   * No passphrase required unless the user opts in.
   *
   * @param privateKeyHex - Ed25519 private key (hex)
   * @returns The vault instance (unlocked)
   */
  static createWithIdentity(
    ownerPublicKey: string,
    privateKeyHex: string
  ): Vault {
    const vault = new Vault(ownerPublicKey);
    vault.vaultKey = deriveKeyFromIdentity(privateKeyHex);
    return vault;
  }

  /**
   * Create a new vault, unlocked with a master passphrase.
   *
   * Adds Argon2id protection on top of device security.
   *
   * @param ownerPublicKey - Ed25519 public key (hex)
   * @param passphrase - User's master passphrase
   * @returns The vault instance (unlocked)
   */
  static createWithPassphrase(
    ownerPublicKey: string,
    passphrase: string
  ): Vault {
    const vault = new Vault(ownerPublicKey);
    vault.vaultKey = deriveKeyFromPassphrase(
      passphrase,
      vault.kdfSalt,
      DEFAULT_KDF_PARAMS
    );
    return vault;
  }

  /**
   * Load and unlock an existing vault from encrypted storage.
   *
   * @param encrypted - The encrypted vault data
   * @param privateKeyHex - Ed25519 private key to derive vault key
   * @returns The unlocked vault
   * @throws Error if decryption or integrity check fails
   */
  static unlockWithIdentity(
    encrypted: EncryptedVault,
    privateKeyHex: string
  ): Vault {
    const vault = new Vault(encrypted.ownerPublicKey);
    vault.kdfSalt = encrypted.kdfSalt;
    vault.vaultKey = deriveKeyFromIdentity(privateKeyHex);

    vault.loadEncryptedEntries(encrypted);
    return vault;
  }

  /**
   * Load and unlock an existing vault with a passphrase.
   *
   * @param encrypted - The encrypted vault data
   * @param passphrase - User's master passphrase
   * @returns The unlocked vault
   * @throws Error if decryption or integrity check fails
   */
  static unlockWithPassphrase(
    encrypted: EncryptedVault,
    passphrase: string
  ): Vault {
    const vault = new Vault(encrypted.ownerPublicKey);
    vault.kdfSalt = encrypted.kdfSalt;
    vault.vaultKey = deriveKeyFromPassphrase(
      passphrase,
      encrypted.kdfSalt,
      encrypted.kdfParams
    );

    vault.loadEncryptedEntries(encrypted);
    return vault;
  }

  /**
   * Lock the vault, clearing all plaintext data from memory.
   */
  lock(): void {
    this.entries.clear();
    if (this.vaultKey) {
      // Zero-fill the key in memory
      this.vaultKey.fill(0);
      this.vaultKey = null;
    }
  }

  /** Check if the vault is currently unlocked */
  get isUnlocked(): boolean {
    return this.vaultKey !== null;
  }

  // ==========================================================
  // CRUD OPERATIONS
  // ==========================================================

  /**
   * Add a new credential entry to the vault.
   *
   * @param entry - Partial entry (id and timestamps are auto-generated)
   * @returns The complete entry with generated fields
   */
  addEntry(entry: Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt' | 'favorite'> & { favorite?: boolean }): VaultEntry {
    this.requireUnlocked();

    const now = new Date().toISOString();
    const complete: VaultEntry = {
      id: uuid(),
      favorite: false,
      ...entry,
      createdAt: now,
      updatedAt: now,
      passwordStrength: entry.password ? passwordStrength(entry.password) : undefined,
    };

    this.entries.set(complete.id, complete);
    return complete;
  }

  /**
   * Get a credential entry by ID.
   *
   * @param id - Entry ID
   * @returns The entry, or undefined if not found
   */
  getEntry(id: string): VaultEntry | undefined {
    this.requireUnlocked();
    return this.entries.get(id);
  }

  /**
   * Update an existing credential entry.
   *
   * @param id - Entry ID
   * @param updates - Fields to update
   * @returns The updated entry
   * @throws Error if entry not found
   */
  updateEntry(
    id: string,
    updates: Partial<Omit<VaultEntry, 'id' | 'createdAt'>>
  ): VaultEntry {
    this.requireUnlocked();

    const existing = this.entries.get(id);
    if (!existing) throw new Error(`Entry not found: ${id}`);

    const updated: VaultEntry = {
      ...existing,
      ...updates,
      id: existing.id, // Never overwrite ID
      createdAt: existing.createdAt, // Never overwrite creation time
      updatedAt: new Date().toISOString(),
      passwordStrength: updates.password
        ? passwordStrength(updates.password)
        : existing.passwordStrength,
    };

    this.entries.set(id, updated);
    return updated;
  }

  /**
   * Delete a credential entry.
   *
   * @param id - Entry ID
   * @returns true if the entry was deleted
   */
  deleteEntry(id: string): boolean {
    this.requireUnlocked();
    return this.entries.delete(id);
  }

  /**
   * Get all entries in the vault.
   *
   * @returns Array of all vault entries
   */
  getAllEntries(): VaultEntry[] {
    this.requireUnlocked();
    return Array.from(this.entries.values());
  }

  /**
   * Search entries by URL, name, or username.
   *
   * Used by the auto-fill engine to find matching credentials.
   *
   * @param query - Search query (URL, name, or username)
   * @returns Matching entries, sorted by relevance
   */
  searchEntries(query: string): VaultEntry[] {
    this.requireUnlocked();
    const q = query.toLowerCase();

    return Array.from(this.entries.values())
      .filter(entry => {
        // Match against URLs
        if (entry.urls.some(url => url.toLowerCase().includes(q))) return true;
        // Match against name
        if (entry.name.toLowerCase().includes(q)) return true;
        // Match against username
        if (entry.username.toLowerCase().includes(q)) return true;
        return false;
      })
      .sort((a, b) => {
        // Prioritize URL matches, then name, then username
        const aUrlMatch = a.urls.some(u => u.toLowerCase().includes(q)) ? 0 : 1;
        const bUrlMatch = b.urls.some(u => u.toLowerCase().includes(q)) ? 0 : 1;
        if (aUrlMatch !== bUrlMatch) return aUrlMatch - bUrlMatch;

        // Then by last used (most recent first)
        const aTime = a.lastUsedAt ? new Date(a.lastUsedAt).getTime() : 0;
        const bTime = b.lastUsedAt ? new Date(b.lastUsedAt).getTime() : 0;
        return bTime - aTime;
      });
  }

  /**
   * Find entries matching a specific URL (for auto-fill).
   *
   * Matches against the hostname, handling subdomains and
   * common URL variations.
   *
   * @param url - The URL to match
   * @returns Matching entries
   */
  findByUrl(url: string): VaultEntry[] {
    this.requireUnlocked();

    let hostname: string;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return [];
    }

    return Array.from(this.entries.values()).filter(entry =>
      entry.urls.some(entryUrl => {
        try {
          const entryHostname = new URL(entryUrl).hostname.toLowerCase();
          // Match exact hostname, subdomain, or shared base domain
          if (hostname === entryHostname) return true;
          if (hostname.endsWith(`.${entryHostname}`)) return true;
          if (entryHostname.endsWith(`.${hostname}`)) return true;
          // Shared base domain (e.g., mail.google.com ↔ accounts.google.com)
          const baseDomain = (h: string) => {
            const parts = h.split('.');
            return parts.length >= 2 ? parts.slice(-2).join('.') : h;
          };
          return baseDomain(hostname) === baseDomain(entryHostname);
        } catch {
          // Fallback to string matching
          return entryUrl.toLowerCase().includes(hostname);
        }
      })
    );
  }

  /**
   * Get vault statistics.
   */
  getStats(): {
    totalEntries: number;
    weakPasswords: number;
    reusedPasswords: number;
    averageStrength: number;
    byType: Record<string, number>;
  } {
    this.requireUnlocked();

    const entries = Array.from(this.entries.values());
    const passwords = entries
      .filter(e => e.password)
      .map(e => e.password);

    // Count reused passwords
    const passwordCounts = new Map<string, number>();
    for (const pwd of passwords) {
      passwordCounts.set(pwd, (passwordCounts.get(pwd) || 0) + 1);
    }
    const reused = Array.from(passwordCounts.values()).filter(c => c > 1).length;

    // Compute stats
    const strengths = entries
      .map(e => e.passwordStrength ?? 0)
      .filter(s => s > 0);
    const avgStrength = strengths.length > 0
      ? strengths.reduce((a, b) => a + b, 0) / strengths.length
      : 0;

    // Count by type
    const byType: Record<string, number> = {};
    for (const entry of entries) {
      byType[entry.type] = (byType[entry.type] || 0) + 1;
    }

    return {
      totalEntries: entries.length,
      weakPasswords: strengths.filter(s => s < 40).length,
      reusedPasswords: reused,
      averageStrength: Math.round(avgStrength),
      byType,
    };
  }

  /** Total number of entries */
  get size(): number {
    return this.entries.size;
  }

  // ==========================================================
  // ENCRYPTION / SERIALIZATION
  // ==========================================================

  /**
   * Encrypt the vault for persistent storage.
   *
   * Each entry is individually encrypted with a unique nonce.
   * The HMAC covers the serialized entries for integrity.
   *
   * @returns The encrypted vault, ready for disk storage
   */
  serialize(): EncryptedVault {
    this.requireUnlocked();
    const key = this.vaultKey!;

    // Encrypt each entry individually
    const encryptedEntries: EncryptedEntry[] = [];
    for (const entry of this.entries.values()) {
      const plaintext = JSON.stringify(entry);
      const { ciphertext, nonce } = encrypt(plaintext, key);

      encryptedEntries.push({
        id: entry.id,
        type: entry.type,
        ciphertext: bytesToHex(ciphertext),
        nonce: bytesToHex(nonce),
        version: 1,
      });
    }

    // Compute integrity HMAC over all encrypted entries
    const entriesJson = JSON.stringify(encryptedEntries);
    const integrityHash = computeHmac(entriesJson, key);

    return {
      version: 1,
      ownerPublicKey: this.ownerPublicKey,
      kdfSalt: this.kdfSalt,
      kdfParams: { ...DEFAULT_KDF_PARAMS },
      entries: encryptedEntries,
      integrityHash,
      lastModified: new Date().toISOString(),
    };
  }

  // ==========================================================
  // PRIVATE METHODS
  // ==========================================================

  /**
   * Load and decrypt entries from an encrypted vault.
   * @private
   */
  private loadEncryptedEntries(encrypted: EncryptedVault): void {
    const key = this.vaultKey!;

    // Verify integrity first
    const entriesJson = JSON.stringify(encrypted.entries);
    if (!verifyHmac(entriesJson, encrypted.integrityHash, key)) {
      throw new Error(
        'Vault integrity check failed. The vault may have been tampered with, ' +
        'or the decryption key is incorrect.'
      );
    }

    // Decrypt each entry
    for (const encEntry of encrypted.entries) {
      try {
        const plaintext = decrypt(
          hexToBytes(encEntry.ciphertext),
          hexToBytes(encEntry.nonce),
          key
        );
        const entry = JSON.parse(plaintext) as VaultEntry;
        this.entries.set(entry.id, entry);
      } catch (err) {
        // If a single entry fails, log but continue
        console.error(`Failed to decrypt entry ${encEntry.id}:`, err);
      }
    }
  }

  /** Ensure vault is unlocked before operations */
  private requireUnlocked(): void {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Unlock before performing operations.');
    }
  }
}

// ============================================================
// PASSWORD GENERATOR
// ============================================================

/**
 * Generate a cryptographically random password.
 *
 * @param options - Generation options (length, character sets, etc.)
 * @returns Generated password string
 */
export function generatePassword(
  options: Partial<PasswordGenOptions> = {}
): string {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };

  let charset = '';
  const LOWER = 'abcdefghijklmnopqrstuvwxyz';
  const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const DIGITS = '0123456789';
  const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const AMBIGUOUS = 'O0Il1';

  if (opts.lowercase) charset += LOWER;
  if (opts.uppercase) charset += UPPER;
  if (opts.digits) charset += DIGITS;
  if (opts.symbols) charset += SYMBOLS;
  if (opts.customChars) charset += opts.customChars;

  if (opts.excludeAmbiguous) {
    charset = charset
      .split('')
      .filter(c => !AMBIGUOUS.includes(c))
      .join('');
  }

  if (charset.length === 0) {
    throw new Error('At least one character set must be enabled');
  }

  // Generate random password using rejection sampling
  // to avoid modulo bias
  const password: string[] = [];
  const randomData = secureRandom(opts.length * 2); // Extra bytes for rejection

  let idx = 0;
  while (password.length < opts.length) {
    if (idx >= randomData.length) {
      // Extremely unlikely, but refill if needed
      const more = secureRandom(opts.length);
      for (let i = 0; i < more.length && password.length < opts.length; i++) {
        password.push(charset[more[i]! % charset.length]!);
      }
      break;
    }
    const byte = randomData[idx++]!;
    // Rejection sampling: only accept if byte < largest multiple of charset.length
    const limit = 256 - (256 % charset.length);
    if (byte < limit) {
      password.push(charset[byte % charset.length]!);
    }
  }

  // Ensure at least one character from each enabled class
  const result = password.join('');
  if (opts.length >= 4) {
    const checks: Array<{ enabled: boolean; charset: string; regex: RegExp }> = [
      { enabled: opts.lowercase, charset: LOWER, regex: /[a-z]/ },
      { enabled: opts.uppercase, charset: UPPER, regex: /[A-Z]/ },
      { enabled: opts.digits, charset: DIGITS, regex: /[0-9]/ },
      { enabled: opts.symbols, charset: SYMBOLS, regex: /[^a-zA-Z0-9]/ },
    ];

    let modified = result.split('');
    let position = 0;
    for (const check of checks) {
      if (check.enabled && !check.regex.test(result)) {
        // Replace a character at a random position
        const randByte = secureRandom(1)[0]!;
        modified[position % modified.length] =
          check.charset[randByte % check.charset.length]!;
        position++;
      }
    }
    return modified.join('');
  }

  return result;
}
