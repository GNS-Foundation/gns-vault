/**
 * GNS Vault Core — Type Definitions
 *
 * All types for the credential vault, identity management,
 * and cryptographic operations.
 *
 * @module @gns-vault/core/types
 */

// ============================================================
// IDENTITY TYPES
// ============================================================

/** Ed25519 keypair for GNS identity */
export interface GnsIdentity {
  /** Ed25519 public key (32 bytes, hex-encoded) */
  publicKey: string;
  /** Ed25519 private key (32 bytes, hex-encoded) — stored in secure enclave */
  privateKey: string;
  /** ISO 8601 timestamp of key generation */
  createdAt: string;
  /** Optional human-readable @handle */
  handle?: string;
  /** Stellar wallet address derived from the same key */
  stellarAddress?: string;
}

/** Trust score from TrIP (Trajectory Recognition Identity Protocol) */
export interface TrustScore {
  /** Overall score (0-100) */
  score: number;
  /** Total breadcrumbs collected */
  breadcrumbs: number;
  /** Days since identity creation */
  identityAgeDays: number;
  /** Badge tier */
  tier: BadgeTier;
  /** Last updated timestamp */
  updatedAt: string;
}

/** Human Identity Badge tiers */
export enum BadgeTier {
  Unverified = 'unverified',
  Bronze = 'bronze',
  Silver = 'silver',
  Gold = 'gold',
  Platinum = 'platinum',
  Diamond = 'diamond',
}

// ============================================================
// VAULT TYPES
// ============================================================

/** A single credential entry in the vault */
export interface VaultEntry {
  /** Unique identifier (UUID v4) */
  id: string;
  /** Entry type */
  type: EntryType;
  /** Display name (e.g., "Gmail", "Amazon") */
  name: string;
  /** URL(s) associated with this credential */
  urls: string[];
  /** Username or email */
  username: string;
  /** Password (plaintext in memory, encrypted at rest) */
  password: string;
  /** TOTP secret key (RFC 6238) */
  totpSecret?: string;
  /** Freeform notes */
  notes?: string;
  /** Custom fields */
  customFields?: CustomField[];
  /** Folder/category */
  folder?: string;
  /** Whether this entry is marked as favorite */
  favorite: boolean;
  /** ISO 8601 creation timestamp */
  createdAt: string;
  /** ISO 8601 last modified timestamp */
  updatedAt: string;
  /** ISO 8601 last used timestamp */
  lastUsedAt?: string;
  /** Password strength score (0-100) */
  passwordStrength?: number;
}

/** Types of vault entries */
export enum EntryType {
  Login = 'login',
  SecureNote = 'secure_note',
  CreditCard = 'credit_card',
  Identity = 'identity',
  ApiKey = 'api_key',
}

/** Custom field on a vault entry */
export interface CustomField {
  name: string;
  value: string;
  type: 'text' | 'hidden' | 'url';
}

// ============================================================
// ENCRYPTED VAULT TYPES
// ============================================================

/** An encrypted vault entry (stored on disk) */
export interface EncryptedEntry {
  /** Entry ID (not encrypted — needed for indexing) */
  id: string;
  /** Entry type (not encrypted — needed for UI) */
  type: EntryType;
  /** Encrypted payload (XChaCha20-Poly1305) */
  ciphertext: string;
  /** Nonce used for this entry (192-bit, hex) */
  nonce: string;
  /** Version of the encryption scheme */
  version: number;
}

/** The complete encrypted vault */
export interface EncryptedVault {
  /** Vault format version */
  version: number;
  /** Public key of the vault owner (hex) */
  ownerPublicKey: string;
  /** Argon2id salt for passphrase derivation (hex) */
  kdfSalt: string;
  /** KDF parameters used */
  kdfParams: KdfParams;
  /** Encrypted entries */
  entries: EncryptedEntry[];
  /** HMAC-SHA256 of the entire entries array for integrity */
  integrityHash: string;
  /** ISO 8601 timestamp */
  lastModified: string;
}

/** Argon2id key derivation parameters */
export interface KdfParams {
  algorithm: 'argon2id';
  /** Time cost (iterations) */
  timeCost: number;
  /** Memory cost (KiB) */
  memoryCost: number;
  /** Parallelism */
  parallelism: number;
  /** Output key length in bytes */
  keyLength: number;
}

/** Default KDF parameters (RFC 9106 recommended) */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  algorithm: 'argon2id',
  timeCost: 3,
  memoryCost: 65536, // 64 MiB
  parallelism: 4,
  keyLength: 32,
};

// ============================================================
// CRYPTO OPERATION TYPES
// ============================================================

/** Result of an encryption operation */
export interface EncryptResult {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/** Ed25519 signature result */
export interface SignatureResult {
  signature: string;
  publicKey: string;
  message: string;
}

// ============================================================
// IMPORT/EXPORT TYPES
// ============================================================

/** Supported import formats */
export enum ImportFormat {
  OnePassword = '1password',
  Bitwarden = 'bitwarden',
  LastPass = 'lastpass',
  ChromeCsv = 'chrome_csv',
  GenericCsv = 'generic_csv',
}

/** Import result with statistics */
export interface ImportResult {
  entries: VaultEntry[];
  totalParsed: number;
  totalImported: number;
  skipped: number;
  errors: string[];
}

/** Export options */
export interface ExportOptions {
  format: 'json' | 'csv';
  /** Include passwords in export (security warning shown to user) */
  includePasswords: boolean;
  /** Filter by folder */
  folder?: string;
}

// ============================================================
// AUTH CHALLENGE TYPES
// ============================================================

/** GNS Auth challenge from a website */
export interface AuthChallenge {
  /** Challenge nonce (hex) */
  nonce: string;
  /** Origin domain requesting auth */
  origin: string;
  /** Timestamp of challenge creation */
  timestamp: string;
  /** Challenge expiry (seconds) */
  expiresIn: number;
}

/** GNS Auth response signed by the user */
export interface AuthResponse {
  /** The original challenge nonce */
  nonce: string;
  /** User's GNS public key (hex) */
  publicKey: string;
  /** Ed25519 signature of (nonce || origin || timestamp) */
  signature: string;
  /** User's current trust score */
  trustScore: number;
  /** User's badge tier */
  badgeTier: BadgeTier;
  /** User's @handle (if claimed) */
  handle?: string;
}

// ============================================================
// PASSWORD GENERATION TYPES
// ============================================================

/** Password generation options */
export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  /** Exclude ambiguous characters (0, O, l, 1, etc.) */
  excludeAmbiguous: boolean;
  /** Custom character set to include */
  customChars?: string;
}

/** Default password generation options */
export const DEFAULT_PASSWORD_OPTIONS: PasswordGenOptions = {
  length: 24,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};
