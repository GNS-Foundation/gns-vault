/**
 * GNS Vault Core — Test Suite
 *
 * Tests for identity generation, cryptographic operations,
 * vault lifecycle, import/export, and auth challenge-response.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  // Identity
  generateIdentity,
  derivePublicKey,
  sign,
  verify,
  signAuthChallenge,
  verifyAuthResponse,
  uuid,
  bytesToHex,
  hexToBytes,

  // Crypto
  encrypt,
  decrypt,
  deriveKeyFromPassphrase,
  deriveKeyFromIdentity,
  generateSalt,
  computeHmac,
  verifyHmac,
  passwordStrength,

  // Vault
  Vault,
  generatePassword,

  // Import/Export
  importCredentials,
  exportCredentials,

  // Types
  BadgeTier,
  EntryType,
  ImportFormat,
} from '../src/index.js';

// ============================================================
// IDENTITY & KEYS
// ============================================================

describe('Identity Generation', () => {
  it('should generate a valid Ed25519 keypair', () => {
    const identity = generateIdentity();

    expect(identity.publicKey).toHaveLength(64);   // 32 bytes hex
    expect(identity.privateKey).toHaveLength(64);   // 32 bytes hex
    expect(identity.createdAt).toBeTruthy();
    expect(new Date(identity.createdAt).getTime()).toBeGreaterThan(0);
  });

  it('should generate unique keypairs', () => {
    const id1 = generateIdentity();
    const id2 = generateIdentity();

    expect(id1.publicKey).not.toBe(id2.publicKey);
    expect(id1.privateKey).not.toBe(id2.privateKey);
  });

  it('should derive correct public key from private key', () => {
    const identity = generateIdentity();
    const derived = derivePublicKey(identity.privateKey);
    expect(derived).toBe(identity.publicKey);
  });
});

describe('Ed25519 Signing & Verification', () => {
  it('should sign and verify a message', () => {
    const identity = generateIdentity();
    const message = 'Hello, GNS Protocol!';

    const result = sign(message, identity.privateKey);
    expect(result.signature).toHaveLength(128); // 64 bytes hex
    expect(result.publicKey).toBe(identity.publicKey);

    const valid = verify(result.signature, message, identity.publicKey);
    expect(valid).toBe(true);
  });

  it('should reject tampered messages', () => {
    const identity = generateIdentity();
    const result = sign('original message', identity.privateKey);

    const valid = verify(result.signature, 'tampered message', identity.publicKey);
    expect(valid).toBe(false);
  });

  it('should reject wrong public key', () => {
    const identity1 = generateIdentity();
    const identity2 = generateIdentity();
    const result = sign('test', identity1.privateKey);

    const valid = verify(result.signature, 'test', identity2.publicKey);
    expect(valid).toBe(false);
  });

  it('should handle empty messages', () => {
    const identity = generateIdentity();
    const result = sign('', identity.privateKey);
    expect(verify(result.signature, '', identity.publicKey)).toBe(true);
  });

  it('should handle unicode messages', () => {
    const identity = generateIdentity();
    const message = '🌍 GNS Vault — Identity through Presence! 日本語テスト';
    const result = sign(message, identity.privateKey);
    expect(verify(result.signature, message, identity.publicKey)).toBe(true);
  });
});

describe('GNS Auth Challenge-Response', () => {
  it('should sign and verify an auth challenge', () => {
    const identity = generateIdentity();
    const challenge = {
      nonce: bytesToHex(hexToBytes(uuid().replace(/-/g, ''))),
      origin: 'https://example.com',
      timestamp: new Date().toISOString(),
      expiresIn: 300,
    };

    const response = signAuthChallenge(
      challenge,
      identity.privateKey,
      85.5,
      BadgeTier.Gold,
      '@camilo'
    );

    expect(response.publicKey).toBe(identity.publicKey);
    expect(response.trustScore).toBe(85.5);
    expect(response.badgeTier).toBe(BadgeTier.Gold);
    expect(response.handle).toBe('@camilo');

    const valid = verifyAuthResponse(response, challenge);
    expect(valid).toBe(true);
  });

  it('should reject expired challenges', () => {
    const identity = generateIdentity();
    const challenge = {
      nonce: 'abc123',
      origin: 'https://example.com',
      timestamp: new Date(Date.now() - 600_000).toISOString(), // 10 min ago
      expiresIn: 300, // 5 min expiry
    };

    expect(() =>
      signAuthChallenge(challenge, identity.privateKey, 50, BadgeTier.Silver)
    ).toThrow('expired');
  });
});

// ============================================================
// SYMMETRIC CRYPTOGRAPHY
// ============================================================

describe('XChaCha20-Poly1305 Encryption', () => {
  const key = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

  it('should encrypt and decrypt a string', () => {
    const plaintext = 'my-secret-password-123!';
    const { ciphertext, nonce } = encrypt(plaintext, key);

    expect(ciphertext.length).toBeGreaterThan(0);
    expect(nonce).toHaveLength(24); // 192-bit nonce

    const decrypted = decrypt(ciphertext, nonce, key);
    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertext for same plaintext (unique nonces)', () => {
    const plaintext = 'same-text';
    const result1 = encrypt(plaintext, key);
    const result2 = encrypt(plaintext, key);

    // Nonces should be different (random)
    expect(bytesToHex(result1.nonce)).not.toBe(bytesToHex(result2.nonce));
    // Ciphertext should be different
    expect(bytesToHex(result1.ciphertext)).not.toBe(bytesToHex(result2.ciphertext));
  });

  it('should fail decryption with wrong key', () => {
    const plaintext = 'secret';
    const { ciphertext, nonce } = encrypt(plaintext, key);

    const wrongKey = hexToBytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    expect(() => decrypt(ciphertext, nonce, wrongKey)).toThrow();
  });

  it('should fail decryption with tampered ciphertext', () => {
    const { ciphertext, nonce } = encrypt('secret', key);
    ciphertext[0] ^= 0xff; // Flip bits
    expect(() => decrypt(ciphertext, nonce, key)).toThrow();
  });

  it('should reject invalid key lengths', () => {
    const shortKey = new Uint8Array(16);
    expect(() => encrypt('test', shortKey)).toThrow('32 bytes');
  });

  it('should handle empty strings', () => {
    const { ciphertext, nonce } = encrypt('', key);
    expect(decrypt(ciphertext, nonce, key)).toBe('');
  });

  it('should handle large payloads', () => {
    const large = 'x'.repeat(100_000);
    const { ciphertext, nonce } = encrypt(large, key);
    expect(decrypt(ciphertext, nonce, key)).toBe(large);
  });
});

describe('Key Derivation', () => {
  it('should derive consistent key from passphrase', () => {
    const salt = generateSalt();
    const key1 = deriveKeyFromPassphrase('my-passphrase', salt);
    const key2 = deriveKeyFromPassphrase('my-passphrase', salt);
    expect(bytesToHex(key1)).toBe(bytesToHex(key2));
  });

  it('should derive different keys for different passphrases', () => {
    const salt = generateSalt();
    const key1 = deriveKeyFromPassphrase('passphrase-1', salt);
    const key2 = deriveKeyFromPassphrase('passphrase-2', salt);
    expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
  });

  it('should derive different keys for different salts', () => {
    const key1 = deriveKeyFromPassphrase('same', generateSalt());
    const key2 = deriveKeyFromPassphrase('same', generateSalt());
    expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
  });

  it('should derive vault key from identity', () => {
    const identity = generateIdentity();
    const key = deriveKeyFromIdentity(identity.privateKey);
    expect(key).toHaveLength(32); // 256 bits

    // Deterministic
    const key2 = deriveKeyFromIdentity(identity.privateKey);
    expect(bytesToHex(key)).toBe(bytesToHex(key2));
  });
});

describe('HMAC Integrity', () => {
  const key = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

  it('should compute and verify HMAC', () => {
    const data = '{"entries": []}';
    const mac = computeHmac(data, key);
    expect(verifyHmac(data, mac, key)).toBe(true);
  });

  it('should reject tampered data', () => {
    const mac = computeHmac('original', key);
    expect(verifyHmac('tampered', mac, key)).toBe(false);
  });
});

describe('Password Strength', () => {
  it('should score empty password as 0', () => {
    expect(passwordStrength('')).toBe(0);
  });

  it('should score weak passwords low', () => {
    expect(passwordStrength('123456')).toBeLessThan(30);
    expect(passwordStrength('password')).toBeLessThan(30);
  });

  it('should score strong passwords high', () => {
    expect(passwordStrength('Tr0ub4dour&3#Xk9!')).toBeGreaterThan(60);
  });

  it('should reward length', () => {
    const short = passwordStrength('Ab1!');
    const long = passwordStrength('Ab1!Ab1!Ab1!Ab1!Ab1!');
    expect(long).toBeGreaterThan(short);
  });

  it('should reward character diversity', () => {
    const lettersOnly = passwordStrength('abcdefghij');
    const mixed = passwordStrength('aBc3ef!hij');
    expect(mixed).toBeGreaterThan(lettersOnly);
  });
});

// ============================================================
// VAULT ENGINE
// ============================================================

describe('Vault Lifecycle', () => {
  let identity: { publicKey: string; privateKey: string };

  beforeEach(() => {
    identity = generateIdentity();
  });

  it('should create a vault with identity key', () => {
    const vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);
    expect(vault.isUnlocked).toBe(true);
    expect(vault.size).toBe(0);
  });

  it('should create a vault with passphrase', () => {
    const vault = Vault.createWithPassphrase(identity.publicKey, 'my-passphrase');
    expect(vault.isUnlocked).toBe(true);
  });

  it('should lock and prevent operations', () => {
    const vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);
    vault.addEntry({
      type: EntryType.Login,
      name: 'Test',
      urls: ['https://test.com'],
      username: 'user',
      password: 'pass',
    });
    vault.lock();

    expect(vault.isUnlocked).toBe(false);
    expect(() => vault.getAllEntries()).toThrow('locked');
  });

  it('should serialize and restore vault', () => {
    const vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);

    vault.addEntry({
      type: EntryType.Login,
      name: 'Amazon',
      urls: ['https://amazon.com'],
      username: 'user@email.com',
      password: 'my-secret-pw',
    });

    vault.addEntry({
      type: EntryType.Login,
      name: 'GitHub',
      urls: ['https://github.com'],
      username: 'developer',
      password: 'gh-token-123',
    });

    // Serialize (encrypt)
    const encrypted = vault.serialize();
    expect(encrypted.version).toBe(1);
    expect(encrypted.entries).toHaveLength(2);
    expect(encrypted.ownerPublicKey).toBe(identity.publicKey);

    // Encrypted entries should NOT contain plaintext
    for (const entry of encrypted.entries) {
      expect(entry.ciphertext).not.toContain('my-secret-pw');
      expect(entry.ciphertext).not.toContain('gh-token-123');
    }

    // Restore (decrypt)
    const restored = Vault.unlockWithIdentity(encrypted, identity.privateKey);
    expect(restored.size).toBe(2);

    const entries = restored.getAllEntries();
    const amazon = entries.find(e => e.name === 'Amazon');
    expect(amazon?.password).toBe('my-secret-pw');
    expect(amazon?.username).toBe('user@email.com');
  });

  it('should fail to unlock with wrong key', () => {
    const vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);
    vault.addEntry({
      type: EntryType.Login,
      name: 'Test',
      urls: [],
      username: 'u',
      password: 'p',
    });
    const encrypted = vault.serialize();

    const wrongIdentity = generateIdentity();
    expect(() =>
      Vault.unlockWithIdentity(encrypted, wrongIdentity.privateKey)
    ).toThrow('integrity');
  });
});

describe('Vault CRUD', () => {
  let vault: InstanceType<typeof Vault>;

  beforeEach(() => {
    const identity = generateIdentity();
    vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);
  });

  it('should add and retrieve entries', () => {
    const entry = vault.addEntry({
      type: EntryType.Login,
      name: 'Test Site',
      urls: ['https://test.com'],
      username: 'admin',
      password: 'secret123',
    });

    expect(entry.id).toBeTruthy();
    expect(entry.createdAt).toBeTruthy();
    expect(entry.passwordStrength).toBeGreaterThan(0);

    const retrieved = vault.getEntry(entry.id);
    expect(retrieved).toEqual(entry);
  });

  it('should update entries', async () => {
    const entry = vault.addEntry({
      type: EntryType.Login,
      name: 'Old Name',
      urls: ['https://test.com'],
      username: 'user',
      password: 'old-password',
    });

    // Small delay to ensure different timestamp
    await new Promise(r => setTimeout(r, 10));

    const updated = vault.updateEntry(entry.id, {
      name: 'New Name',
      password: 'new-stronger-password!',
    });

    expect(updated.name).toBe('New Name');
    expect(updated.password).toBe('new-stronger-password!');
    expect(updated.createdAt).toBe(entry.createdAt); // Preserved
    expect(updated.id).toBe(entry.id); // ID preserved
  });

  it('should delete entries', () => {
    const entry = vault.addEntry({
      type: EntryType.Login,
      name: 'Delete Me',
      urls: [],
      username: 'u',
      password: 'p',
    });

    expect(vault.deleteEntry(entry.id)).toBe(true);
    expect(vault.getEntry(entry.id)).toBeUndefined();
    expect(vault.size).toBe(0);
  });

  it('should search entries', () => {
    vault.addEntry({ type: EntryType.Login, name: 'Amazon', urls: ['https://amazon.com'], username: 'a@b.com', password: 'p1' });
    vault.addEntry({ type: EntryType.Login, name: 'Gmail', urls: ['https://mail.google.com'], username: 'a@gmail.com', password: 'p2' });
    vault.addEntry({ type: EntryType.Login, name: 'GitHub', urls: ['https://github.com'], username: 'dev', password: 'p3' });

    expect(vault.searchEntries('amazon')).toHaveLength(1);
    expect(vault.searchEntries('gmail')).toHaveLength(1);
    expect(vault.searchEntries('a@')).toHaveLength(2); // Matches username
  });

  it('should find by URL with subdomain matching', () => {
    vault.addEntry({
      type: EntryType.Login,
      name: 'Google',
      urls: ['https://accounts.google.com'],
      username: 'user',
      password: 'pass',
    });

    expect(vault.findByUrl('https://accounts.google.com/login')).toHaveLength(1);
    expect(vault.findByUrl('https://mail.google.com')).toHaveLength(1); // Subdomain match
    expect(vault.findByUrl('https://facebook.com')).toHaveLength(0);
  });

  it('should compute vault statistics', () => {
    vault.addEntry({ type: EntryType.Login, name: 'A', urls: [], username: 'u1', password: 'weak' });
    vault.addEntry({ type: EntryType.Login, name: 'B', urls: [], username: 'u2', password: 'Str0ng!P@ssw0rd' });
    vault.addEntry({ type: EntryType.Login, name: 'C', urls: [], username: 'u3', password: 'weak' }); // Reused!
    vault.addEntry({ type: EntryType.SecureNote, name: 'Note', urls: [], username: '', password: '' });

    const stats = vault.getStats();
    expect(stats.totalEntries).toBe(4);
    expect(stats.reusedPasswords).toBeGreaterThanOrEqual(1);
    expect(stats.byType[EntryType.Login]).toBe(3);
    expect(stats.byType[EntryType.SecureNote]).toBe(1);
  });
});

// ============================================================
// PASSWORD GENERATOR
// ============================================================

describe('Password Generator', () => {
  it('should generate passwords of specified length', () => {
    expect(generatePassword({ length: 16 })).toHaveLength(16);
    expect(generatePassword({ length: 32 })).toHaveLength(32);
    expect(generatePassword({ length: 64 })).toHaveLength(64);
  });

  it('should respect character set options', () => {
    const lower = generatePassword({ length: 50, lowercase: true, uppercase: false, digits: false, symbols: false });
    expect(lower).toMatch(/^[a-z]+$/);

    const upper = generatePassword({ length: 50, lowercase: false, uppercase: true, digits: false, symbols: false });
    expect(upper).toMatch(/^[A-Z]+$/);

    const digits = generatePassword({ length: 50, lowercase: false, uppercase: false, digits: true, symbols: false });
    expect(digits).toMatch(/^[0-9]+$/);
  });

  it('should generate unique passwords', () => {
    const passwords = new Set<string>();
    for (let i = 0; i < 100; i++) {
      passwords.add(generatePassword({ length: 24 }));
    }
    expect(passwords.size).toBe(100); // All unique
  });

  it('should reject empty charset', () => {
    expect(() =>
      generatePassword({ length: 16, lowercase: false, uppercase: false, digits: false, symbols: false })
    ).toThrow();
  });
});

// ============================================================
// IMPORT / EXPORT
// ============================================================

describe('Import — Chrome CSV', () => {
  it('should import Chrome CSV format', () => {
    const csv = `name,url,username,password,note
Amazon,https://amazon.com,user@email.com,MyP@ss123,Shopping account
GitHub,https://github.com,developer,gh-secret,Dev account`;

    const result = importCredentials(csv, ImportFormat.ChromeCsv);
    expect(result.totalImported).toBe(2);
    expect(result.errors).toHaveLength(0);

    const amazon = result.entries.find(e => e.name === 'Amazon');
    expect(amazon?.urls).toContain('https://amazon.com');
    expect(amazon?.username).toBe('user@email.com');
    expect(amazon?.password).toBe('MyP@ss123');
  });
});

describe('Import — Bitwarden JSON', () => {
  it('should import Bitwarden JSON format', () => {
    const json = JSON.stringify({
      items: [
        {
          type: 1,
          name: 'Example',
          login: {
            username: 'user',
            password: 'pass123',
            uris: [{ uri: 'https://example.com' }],
            totp: 'JBSWY3DPEHPK3PXP',
          },
          notes: 'Some notes',
          favorite: true,
        },
      ],
    });

    const result = importCredentials(json, ImportFormat.Bitwarden);
    expect(result.totalImported).toBe(1);
    expect(result.entries[0]?.name).toBe('Example');
    expect(result.entries[0]?.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(result.entries[0]?.favorite).toBe(true);
  });
});

describe('Export', () => {
  it('should export to JSON', () => {
    const entries: VaultEntry[] = [{
      id: 'test-id',
      type: EntryType.Login,
      name: 'Test',
      urls: ['https://test.com'],
      username: 'user',
      password: 'secret',
      favorite: false,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    }];

    const json = exportCredentials(entries, { format: 'json', includePasswords: true });
    const parsed = JSON.parse(json);
    expect(parsed.format).toBe('gns-vault-export');
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0].password).toBe('secret');
  });

  it('should mask passwords when not included', () => {
    const entries: VaultEntry[] = [{
      id: 'test-id',
      type: EntryType.Login,
      name: 'Test',
      urls: [],
      username: 'user',
      password: 'secret',
      favorite: false,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    }];

    const json = exportCredentials(entries, { format: 'json', includePasswords: false });
    const parsed = JSON.parse(json);
    expect(parsed.entries[0].password).toBe('********');
  });

  it('should export to CSV', () => {
    const entries: VaultEntry[] = [{
      id: 'test-id',
      type: EntryType.Login,
      name: 'My Site',
      urls: ['https://test.com'],
      username: 'user',
      password: 'pass',
      favorite: false,
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    }];

    const csv = exportCredentials(entries, { format: 'csv', includePasswords: true });
    expect(csv).toContain('name,url,username,password');
    expect(csv).toContain('My Site');
  });
});

// ============================================================
// UTILITIES
// ============================================================

describe('Utilities', () => {
  it('should convert between hex and bytes', () => {
    const original = new Uint8Array([0, 1, 255, 128, 64]);
    const hex = bytesToHex(original);
    expect(hex).toBe('0001ff8040');
    const back = hexToBytes(hex);
    expect(back).toEqual(original);
  });

  it('should generate valid UUIDs', () => {
    const id = uuid();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    // All unique
    const ids = new Set(Array.from({ length: 100 }, () => uuid()));
    expect(ids.size).toBe(100);
  });
});
