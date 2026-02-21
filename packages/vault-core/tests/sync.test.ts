/**
 * GNS Vault — Sync Module Tests
 *
 * Tests for P2P sync envelope sealing, unsealing, and topic derivation.
 */

import { describe, it, expect } from 'vitest';
import {
  generateIdentity,
  deriveSyncTopic,
  sealEnvelope,
  unsealEnvelope,
  createFullSyncPayload,
  createEntryAddPayload,
  createEntryDeletePayload,
  SyncMessageType,
} from '../src/index.js';

describe('Sync Topic Derivation', () => {
  it('should derive a deterministic topic from a public key', () => {
    const identity = generateIdentity();
    const topic1 = deriveSyncTopic(identity.publicKey);
    const topic2 = deriveSyncTopic(identity.publicKey);

    expect(topic1).toHaveLength(64); // 32 bytes hex
    expect(topic1).toBe(topic2); // Deterministic
  });

  it('should derive different topics for different identities', () => {
    const id1 = generateIdentity();
    const id2 = generateIdentity();

    expect(deriveSyncTopic(id1.publicKey)).not.toBe(deriveSyncTopic(id2.publicKey));
  });

  it('should not leak the public key in the topic', () => {
    const identity = generateIdentity();
    const topic = deriveSyncTopic(identity.publicKey);

    // Topic should not contain any substring of the public key
    expect(topic).not.toContain(identity.publicKey.substring(0, 16));
  });
});

describe('Envelope Sealing & Unsealing', () => {
  it('should seal and unseal a full sync payload', () => {
    const identity = generateIdentity();

    const payload = createFullSyncPayload({
      version: 1,
      ownerPublicKey: identity.publicKey,
      kdfSalt: 'abcdef1234567890',
      kdfParams: { algorithm: 'argon2id', timeCost: 3, memoryCost: 65536, parallelism: 4, keyLength: 32 },
      entries: [],
      integrityHash: 'deadbeef',
      lastModified: new Date().toISOString(),
    });

    const envelope = sealEnvelope(payload, identity.privateKey, identity.publicKey);

    // Envelope structure
    expect(envelope.version).toBe(1);
    expect(envelope.type).toBe(SyncMessageType.FullSync);
    expect(envelope.senderPublicKey).toBe(identity.publicKey);
    expect(envelope.ephemeralPublicKey).toHaveLength(64);
    expect(envelope.ciphertext.length).toBeGreaterThan(0);
    expect(envelope.nonce).toHaveLength(48); // 24 bytes hex
    expect(envelope.signature).toHaveLength(128); // 64 bytes hex
    expect(envelope.timestamp).toBeGreaterThan(0);

    // Unseal on the "other device" (same identity key)
    const decrypted = unsealEnvelope(envelope, identity.privateKey);

    expect(decrypted.type).toBe(SyncMessageType.FullSync);
    expect(decrypted.timestamp).toBe(payload.timestamp);
    expect((decrypted.data as { ownerPublicKey: string }).ownerPublicKey).toBe(identity.publicKey);
  });

  it('should seal and unseal incremental payloads', () => {
    const identity = generateIdentity();

    const addPayload = createEntryAddPayload('entry-123', { encrypted: 'data' });
    const envelope = sealEnvelope(addPayload, identity.privateKey, identity.publicKey);

    const decrypted = unsealEnvelope(envelope, identity.privateKey);
    expect(decrypted.type).toBe(SyncMessageType.EntryAdd);
    expect((decrypted.data as { entryId: string }).entryId).toBe('entry-123');
  });

  it('should seal and unseal delete payloads', () => {
    const identity = generateIdentity();

    const delPayload = createEntryDeletePayload('entry-456');
    const envelope = sealEnvelope(delPayload, identity.privateKey, identity.publicKey);

    const decrypted = unsealEnvelope(envelope, identity.privateKey);
    expect(decrypted.type).toBe(SyncMessageType.EntryDelete);
    expect((decrypted.data as { entryId: string }).entryId).toBe('entry-456');
  });

  it('should reject tampered envelopes (signature failure)', () => {
    const identity = generateIdentity();
    const payload = createEntryAddPayload('test', {});
    const envelope = sealEnvelope(payload, identity.privateKey, identity.publicKey);

    // Tamper with ciphertext
    const tampered = { ...envelope };
    tampered.ciphertext = 'ff' + tampered.ciphertext.slice(2);

    expect(() => unsealEnvelope(tampered, identity.privateKey)).toThrow('signature');
  });

  it('should reject envelopes from different identities', () => {
    const sender = generateIdentity();
    const attacker = generateIdentity();

    const payload = createEntryAddPayload('test', { secret: 'data' });
    const envelope = sealEnvelope(payload, sender.privateKey, sender.publicKey);

    // Attacker tries to unseal with their own key
    expect(() => unsealEnvelope(envelope, attacker.privateKey)).toThrow();
  });

  it('should produce unique envelopes for same payload (ephemeral keys)', () => {
    const identity = generateIdentity();
    const payload = createEntryAddPayload('test', {});

    const env1 = sealEnvelope(payload, identity.privateKey, identity.publicKey);
    const env2 = sealEnvelope(payload, identity.privateKey, identity.publicKey);

    // Ephemeral keys should differ
    expect(env1.ephemeralPublicKey).not.toBe(env2.ephemeralPublicKey);
    // Ciphertext should differ (different nonces)
    expect(env1.ciphertext).not.toBe(env2.ciphertext);
    // Both should unseal correctly
    expect(unsealEnvelope(env1, identity.privateKey).type).toBe(SyncMessageType.EntryAdd);
    expect(unsealEnvelope(env2, identity.privateKey).type).toBe(SyncMessageType.EntryAdd);
  });

  it('should handle large payloads', () => {
    const identity = generateIdentity();

    // Simulate a vault with many entries
    const bigData = {
      entries: Array.from({ length: 500 }, (_, i) => ({
        id: `entry-${i}`,
        ciphertext: 'a'.repeat(200),
        nonce: 'b'.repeat(48),
      })),
    };

    const payload = createFullSyncPayload(bigData as unknown as import('../src/types.js').EncryptedVault);
    const envelope = sealEnvelope(payload, identity.privateKey, identity.publicKey);
    const decrypted = unsealEnvelope(envelope, identity.privateKey);

    expect((decrypted.data as { entries: unknown[] }).entries).toHaveLength(500);
  });
});
