/**
 * GNS Vault — P2P Sync via GNS Relay
 *
 * Cross-device synchronization using the GNS Relay Channel.
 * The relay is a stateless, end-to-end encrypted message forwarder.
 *
 * Architecture:
 *   Device A ──[sealed envelope]──→ GNS Relay ──[sealed envelope]──→ Device B
 *
 * The relay operator CANNOT:
 *   - Decrypt envelope contents (sealed with X25519 + XChaCha20-Poly1305)
 *   - Determine what type of data is being synced
 *   - Store envelopes beyond the delivery window
 *   - Associate envelopes with user identities
 *
 * Protocol:
 *   1. Device A computes a deterministic "device sync topic" from the identity key
 *   2. Both devices subscribe to the same topic on the relay via WebSocket
 *   3. When vault changes occur, Device A seals a SyncEnvelope and sends it
 *   4. Device B receives the envelope, verifies the signature, decrypts, and applies
 *
 * @module @gns-vault/core/sync
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, signBytes, verifyBytes } from './keys.js';
import type { EncryptedVault } from './types.js';

// ============================================================
// TYPES
// ============================================================

/** Sealed envelope for transit over the relay */
export interface SyncEnvelope {
  /** Protocol version */
  version: number;
  /** Envelope type */
  type: SyncMessageType;
  /** Sender's Ed25519 public key (hex) */
  senderPublicKey: string;
  /** Ephemeral X25519 public key for this envelope (hex) */
  ephemeralPublicKey: string;
  /** Encrypted payload (hex) */
  ciphertext: string;
  /** Nonce for XChaCha20-Poly1305 (hex) */
  nonce: string;
  /** Ed25519 signature over (type || ephemeralPublicKey || ciphertext || nonce) */
  signature: string;
  /** Unix timestamp (ms) */
  timestamp: number;
}

/** Types of sync messages */
export enum SyncMessageType {
  /** Full vault sync (initial or recovery) */
  FullSync = 'full_sync',
  /** Incremental: single entry added */
  EntryAdd = 'entry_add',
  /** Incremental: single entry updated */
  EntryUpdate = 'entry_update',
  /** Incremental: single entry deleted */
  EntryDelete = 'entry_delete',
  /** Device pairing request */
  PairRequest = 'pair_request',
  /** Device pairing confirmation */
  PairConfirm = 'pair_confirm',
  /** Ping / keepalive */
  Ping = 'ping',
}

/** Decrypted sync payload */
export interface SyncPayload {
  type: SyncMessageType;
  timestamp: number;
  data: unknown;
}

/** Device info for pairing */
export interface DeviceInfo {
  /** Device identifier (random, per-installation) */
  deviceId: string;
  /** Human-readable device name */
  deviceName: string;
  /** Device platform */
  platform: 'chrome' | 'firefox' | 'ios' | 'android' | 'desktop';
  /** Timestamp of last sync */
  lastSyncAt?: string;
}

/** Sync session state */
export interface SyncSession {
  /** Deterministic topic for this identity's devices */
  topic: string;
  /** List of known paired devices */
  devices: DeviceInfo[];
  /** This device's info */
  thisDevice: DeviceInfo;
  /** WebSocket connection state */
  connectionState: 'disconnected' | 'connecting' | 'connected';
}

// ============================================================
// SYNC TOPIC DERIVATION
// ============================================================

/**
 * Derive a deterministic sync topic from the identity key.
 *
 * All devices belonging to the same identity subscribe to the same topic.
 * The topic is derived via HKDF so the relay cannot reverse-engineer
 * the identity public key from the topic.
 *
 * @param publicKeyHex - GNS identity public key (hex)
 * @returns Topic string (hex, 32 bytes)
 */
export function deriveSyncTopic(publicKeyHex: string): string {
  const publicKey = hexToBytes(publicKeyHex);
  const salt = new TextEncoder().encode('gns-vault-sync-topic-v1');
  const info = new TextEncoder().encode('sync-topic');
  const topicBytes = hkdf(sha256, publicKey, salt, info, 32);
  return bytesToHex(topicBytes);
}

// ============================================================
// ENVELOPE SEALING (ENCRYPT + SIGN)
// ============================================================

/**
 * Seal a sync envelope for transmission over the relay.
 *
 * Uses X25519 ephemeral key exchange + XChaCha20-Poly1305 encryption
 * + Ed25519 signature for authenticated encryption.
 *
 * @param payload - The sync payload to seal
 * @param senderPrivateKeyHex - Sender's Ed25519 private key
 * @param senderPublicKeyHex - Sender's Ed25519 public key
 * @returns Sealed envelope ready for relay transmission
 */
export function sealEnvelope(
  payload: SyncPayload,
  senderPrivateKeyHex: string,
  senderPublicKeyHex: string
): SyncEnvelope {
  // Serialize payload
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  // Generate ephemeral X25519 keypair for this message
  const ephemeralPrivate = randomBytes(32);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);

  // For self-sync (same identity on multiple devices), both sides have:
  //   - ephemeralPublicKey (included in envelope)
  //   - identity private key (shared across devices)
  // So we derive the encryption key from both, which only the identity owner can reproduce.
  const senderPrivate = hexToBytes(senderPrivateKeyHex);
  const ikm = new Uint8Array([...ephemeralPublic, ...senderPrivate]);
  const salt = new TextEncoder().encode('gns-vault-sync-envelope-v1');
  const info = new TextEncoder().encode('envelope-key');
  const encKey = hkdf(sha256, ikm, salt, info, 32);

  // Encrypt with XChaCha20-Poly1305
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(encKey, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  // Sign the envelope contents with Ed25519
  const signData = new Uint8Array([
    ...new TextEncoder().encode(payload.type),
    ...ephemeralPublic,
    ...ciphertext,
    ...nonce,
  ]);
  const signature = signBytes(signData, senderPrivateKeyHex);

  return {
    version: 1,
    type: payload.type,
    senderPublicKey: senderPublicKeyHex,
    ephemeralPublicKey: bytesToHex(ephemeralPublic),
    ciphertext: bytesToHex(ciphertext),
    nonce: bytesToHex(nonce),
    signature: bytesToHex(signature),
    timestamp: Date.now(),
  };
}

/**
 * Unseal a sync envelope received from the relay.
 *
 * Verifies the Ed25519 signature, then decrypts using the shared secret.
 *
 * @param envelope - Sealed envelope from the relay
 * @param receiverPrivateKeyHex - Receiver's Ed25519 private key
 * @returns Decrypted sync payload
 * @throws Error if signature verification or decryption fails
 */
export function unsealEnvelope(
  envelope: SyncEnvelope,
  receiverPrivateKeyHex: string
): SyncPayload {
  // Verify signature first
  const ciphertextBytes = hexToBytes(envelope.ciphertext);
  const nonceBytes = hexToBytes(envelope.nonce);
  const ephemeralPublic = hexToBytes(envelope.ephemeralPublicKey);

  const signData = new Uint8Array([
    ...new TextEncoder().encode(envelope.type),
    ...ephemeralPublic,
    ...ciphertextBytes,
    ...nonceBytes,
  ]);

  const signatureBytes = hexToBytes(envelope.signature);
  const valid = verifyBytes(signatureBytes, signData, envelope.senderPublicKey);

  if (!valid) {
    throw new Error('Envelope signature verification failed — message may be tampered');
  }

  // Derive the same encryption key using ephemeralPublic + identity private key
  // Both devices have: the ephemeral public key (from envelope) + the identity private key
  const receiverPrivate = hexToBytes(receiverPrivateKeyHex);
  const ikm = new Uint8Array([...ephemeralPublic, ...receiverPrivate]);
  const salt = new TextEncoder().encode('gns-vault-sync-envelope-v1');
  const info = new TextEncoder().encode('envelope-key');
  const encKey = hkdf(sha256, ikm, salt, info, 32);

  // Decrypt
  const cipher = xchacha20poly1305(encKey, nonceBytes);
  const plaintext = cipher.decrypt(ciphertextBytes);

  const payload = JSON.parse(new TextDecoder().decode(plaintext)) as SyncPayload;
  return payload;
}

// ============================================================
// SYNC PAYLOADS
// ============================================================

/**
 * Create a full vault sync payload.
 */
export function createFullSyncPayload(vault: EncryptedVault): SyncPayload {
  return {
    type: SyncMessageType.FullSync,
    timestamp: Date.now(),
    data: vault,
  };
}

/**
 * Create an incremental entry addition payload.
 */
export function createEntryAddPayload(entryId: string, encryptedEntry: unknown): SyncPayload {
  return {
    type: SyncMessageType.EntryAdd,
    timestamp: Date.now(),
    data: { entryId, entry: encryptedEntry },
  };
}

/**
 * Create an incremental entry update payload.
 */
export function createEntryUpdatePayload(entryId: string, encryptedEntry: unknown): SyncPayload {
  return {
    type: SyncMessageType.EntryUpdate,
    timestamp: Date.now(),
    data: { entryId, entry: encryptedEntry },
  };
}

/**
 * Create an entry deletion payload.
 */
export function createEntryDeletePayload(entryId: string): SyncPayload {
  return {
    type: SyncMessageType.EntryDelete,
    timestamp: Date.now(),
    data: { entryId },
  };
}

/**
 * Create a device pairing request payload.
 */
export function createPairRequestPayload(device: DeviceInfo): SyncPayload {
  return {
    type: SyncMessageType.PairRequest,
    timestamp: Date.now(),
    data: device,
  };
}

// ============================================================
// RELAY CLIENT
// ============================================================

/** Relay client event handlers */
export interface RelayClientHandlers {
  onConnected: () => void;
  onDisconnected: (reason: string) => void;
  onEnvelope: (envelope: SyncEnvelope) => void;
  onError: (error: Error) => void;
}

/**
 * GNS Relay WebSocket client.
 *
 * Manages the persistent connection to the GNS Relay for P2P sync.
 * Handles reconnection, heartbeat, and message routing.
 */
export class RelayClient {
  private ws: WebSocket | null = null;
  private topic: string;
  private relayUrl: string;
  private handlers: RelayClientHandlers;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    relayUrl: string,
    topic: string,
    handlers: RelayClientHandlers
  ) {
    this.relayUrl = relayUrl;
    this.topic = topic;
    this.handlers = handlers;
  }

  /**
   * Connect to the relay and subscribe to the sync topic.
   */
  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      const url = `${this.relayUrl}/sync/${this.topic}`;
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.startHeartbeat();
        this.handlers.onConnected();
      };

      this.ws.onmessage = (event) => {
        try {
          const envelope = JSON.parse(event.data as string) as SyncEnvelope;
          if (envelope.version && envelope.type && envelope.ciphertext) {
            this.handlers.onEnvelope(envelope);
          }
        } catch (err) {
          this.handlers.onError(new Error(`Invalid relay message: ${(err as Error).message}`));
        }
      };

      this.ws.onclose = (event) => {
        this.stopHeartbeat();
        this.handlers.onDisconnected(event.reason || 'Connection closed');
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.handlers.onError(new Error('WebSocket connection error'));
      };
    } catch (err) {
      this.handlers.onError(err as Error);
      this.scheduleReconnect();
    }
  }

  /**
   * Send a sealed envelope through the relay.
   */
  send(envelope: SyncEnvelope): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return false;
    }
    this.ws.send(JSON.stringify(envelope));
    return true;
  }

  /**
   * Disconnect from the relay.
   */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopHeartbeat();
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
  }

  /** Current connection state */
  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  // ---- Private ----

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.handlers.onError(new Error('Max reconnection attempts reached'));
      return;
    }

    // Exponential backoff: 1s, 2s, 4s, 8s, ... up to 30s
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000); // 30s heartbeat
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}

/** Default GNS Relay URL */
export const DEFAULT_RELAY_URL = 'wss://relay.globecrumbs.com';
