/**
 * GNS Vault Extension — Background Service Worker
 *
 * This is the vault operations hub. It:
 *   1. Manages the vault lifecycle (create, unlock, lock, auto-lock)
 *   2. Routes messages between popup and content scripts
 *   3. Handles credential CRUD operations
 *   4. Manages GNS identity state
 *   5. Processes auth challenges from GNS-enabled websites
 *
 * The vault key is held in memory ONLY while the service worker is alive.
 * Chrome may terminate the service worker after ~30s of inactivity,
 * which naturally locks the vault (key is cleared from memory).
 *
 * @module vault-extension/background
 */

import {
  generateIdentity,
  Vault,
  generatePassword,
  importCredentials,
  exportCredentials,
  signAuthChallenge,
  passwordStrength,
  type GnsIdentity,
  type EncryptedVault,
  type ImportFormat,
  BadgeTier,
  EntryType,
} from '@gns-vault/core';

import type {
  PopupMessage,
  ContentMessage,
  MessageResponse,
  VaultStatusData,
  AutofillData,
} from '../utils/messages';

// ============================================================
// STATE
// ============================================================

/** In-memory vault instance (null when locked) */
let vault: InstanceType<typeof Vault> | null = null;

/** Identity persisted to chrome.storage.local */
let identity: GnsIdentity | null = null;

/** Auto-lock timer (minutes) */
const AUTO_LOCK_MINUTES = 15;

// ============================================================
// INITIALIZATION
// ============================================================

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    console.log('[GNS Vault] Extension installed — welcome!');
    // Set default settings
    await chrome.storage.local.set({
      settings: {
        autoLockMinutes: AUTO_LOCK_MINUTES,
        showNotifications: true,
        autoSaveCredentials: true,
        theme: 'system',
      },
    });
  }
});

// Load identity on startup
loadIdentity();

// ============================================================
// MESSAGE ROUTING
// ============================================================

chrome.runtime.onMessage.addListener(
  (message: PopupMessage | ContentMessage, _sender, sendResponse) => {
    // Handle async responses
    handleMessage(message)
      .then(sendResponse)
      .catch((err) =>
        sendResponse({ success: false, error: (err as Error).message })
      );
    return true; // Keep message channel open for async response
  }
);

async function handleMessage(
  message: PopupMessage | ContentMessage
): Promise<MessageResponse> {
  switch (message.type) {
    // === Vault Lifecycle ===
    case 'VAULT_GET_STATUS':
      return getVaultStatus();
    case 'VAULT_CREATE':
      return createVault(message.passphrase);
    case 'VAULT_UNLOCK':
      return unlockVault(message.passphrase);
    case 'VAULT_LOCK':
      return lockVault();

    // === CRUD ===
    case 'VAULT_GET_ENTRIES':
      return getEntries();
    case 'VAULT_GET_ENTRY':
      return getEntry(message.id);
    case 'VAULT_ADD_ENTRY':
      return addEntry(message.entry);
    case 'VAULT_UPDATE_ENTRY':
      return updateEntry(message.id, message.updates);
    case 'VAULT_DELETE_ENTRY':
      return deleteEntry(message.id);
    case 'VAULT_SEARCH':
      return searchEntries(message.query);
    case 'VAULT_GET_STATS':
      return getStats();

    // === Password Generation ===
    case 'VAULT_GENERATE_PASSWORD':
      return generatePwd(message.options);

    // === Import/Export ===
    case 'VAULT_IMPORT':
      return importEntries(message.data, message.format as ImportFormat);
    case 'VAULT_EXPORT':
      return exportEntries(message.options);

    // === Identity ===
    case 'IDENTITY_GET':
      return getIdentity();
    case 'IDENTITY_GET_TRUST_SCORE':
      return getTrustScore();

    // === Content Script: Auto-fill ===
    case 'AUTOFILL_REQUEST':
      return getAutofillData(message.url);
    case 'AUTOFILL_SAVE':
      return saveAutofillCredential(message);

    // === GNS Auth ===
    case 'GNS_AUTH_CHECK':
      return checkGnsAuth(message.origin);
    case 'GNS_AUTH_RESPOND':
      return signGnsAuth(message.challenge);

    default:
      return { success: false, error: `Unknown message type: ${(message as { type: string }).type}` };
  }
}

// ============================================================
// VAULT LIFECYCLE
// ============================================================

async function getVaultStatus(): Promise<MessageResponse<VaultStatusData>> {
  const stored = await chrome.storage.local.get(['encryptedVault', 'identity']);
  const exists = !!stored.encryptedVault;

  return {
    success: true,
    data: {
      exists,
      isUnlocked: vault !== null,
      entryCount: vault?.size ?? 0,
      identity: identity
        ? {
            publicKey: identity.publicKey,
            handle: identity.handle,
            createdAt: identity.createdAt,
          }
        : null,
    },
  };
}

async function createVault(
  passphrase?: string
): Promise<MessageResponse> {
  // Generate new GNS identity
  identity = generateIdentity();

  // Create vault
  if (passphrase) {
    vault = Vault.createWithPassphrase(identity.publicKey, passphrase);
  } else {
    vault = Vault.createWithIdentity(identity.publicKey, identity.privateKey);
  }

  // Persist identity and empty encrypted vault
  await persistVault();
  await chrome.storage.local.set({ identity });

  // Start auto-lock timer
  resetAutoLock();

  console.log('[GNS Vault] New vault created. Identity:', identity.publicKey.substring(0, 16) + '...');

  return {
    success: true,
    data: {
      publicKey: identity.publicKey,
      createdAt: identity.createdAt,
    },
  };
}

async function unlockVault(
  passphrase?: string
): Promise<MessageResponse> {
  const stored = await chrome.storage.local.get(['encryptedVault', 'identity']);

  if (!stored.encryptedVault) {
    return { success: false, error: 'No vault found. Create one first.' };
  }
  if (!stored.identity) {
    return { success: false, error: 'Identity not found. Vault may be corrupted.' };
  }

  identity = stored.identity as GnsIdentity;
  const encrypted = stored.encryptedVault as EncryptedVault;

  try {
    if (passphrase) {
      vault = Vault.unlockWithPassphrase(encrypted, passphrase);
    } else {
      vault = Vault.unlockWithIdentity(encrypted, identity.privateKey);
    }

    resetAutoLock();
    return { success: true, data: { entryCount: vault.size } };
  } catch (err) {
    return {
      success: false,
      error: passphrase
        ? 'Incorrect passphrase. Please try again.'
        : 'Failed to unlock vault. ' + (err as Error).message,
    };
  }
}

async function lockVault(): Promise<MessageResponse> {
  if (vault) {
    vault.lock();
    vault = null;
  }
  return { success: true };
}

// ============================================================
// CRUD OPERATIONS
// ============================================================

function requireVault(): InstanceType<typeof Vault> {
  if (!vault) throw new Error('Vault is locked');
  return vault;
}

async function getEntries(): Promise<MessageResponse> {
  const v = requireVault();
  const entries = v.getAllEntries().map(sanitizeEntry);
  return { success: true, data: entries };
}

async function getEntry(id: string): Promise<MessageResponse> {
  const v = requireVault();
  const entry = v.getEntry(id);
  if (!entry) return { success: false, error: 'Entry not found' };
  return { success: true, data: entry };
}

async function addEntry(entryData: PopupMessage & { type: 'VAULT_ADD_ENTRY' } extends { entry: infer E } ? E : never): Promise<MessageResponse> {
  const v = requireVault();
  const entry = v.addEntry({
    type: (entryData.type as EntryType) || EntryType.Login,
    name: entryData.name,
    urls: entryData.urls,
    username: entryData.username,
    password: entryData.password,
    totpSecret: entryData.totpSecret,
    notes: entryData.notes,
    folder: entryData.folder,
  });
  await persistVault();
  return { success: true, data: sanitizeEntry(entry) };
}

async function updateEntry(
  id: string,
  updates: Record<string, unknown>
): Promise<MessageResponse> {
  const v = requireVault();
  const entry = v.updateEntry(id, updates as Parameters<typeof v.updateEntry>[1]);
  await persistVault();
  return { success: true, data: sanitizeEntry(entry) };
}

async function deleteEntry(id: string): Promise<MessageResponse> {
  const v = requireVault();
  const deleted = v.deleteEntry(id);
  if (deleted) await persistVault();
  return { success: true, data: { deleted } };
}

async function searchEntries(query: string): Promise<MessageResponse> {
  const v = requireVault();
  const entries = v.searchEntries(query).map(sanitizeEntry);
  return { success: true, data: entries };
}

async function getStats(): Promise<MessageResponse> {
  const v = requireVault();
  return { success: true, data: v.getStats() };
}

// ============================================================
// PASSWORD GENERATION
// ============================================================

async function generatePwd(
  options?: { length?: number; uppercase?: boolean; lowercase?: boolean; digits?: boolean; symbols?: boolean; excludeAmbiguous?: boolean }
): Promise<MessageResponse> {
  const password = generatePassword(options);
  return {
    success: true,
    data: {
      password,
      strength: passwordStrength(password),
    },
  };
}

// ============================================================
// IMPORT / EXPORT
// ============================================================

async function importEntries(
  data: string,
  format: ImportFormat
): Promise<MessageResponse> {
  const v = requireVault();
  const result = importCredentials(data, format);

  // Add imported entries to vault
  for (const entry of result.entries) {
    v.addEntry(entry);
  }
  await persistVault();

  return {
    success: true,
    data: {
      totalParsed: result.totalParsed,
      totalImported: result.totalImported,
      skipped: result.skipped,
      errors: result.errors,
      newTotal: v.size,
    },
  };
}

async function exportEntries(
  options: { format: 'json' | 'csv'; includePasswords: boolean; folder?: string }
): Promise<MessageResponse> {
  const v = requireVault();
  const data = exportCredentials(v.getAllEntries(), options);
  return { success: true, data: { exported: data } };
}

// ============================================================
// IDENTITY
// ============================================================

async function getIdentity(): Promise<MessageResponse> {
  if (!identity) {
    const stored = await chrome.storage.local.get('identity');
    identity = stored.identity as GnsIdentity | null;
  }
  if (!identity) {
    return { success: false, error: 'No identity found' };
  }
  return {
    success: true,
    data: {
      publicKey: identity.publicKey,
      handle: identity.handle,
      createdAt: identity.createdAt,
      stellarAddress: identity.stellarAddress,
    },
  };
}

async function getTrustScore(): Promise<MessageResponse> {
  // TODO: Integrate with TrIP module / GNS Ledger API
  // For now, return a placeholder based on vault age
  if (!identity) return { success: false, error: 'No identity' };

  const ageDays = Math.floor(
    (Date.now() - new Date(identity.createdAt).getTime()) / 86_400_000
  );

  return {
    success: true,
    data: {
      score: Math.min(100, ageDays * 2), // Placeholder
      breadcrumbs: 0, // Will come from TrIP module
      identityAgeDays: ageDays,
      tier: BadgeTier.Unverified,
    },
  };
}

// ============================================================
// AUTO-FILL (Content Script Interface)
// ============================================================

async function getAutofillData(
  url: string
): Promise<MessageResponse<AutofillData>> {
  if (!vault) {
    return {
      success: true,
      data: { entries: [], gnsAuthAvailable: false },
    };
  }

  const matches = vault.findByUrl(url);

  return {
    success: true,
    data: {
      entries: matches.map((e) => ({
        id: e.id,
        name: e.name,
        username: e.username,
        password: e.password,
      })),
      gnsAuthAvailable: false, // TODO: Check GNS Auth SDK presence
    },
  };
}

async function saveAutofillCredential(
  msg: ContentMessage & { type: 'AUTOFILL_SAVE' }
): Promise<MessageResponse> {
  if (!vault) return { success: false, error: 'Vault is locked' };

  // Check if entry already exists for this URL
  const existing = vault.findByUrl(msg.url);
  const match = existing.find((e) => e.username === msg.username);

  if (match) {
    // Update existing entry's password if changed
    if (match.password !== msg.password) {
      vault.updateEntry(match.id, { password: msg.password });
      await persistVault();
      return { success: true, data: { action: 'updated', id: match.id } };
    }
    return { success: true, data: { action: 'unchanged' } };
  }

  // Create new entry
  let hostname = msg.url;
  try {
    hostname = new URL(msg.url).hostname.replace(/^www\./, '');
  } catch { /* keep original */ }

  const entry = vault.addEntry({
    type: EntryType.Login,
    name: msg.name || hostname,
    urls: [msg.url],
    username: msg.username,
    password: msg.password,
  });
  await persistVault();
  return { success: true, data: { action: 'created', id: entry.id } };
}

// ============================================================
// GNS AUTH
// ============================================================

async function checkGnsAuth(
  _origin: string
): Promise<MessageResponse> {
  // TODO: Check if origin has GNS Auth SDK integrated
  return {
    success: true,
    data: { available: false, origin: _origin },
  };
}

async function signGnsAuth(
  challenge: { nonce: string; origin: string; timestamp: string; expiresIn: number }
): Promise<MessageResponse> {
  if (!identity) return { success: false, error: 'No identity' };

  try {
    const response = signAuthChallenge(
      challenge,
      identity.privateKey,
      0, // TODO: Real trust score from TrIP
      BadgeTier.Unverified,
      identity.handle
    );
    return { success: true, data: response };
  } catch (err) {
    return { success: false, error: (err as Error).message };
  }
}

// ============================================================
// PERSISTENCE
// ============================================================

async function persistVault(): Promise<void> {
  if (!vault) return;
  const encrypted = vault.serialize();
  await chrome.storage.local.set({ encryptedVault: encrypted });
}

async function loadIdentity(): Promise<void> {
  const stored = await chrome.storage.local.get('identity');
  identity = (stored.identity as GnsIdentity) || null;
}

// ============================================================
// AUTO-LOCK
// ============================================================

function resetAutoLock(): void {
  chrome.alarms.clear('auto-lock');
  chrome.alarms.create('auto-lock', { delayInMinutes: AUTO_LOCK_MINUTES });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'auto-lock') {
    console.log('[GNS Vault] Auto-locking vault due to inactivity');
    lockVault();
  }
});

// ============================================================
// HELPERS
// ============================================================

/** Strip sensitive fields for list views (keep password for popup access) */
function sanitizeEntry(entry: ReturnType<InstanceType<typeof Vault>['getAllEntries']>[0]) {
  return {
    id: entry.id,
    type: entry.type,
    name: entry.name,
    urls: entry.urls,
    username: entry.username,
    password: entry.password,
    totpSecret: entry.totpSecret,
    notes: entry.notes,
    folder: entry.folder,
    favorite: entry.favorite,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    lastUsedAt: entry.lastUsedAt,
    passwordStrength: entry.passwordStrength,
  };
}
