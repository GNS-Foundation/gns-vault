/**
 * GNS Vault Extension — Message Protocol
 *
 * Defines typed messages between:
 *   - Popup ↔ Background (chrome.runtime)
 *   - Content Script ↔ Background (chrome.runtime)
 *   - Content Script ↔ Page (window.postMessage)
 *
 * @module vault-extension/messages
 */

// ============================================================
// POPUP → BACKGROUND MESSAGES
// ============================================================

export type PopupMessage =
  | { type: 'VAULT_GET_STATUS' }
  | { type: 'VAULT_UNLOCK'; passphrase?: string }
  | { type: 'VAULT_LOCK' }
  | { type: 'VAULT_CREATE'; passphrase?: string }
  | { type: 'VAULT_GET_ENTRIES' }
  | { type: 'VAULT_GET_ENTRY'; id: string }
  | { type: 'VAULT_ADD_ENTRY'; entry: NewEntryData }
  | { type: 'VAULT_UPDATE_ENTRY'; id: string; updates: Partial<EntryUpdateData> }
  | { type: 'VAULT_DELETE_ENTRY'; id: string }
  | { type: 'VAULT_SEARCH'; query: string }
  | { type: 'VAULT_GET_STATS' }
  | { type: 'VAULT_GENERATE_PASSWORD'; options?: PasswordGenRequest }
  | { type: 'VAULT_IMPORT'; data: string; format: string }
  | { type: 'VAULT_EXPORT'; options: ExportRequest }
  | { type: 'IDENTITY_GET' }
  | { type: 'IDENTITY_GET_TRUST_SCORE' }
  | { type: 'IDENTITY_CLAIM_HANDLE'; handle: string }
  | { type: 'AUTH_SIGN_CHALLENGE'; challenge: AuthChallengeData }
  | { type: 'DNS_GET_VERIFICATION'; tabId: number }
  | { type: 'DNS_VERIFY_DOMAIN'; domain: string }
  | { type: 'DNS_CLEAR_CACHE' };

// ============================================================
// CONTENT SCRIPT → BACKGROUND MESSAGES
// ============================================================

export type ContentMessage =
  | { type: 'AUTOFILL_REQUEST'; url: string }
  | { type: 'AUTOFILL_SAVE'; url: string; username: string; password: string; name?: string }
  | { type: 'GNS_AUTH_CHECK'; origin: string }
  | { type: 'GNS_AUTH_RESPOND'; challenge: AuthChallengeData };

// ============================================================
// BACKGROUND → POPUP/CONTENT RESPONSES
// ============================================================

export interface MessageResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

// ============================================================
// DATA TYPES FOR MESSAGES
// ============================================================

export interface NewEntryData {
  type: string;
  name: string;
  urls: string[];
  username: string;
  password: string;
  totpSecret?: string;
  notes?: string;
  folder?: string;
}

export interface EntryUpdateData {
  name: string;
  urls: string[];
  username: string;
  password: string;
  totpSecret?: string;
  notes?: string;
  folder?: string;
  favorite: boolean;
}

export interface PasswordGenRequest {
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
}

export interface ExportRequest {
  format: 'json' | 'csv';
  includePasswords: boolean;
  folder?: string;
}

export interface AuthChallengeData {
  nonce: string;
  origin: string;
  timestamp: string;
  expiresIn: number;
}

export interface VaultStatusData {
  exists: boolean;
  isUnlocked: boolean;
  entryCount: number;
  identity: {
    publicKey: string;
    handle?: string;
    createdAt: string;
  } | null;
}

export interface AutofillData {
  entries: Array<{
    id: string;
    name: string;
    username: string;
    password: string;
  }>;
  gnsAuthAvailable: boolean;
}
