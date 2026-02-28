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
  | { type: 'DNS_CLEAR_CACHE' }
  // === AIP (AI Agent Identity Protocol) ===
  | { type: 'AIP_GET_AGENTS'; tabId: number }
  | { type: 'AIP_VERIFY_CHAIN'; domain: string }
  | { type: 'AIP_GET_JURISDICTION'; domain: string }
  | { type: 'AIP_CLEAR_CACHE' };

// ============================================================
// CONTENT SCRIPT → BACKGROUND MESSAGES
// ============================================================

export type ContentMessage =
  | { type: 'AUTOFILL_REQUEST'; url: string }
  | { type: 'AUTOFILL_SAVE'; url: string; username: string; password: string; name?: string }
  | { type: 'GNS_AUTH_CHECK'; origin: string }
  | { type: 'GNS_AUTH_RESPOND'; challenge: AuthChallengeData }
  // === AIP (content script → background) ===
  | { type: 'AIP_AGENTS_DETECTED'; tabId: number; agents: AipAgentEntry[] };

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

// ============================================================
// AIP (AI Agent Identity Protocol) TYPES
// ============================================================

/** Shield tier for AI agent provenance verification */
export type AipShieldTier = 'green' | 'amber' | 'red' | 'unknown';

/** /.well-known/gns-aip.json manifest */
export interface AipAgentManifest {
  version: number;
  domain?: string;
  agents: AipAgentEntry[];
  updated_at?: string;
}

/** A single agent entry from the manifest */
export interface AipAgentEntry {
  /** Agent's Ed25519 public key (64 hex chars) */
  agent_key: string;
  /** Model identifier (e.g., "claude-sonnet-4-5-20250929") */
  model_id?: string;
  /** Creator organization domain (e.g., "anthropic.com") */
  creator_org?: string;
  /** Deployer organization domain (defaults to navigated domain) */
  deployer_org?: string;
  /** SHA-256 hash of model weights (hex) */
  model_hash?: string;
  /** H3 territory cell indices */
  territory_cells?: number[];
  /** H3 resolution for territory cells (0-15) */
  territory_resolution?: number;
  /** URL to fetch the delegation certificate */
  delegation_cert_url?: string;
  /** Authorized capability facets */
  capabilities?: string[];
  /** URIs to safety documentation */
  safety_certs?: string[];
  /** Territory-to-regulation mapping */
  jurisdiction_binding?: Record<string, AipJurisdictionBinding>;
}

/** Jurisdiction binding entry from the provenance chain */
export interface AipJurisdictionBinding {
  regulations: string[];
  risk_class?: string;
  disclosure_required?: boolean;
}

/** Delegation certificate (JSON representation of COSE_Sign1 payload) */
export interface AipDelegationCert {
  version: number;
  principal_tit?: string;
  principal_pk?: string;
  agent_pk?: string;
  capabilities: string[];
  territory_cells: number[];
  territory_res?: number;
  not_before?: string;
  not_after?: string;
  max_subdelegation: number;
  trust_score?: number;
  trust_floor?: number;
  poh_alpha?: number;
  poh_beta?: number;
  /** Whether the COSE_Sign1 signature has been cryptographically verified */
  signature_valid: boolean;
}

/** A single verified layer in the provenance chain */
export interface AipProvenanceLayer {
  /** Layer number (1=Creator, 2=Deployer, 3=Principal) */
  layer: 1 | 2 | 3;
  /** Display label */
  label: string;
  /** Organization domain (Layers 1-2) */
  org?: string;
  /** Whether this layer passed verification */
  verified: boolean;
  /** Whether DNS TXT record was found and matched */
  dns_verified: boolean;
  /** Human-readable detail string */
  detail?: string;
  /** Trust score (Layer 3 only) */
  trust_score?: number;
  /** Territory cells (Layer 2) */
  territory_cells?: number[];
  /** Territory resolution (Layer 2) */
  territory_resolution?: number;
  /** Delegation certificate (Layer 3) */
  delegation?: AipDelegationCert;
}

/** Full verification result for a single AI agent */
export interface AipVerificationResult {
  agent_key: string;
  model_id?: string;
  creator_org?: string;
  deployer_org: string;
  shield: AipShieldTier;
  layers: AipProvenanceLayer[];
  jurisdiction?: Record<string, AipJurisdictionBinding>;
  capabilities?: string[];
  safety_certs?: string[];
  delegation?: AipDelegationCert;
  verified_at: string;
  warnings: string[];
  errors: string[];
}

/** Per-tab AIP data stored in chrome.storage.session */
export interface AipTabData {
  domain: string;
  agents: AipVerificationResult[];
  agent_count: number;
  best_shield: AipShieldTier;
  checked_at: string;
}
