/**
 * GNS Vault — Auth Bridge (Content Script Module)
 *
 * This module intercepts GNS Auth messages from the page
 * and routes them through the extension's background service worker.
 *
 * Supports TWO protocols:
 *   A) CustomEvent — simple, preferred for direct integration
 *      Page fires:   CustomEvent('gns-auth-request', { detail: challenge })
 *      Bridge fires: CustomEvent('gns-auth-response', { detail: response })
 *
 *   B) window.postMessage — used by the GNS Auth SDK (gns-auth.js)
 *      Page posts:   { type: 'GNS_AUTH_SDK', action: 'challenge', challenge }
 *      Bridge posts: { type: 'GNS_AUTH_RESPONSE', response }
 *
 * Flow:
 *   Page ──→ Content Script (Auth Bridge) ──→ Background (signs with Ed25519)
 *     ──→ Content Script ──→ Page (signed response with publicKey + signature)
 *
 * @module vault-extension/content/auth-bridge
 */

import { showConsentOverlay } from './consent-overlay';

// === Protocol constants ===
const GNS_AUTH_MESSAGE_TYPE = 'GNS_AUTH_SDK';
const GNS_AUTH_RESPONSE_TYPE = 'GNS_AUTH_RESPONSE';
const GNS_EXTENSION_DETECT = 'GNS_EXTENSION_DETECT';
const GNS_EXTENSION_PRESENT = 'GNS_EXTENSION_PRESENT';

// === CustomEvent protocol names ===
const CE_AUTH_REQUEST = 'gns-auth-request';
const CE_AUTH_RESPONSE = 'gns-auth-response';
const CE_EXTENSION_DETECT = 'gns-extension-detect';
const CE_EXTENSION_PRESENT = 'gns-extension-present';

/** Origins the user has previously approved for GNS Auth */
let approvedOrigins: Set<string> = new Set();

// ============================================================
// INITIALIZATION
// ============================================================

/**
 * Initialize the auth bridge — called by content/index.ts on every page load.
 */
export function initAuthBridge(): void {
  // Protocol A: Listen for CustomEvent from the page
  window.addEventListener(CE_AUTH_REQUEST, ((e: Event) => handleCustomEventAuth(e as CustomEvent)) as EventListener);
  window.addEventListener(CE_EXTENSION_DETECT, () => announcePresence());

  // Protocol B: Listen for postMessage from the GNS Auth SDK
  window.addEventListener('message', handlePostMessageAuth);

  // Announce extension presence via BOTH protocols
  announcePresence();

  // Load approved origins from storage
  loadApprovedOrigins();

  // Set DOM attribute for SDK detection
  document.documentElement.setAttribute('data-gns-vault-extension', 'true');

  console.log('[GNS Vault] Auth bridge initialized on', window.location.origin);
}

// ============================================================
// PROTOCOL A: CustomEvent handlers
// ============================================================

/**
 * Handle `gns-auth-request` CustomEvent dispatched by the page.
 * The event.detail contains the challenge object:
 *   { nonce, origin, timestamp, expiresIn, appId? }
 */
async function handleCustomEventAuth(event: CustomEvent): Promise<void> {
  const challenge = event.detail;

  if (!challenge || !challenge.nonce) {
    console.warn('[GNS Vault] Invalid auth request — missing nonce');
    return;
  }

  console.log('[GNS Vault] Auth request received via CustomEvent', { nonce: challenge.nonce });

  // Fill in origin if the page didn't provide it
  const fullChallenge = {
    nonce: challenge.nonce,
    origin: challenge.origin || window.location.origin,
    timestamp: challenge.timestamp || new Date().toISOString(),
    expiresIn: challenge.expiresIn || 300,
    appId: challenge.appId,
  };

  await processAuthChallenge(fullChallenge, 'customEvent');
}

// ============================================================
// PROTOCOL B: postMessage handlers
// ============================================================

/**
 * Handle window.postMessage from the GNS Auth SDK (gns-auth.js).
 */
function handlePostMessageAuth(event: MessageEvent): void {
  if (event.source !== window) return;

  const data = event.data;
  if (!data || typeof data !== 'object') return;

  // Extension detection probe
  if (data.type === GNS_EXTENSION_DETECT) {
    announcePresence();
    return;
  }

  // Auth challenge from SDK
  if (data.type === GNS_AUTH_MESSAGE_TYPE && data.action === 'challenge') {
    processAuthChallenge(data.challenge, 'postMessage');
    return;
  }
}

// ============================================================
// SHARED: Process auth challenge (both protocols converge here)
// ============================================================

async function processAuthChallenge(
  challenge: {
    nonce: string;
    origin: string;
    timestamp: string;
    expiresIn: number;
    appId?: string;
  },
  protocol: 'customEvent' | 'postMessage'
): Promise<void> {
  // Validate the challenge origin matches the actual page origin
  // For file:// URLs, be lenient
  const isFileUrl = window.location.protocol === 'file:';
  if (!isFileUrl && challenge.origin !== window.location.origin) {
    sendAuthError('ORIGIN_MISMATCH', 'Challenge origin does not match page origin', protocol);
    return;
  }

  // For file:// or localhost, skip consent overlay (developer mode)
  const isDev = isFileUrl ||
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1';

  if (!isDev && !approvedOrigins.has(challenge.origin)) {
    // Show consent overlay to the user
    const approved = await showConsentOverlay({
      origin: challenge.origin,
      appId: challenge.appId,
    });

    if (!approved) {
      sendAuthError('USER_DENIED', 'User denied GNS Auth for this origin', protocol);
      return;
    }

    approvedOrigins.add(challenge.origin);
    saveApprovedOrigins();
  }

  try {
    // Forward to background service worker for signing
    const response = await sendToBackground({
      type: 'GNS_AUTH_RESPOND',
      challenge: {
        nonce: challenge.nonce,
        origin: challenge.origin,
        timestamp: challenge.timestamp,
        expiresIn: challenge.expiresIn,
      },
    });

    if (!response.success) {
      sendAuthError(
        'SIGN_FAILED',
        response.error || 'Failed to sign challenge. Is the vault unlocked?',
        protocol
      );
      return;
    }

    console.log('[GNS Vault] Auth challenge signed successfully');

    // Send signed response back to the page via BOTH protocols
    const authResponse = {
      ...response.data,
      nonce: challenge.nonce,
    };

    // Always fire CustomEvent (pages can listen for this)
    window.dispatchEvent(
      new CustomEvent(CE_AUTH_RESPONSE, { detail: authResponse })
    );

    // Also send via postMessage (for SDK compatibility)
    window.postMessage(
      {
        type: GNS_AUTH_RESPONSE_TYPE,
        response: authResponse,
      },
      '*'
    );

  } catch (err) {
    sendAuthError('INTERNAL', (err as Error).message, protocol);
  }
}

// ============================================================
// Announce extension presence
// ============================================================

function announcePresence(): void {
  // CustomEvent protocol
  window.dispatchEvent(
    new CustomEvent(CE_EXTENSION_PRESENT, {
      detail: { version: '0.2.0' },
    })
  );

  // postMessage protocol
  window.postMessage(
    {
      type: GNS_EXTENSION_PRESENT,
      version: '0.2.0',
    },
    '*'
  );

  console.log('[GNS Vault] Extension presence announced');
}

// ============================================================
// Error responses
// ============================================================

function sendAuthError(code: string, message: string, protocol: 'customEvent' | 'postMessage'): void {
  const error = { code, message };

  console.warn('[GNS Vault] Auth error:', code, message);

  // Fire on BOTH protocols regardless of source
  window.dispatchEvent(
    new CustomEvent(CE_AUTH_RESPONSE, {
      detail: { error },
    })
  );

  window.postMessage(
    {
      type: GNS_AUTH_RESPONSE_TYPE,
      error,
    },
    '*'
  );
}

// ============================================================
// Background communication
// ============================================================

function sendToBackground(
  message: Record<string, unknown>
): Promise<{ success: boolean; data?: Record<string, unknown>; error?: string }> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        resolve({
          success: false,
          error: chrome.runtime.lastError.message || 'Extension error',
        });
        return;
      }
      resolve(response || { success: false, error: 'No response from background' });
    });
  });
}

// ============================================================
// Approved origins storage
// ============================================================

async function loadApprovedOrigins(): Promise<void> {
  try {
    const stored = await chrome.storage.local.get('approvedAuthOrigins');
    if (stored.approvedAuthOrigins && Array.isArray(stored.approvedAuthOrigins)) {
      approvedOrigins = new Set(stored.approvedAuthOrigins);
    }
  } catch {
    // Storage may not be available in all contexts
  }
}

async function saveApprovedOrigins(): Promise<void> {
  try {
    await chrome.storage.local.set({
      approvedAuthOrigins: Array.from(approvedOrigins),
    });
  } catch {
    // Storage may not be available
  }
}
