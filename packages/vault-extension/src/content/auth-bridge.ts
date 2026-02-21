/**
 * GNS Vault — Auth Bridge (Content Script Module)
 *
 * This module intercepts GNS Auth SDK messages from the page
 * and routes them through the extension's background service worker.
 *
 * Flow:
 *   Page (GNS Auth SDK) ──[window.postMessage]──→ Content Script (Auth Bridge)
 *     ──[chrome.runtime.sendMessage]──→ Background (signs challenge)
 *       ──[response]──→ Content Script ──[window.postMessage]──→ Page
 *
 * The bridge also:
 *   - Announces extension presence to the SDK
 *   - Validates challenge origins
 *   - Handles user consent for new origins
 *
 * @module vault-extension/content/auth-bridge
 */

const GNS_AUTH_MESSAGE_TYPE = 'GNS_AUTH_SDK';
const GNS_AUTH_RESPONSE_TYPE = 'GNS_AUTH_RESPONSE';
const GNS_EXTENSION_DETECT = 'GNS_EXTENSION_DETECT';
const GNS_EXTENSION_PRESENT = 'GNS_EXTENSION_PRESENT';

import { showConsentOverlay } from './consent-overlay';

/** Origins the user has previously approved for GNS Auth */
let approvedOrigins: Set<string> = new Set();

/**
 * Initialize the auth bridge.
 */
export function initAuthBridge(): void {
  // Listen for messages from the page (GNS Auth SDK)
  window.addEventListener('message', handlePageMessage);

  // Announce extension presence
  announcePresence();

  // Load approved origins from storage
  loadApprovedOrigins();

  // Set DOM marker for SDK detection
  document.documentElement.setAttribute('data-gns-vault-extension', 'true');
}

/**
 * Handle messages from the GNS Auth SDK on the page.
 */
function handlePageMessage(event: MessageEvent): void {
  // Only accept messages from the same window
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
    handleAuthChallenge(data.challenge);
    return;
  }
}

/**
 * Handle an authentication challenge from the GNS Auth SDK.
 */
async function handleAuthChallenge(challenge: {
  nonce: string;
  origin: string;
  timestamp: string;
  expiresIn: number;
  appId?: string;
}): Promise<void> {
  // Validate the challenge origin matches the actual page origin
  if (challenge.origin !== window.location.origin) {
    sendAuthError('ORIGIN_MISMATCH', 'Challenge origin does not match page origin');
    return;
  }

  // Check if this origin is approved
  if (!approvedOrigins.has(challenge.origin)) {
    // Show consent overlay to the user
    const approved = await showConsentOverlay({
      origin: challenge.origin,
      appId: challenge.appId,
    });

    if (!approved) {
      sendAuthError('USER_DENIED', 'User denied GNS Auth for this origin');
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
        response.error || 'Failed to sign challenge. Is the vault unlocked?'
      );
      return;
    }

    // Send signed response back to the page
    window.postMessage(
      {
        type: GNS_AUTH_RESPONSE_TYPE,
        response: {
          ...response.data,
          nonce: challenge.nonce,
        },
      },
      '*'
    );
  } catch (err) {
    sendAuthError('INTERNAL', (err as Error).message);
  }
}

/**
 * Announce extension presence to the page.
 */
function announcePresence(): void {
  window.postMessage(
    {
      type: GNS_EXTENSION_PRESENT,
      version: '0.1.0',
    },
    '*'
  );
}

/**
 * Send an error response to the page.
 */
function sendAuthError(code: string, message: string): void {
  window.postMessage(
    {
      type: GNS_AUTH_RESPONSE_TYPE,
      error: { code, message },
    },
    '*'
  );
}

/**
 * Send a message to the background service worker and wait for response.
 */
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
      resolve(response || { success: false, error: 'No response' });
    });
  });
}

/**
 * Load previously approved origins from extension storage.
 */
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

/**
 * Save approved origins to extension storage.
 */
async function saveApprovedOrigins(): Promise<void> {
  try {
    await chrome.storage.local.set({
      approvedAuthOrigins: Array.from(approvedOrigins),
    });
  } catch {
    // Storage may not be available
  }
}
