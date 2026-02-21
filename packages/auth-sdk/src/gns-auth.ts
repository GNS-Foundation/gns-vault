/**
 * GNS Auth SDK — Website Integration
 *
 * Drop-in SDK that adds "Sign in with GNS" to any website.
 *
 * Usage:
 *   <script src="https://auth.globecrumbs.com/v1/gns-auth.js"></script>
 *   <div id="gns-login"></div>
 *   <script>
 *     GNSAuth.init({
 *       appId: 'your-app-id',
 *       onAuth: (response) => {
 *         // response.publicKey — user's GNS identity
 *         // response.signature — Ed25519 signed challenge
 *         // response.trustScore — TrIP human verification score
 *         // response.badgeTier — human badge level
 *         // Send to your server to verify
 *       },
 *     });
 *     GNSAuth.renderButton('#gns-login');
 *   </script>
 *
 * Protocol:
 *   1. SDK generates a random challenge nonce
 *   2. SDK sends challenge to GNS Vault extension via window.postMessage
 *   3. Extension signs the challenge with user's Ed25519 key
 *   4. SDK receives signed response and calls onAuth callback
 *   5. Website server verifies signature using GNS Verify API or locally
 *
 * @module @gns-vault/auth-sdk
 */

// ============================================================
// TYPES
// ============================================================

export interface GNSAuthConfig {
  /** Your application ID (registered with GNS) */
  appId?: string;
  /** Callback when authentication succeeds */
  onAuth: (response: GNSAuthResponse) => void;
  /** Callback when authentication fails */
  onError?: (error: GNSAuthError) => void;
  /** Callback when GNS Vault extension is detected/not detected */
  onExtensionDetect?: (detected: boolean) => void;
  /** Challenge expiry in seconds (default: 300 = 5 minutes) */
  challengeExpiry?: number;
  /** Minimum required trust score (0-100, default: 0) */
  minTrustScore?: number;
  /** Minimum required badge tier (default: 'unverified') */
  minBadgeTier?: string;
  /** Custom button styling */
  buttonStyle?: Partial<GNSButtonStyle>;
}

export interface GNSAuthResponse {
  /** User's GNS public key (Ed25519, hex) */
  publicKey: string;
  /** Ed25519 signature of (nonce || origin || timestamp) */
  signature: string;
  /** The challenge nonce that was signed */
  nonce: string;
  /** User's TrIP trust score (0-100) */
  trustScore: number;
  /** User's human badge tier */
  badgeTier: string;
  /** User's @handle (if claimed) */
  handle?: string;
  /** Timestamp of the authentication */
  timestamp: string;
}

export interface GNSAuthError {
  code: string;
  message: string;
}

export interface GNSButtonStyle {
  width: string;
  height: string;
  borderRadius: string;
  fontSize: string;
  theme: 'dark' | 'light' | 'outline';
}

// ============================================================
// INTERNAL STATE
// ============================================================

const GNS_AUTH_MESSAGE_TYPE = 'GNS_AUTH_SDK';
const GNS_AUTH_RESPONSE_TYPE = 'GNS_AUTH_RESPONSE';
const GNS_EXTENSION_DETECT = 'GNS_EXTENSION_DETECT';
const GNS_EXTENSION_PRESENT = 'GNS_EXTENSION_PRESENT';

let config: GNSAuthConfig | null = null;
let extensionDetected = false;
let pendingChallenge: {
  nonce: string;
  origin: string;
  timestamp: string;
  expiresIn: number;
  resolve: (response: GNSAuthResponse) => void;
  reject: (error: GNSAuthError) => void;
} | null = null;

// ============================================================
// PUBLIC API
// ============================================================

/**
 * Initialize the GNS Auth SDK.
 *
 * Call this once when your page loads.
 */
export function init(userConfig: GNSAuthConfig): void {
  config = {
    challengeExpiry: 300,
    minTrustScore: 0,
    minBadgeTier: 'unverified',
    ...userConfig,
  };

  // Listen for messages from the GNS Vault extension
  window.addEventListener('message', handleExtensionMessage);

  // Detect if GNS Vault extension is installed
  detectExtension();
}

/**
 * Render a "Sign in with GNS" button into a container element.
 *
 * @param selector - CSS selector for the container element
 * @param style - Optional custom styling
 */
export function renderButton(selector: string, style?: Partial<GNSButtonStyle>): void {
  const container = document.querySelector(selector);
  if (!container) {
    console.warn(`[GNS Auth] Container not found: ${selector}`);
    return;
  }

  const buttonStyle = { ...DEFAULT_BUTTON_STYLE, ...config?.buttonStyle, ...style };
  const button = createButton(buttonStyle);

  button.addEventListener('click', () => {
    authenticate().catch((err) => {
      config?.onError?.({
        code: 'AUTH_FAILED',
        message: err instanceof Error ? err.message : String(err),
      });
    });
  });

  container.appendChild(button);
}

/**
 * Programmatically trigger GNS authentication.
 *
 * @returns Promise that resolves with the auth response
 */
export function authenticate(): Promise<GNSAuthResponse> {
  if (!config) {
    return Promise.reject({ code: 'NOT_INITIALIZED', message: 'Call GNSAuth.init() first' });
  }

  if (!extensionDetected) {
    return Promise.reject({
      code: 'NO_EXTENSION',
      message: 'GNS Vault extension not detected. Install from the Chrome Web Store.',
    });
  }

  return new Promise<GNSAuthResponse>((resolve, reject) => {
    const nonce = generateNonce();
    const timestamp = new Date().toISOString();

    pendingChallenge = {
      nonce,
      origin: window.location.origin,
      timestamp,
      expiresIn: config!.challengeExpiry ?? 300,
      resolve,
      reject,
    };

    // Send challenge to extension via content script
    window.postMessage(
      {
        type: GNS_AUTH_MESSAGE_TYPE,
        action: 'challenge',
        challenge: {
          nonce,
          origin: window.location.origin,
          timestamp,
          expiresIn: config!.challengeExpiry ?? 300,
          appId: config!.appId,
        },
      },
      '*'
    );

    // Timeout
    setTimeout(() => {
      if (pendingChallenge?.nonce === nonce) {
        pendingChallenge = null;
        reject({ code: 'TIMEOUT', message: 'Authentication timed out. Is GNS Vault unlocked?' });
      }
    }, (config!.challengeExpiry ?? 300) * 1000);
  });
}

/**
 * Check if the GNS Vault extension is installed and available.
 */
export function isExtensionAvailable(): boolean {
  return extensionDetected;
}

/**
 * Clean up event listeners. Call when your SPA unmounts.
 */
export function destroy(): void {
  window.removeEventListener('message', handleExtensionMessage);
  config = null;
  pendingChallenge = null;
  extensionDetected = false;
}

/**
 * Server-side signature verification helper.
 *
 * NOTE: For production, verify signatures on your server using
 * the GNS Verify API or an Ed25519 library. This client-side
 * function is provided for development/testing only.
 *
 * @param response - The auth response to verify
 * @param expectedOrigin - Your website's origin
 * @returns Verification result
 */
export function verifyLocally(
  response: GNSAuthResponse,
  _expectedOrigin: string
): { valid: boolean; reason?: string } {
  // Client-side verification is NOT secure — use server-side verification in production
  console.warn(
    '[GNS Auth] Client-side verification is for development only. ' +
    'Use server-side verification (GNS Verify API) in production.'
  );

  // Basic structural checks
  if (!response.publicKey || response.publicKey.length !== 64) {
    return { valid: false, reason: 'Invalid public key format' };
  }
  if (!response.signature || response.signature.length !== 128) {
    return { valid: false, reason: 'Invalid signature format' };
  }
  if (!response.nonce) {
    return { valid: false, reason: 'Missing nonce' };
  }

  return { valid: true };
}

// ============================================================
// EXTENSION COMMUNICATION
// ============================================================

function handleExtensionMessage(event: MessageEvent): void {
  // Only accept messages from the same window
  if (event.source !== window) return;

  const data = event.data;
  if (!data || typeof data !== 'object') return;

  // Extension presence detection
  if (data.type === GNS_EXTENSION_PRESENT) {
    extensionDetected = true;
    config?.onExtensionDetect?.(true);
    return;
  }

  // Auth response from extension
  if (data.type === GNS_AUTH_RESPONSE_TYPE && pendingChallenge) {
    if (data.error) {
      pendingChallenge.reject({
        code: data.error.code || 'AUTH_ERROR',
        message: data.error.message || 'Authentication failed',
      });
      pendingChallenge = null;
      return;
    }

    const response: GNSAuthResponse = data.response;

    // Verify nonce matches
    if (response.nonce !== pendingChallenge.nonce) {
      pendingChallenge.reject({
        code: 'NONCE_MISMATCH',
        message: 'Response nonce does not match challenge',
      });
      pendingChallenge = null;
      return;
    }

    // Check minimum trust score
    if (config?.minTrustScore && response.trustScore < config.minTrustScore) {
      pendingChallenge.reject({
        code: 'TRUST_TOO_LOW',
        message: `Trust score ${response.trustScore} below minimum ${config.minTrustScore}`,
      });
      pendingChallenge = null;
      return;
    }

    // Success
    pendingChallenge.resolve(response);
    pendingChallenge = null;

    // Notify app
    config?.onAuth(response);
  }
}

function detectExtension(): void {
  // Send detection probe
  window.postMessage({ type: GNS_EXTENSION_DETECT }, '*');

  // Also check for injected marker
  setTimeout(() => {
    if (!extensionDetected) {
      const marker = document.querySelector('[data-gns-vault-extension]');
      if (marker) {
        extensionDetected = true;
        config?.onExtensionDetect?.(true);
      } else {
        config?.onExtensionDetect?.(false);
      }
    }
  }, 500);
}

// ============================================================
// BUTTON RENDERING
// ============================================================

const DEFAULT_BUTTON_STYLE: GNSButtonStyle = {
  width: '240px',
  height: '44px',
  borderRadius: '8px',
  fontSize: '14px',
  theme: 'dark',
};

const THEMES = {
  dark: {
    bg: '#1A3C5E',
    bgHover: '#15324e',
    color: '#FFFFFF',
    border: 'none',
    dotColor: '#1E8449',
  },
  light: {
    bg: '#FFFFFF',
    bgHover: '#F5F7FA',
    color: '#1A3C5E',
    border: '1px solid #E0E0E0',
    dotColor: '#1E8449',
  },
  outline: {
    bg: 'transparent',
    bgHover: '#EBF5FB',
    color: '#1A3C5E',
    border: '2px solid #1A3C5E',
    dotColor: '#1E8449',
  },
};

function createButton(style: GNSButtonStyle): HTMLButtonElement {
  const theme = THEMES[style.theme] || THEMES.dark;
  const button = document.createElement('button');

  Object.assign(button.style, {
    width: style.width,
    height: style.height,
    borderRadius: style.borderRadius,
    fontSize: style.fontSize,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontWeight: '500',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '10px',
    background: theme.bg,
    color: theme.color,
    border: theme.border,
    transition: 'all 0.2s ease',
    outline: 'none',
    padding: '0 16px',
    letterSpacing: '0.2px',
  });

  // Hover effect
  button.addEventListener('mouseenter', () => {
    button.style.background = theme.bgHover;
    button.style.transform = 'translateY(-1px)';
    button.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
  });
  button.addEventListener('mouseleave', () => {
    button.style.background = theme.bg;
    button.style.transform = 'none';
    button.style.boxShadow = 'none';
  });

  // GNS dot icon
  const dot = document.createElement('span');
  Object.assign(dot.style, {
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    background: theme.dotColor,
    display: 'inline-block',
    flexShrink: '0',
  });

  // Label
  const label = document.createElement('span');
  label.textContent = 'Sign in with GNS';

  // Verified badge
  const badge = document.createElement('span');
  Object.assign(badge.style, {
    fontSize: '10px',
    opacity: '0.7',
    marginLeft: '2px',
  });
  badge.textContent = '✓ Human';

  button.appendChild(dot);
  button.appendChild(label);
  button.appendChild(badge);

  // Loading state management
  button.setAttribute('data-gns-auth-button', 'true');

  return button;
}

// ============================================================
// UTILITIES
// ============================================================

function generateNonce(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ============================================================
// AUTO-INITIALIZATION (for <script> tag usage)
// ============================================================

// Expose on window for non-module usage
if (typeof window !== 'undefined') {
  (window as unknown as Record<string, unknown>).GNSAuth = {
    init,
    renderButton,
    authenticate,
    isExtensionAvailable,
    destroy,
    verifyLocally,
  };
}
