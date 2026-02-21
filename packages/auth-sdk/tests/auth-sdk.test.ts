/**
 * GNS Auth SDK — Test Suite
 *
 * Tests the client-side SDK using jsdom environment.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  init,
  renderButton,
  authenticate,
  isExtensionAvailable,
  verifyLocally,
  destroy,
} from '../src/gns-auth.js';

// ============================================================
// SETUP
// ============================================================

/**
 * In jsdom, window.postMessage doesn't set event.source = window.
 * The SDK checks `event.source !== window`, so we need to dispatch
 * a properly constructed MessageEvent instead.
 */
function simulateExtensionMessage(data: unknown) {
  window.dispatchEvent(
    new MessageEvent('message', { data, source: window })
  );
}

beforeEach(() => {
  // Clean up from previous tests
  destroy();
  document.body.innerHTML = '';
});

afterEach(() => {
  destroy();
});

// ============================================================
// INIT
// ============================================================

describe('init', () => {
  it('should initialize without errors', () => {
    expect(() =>
      init({
        onAuth: () => {},
      })
    ).not.toThrow();
  });

  it('should accept all config options', () => {
    expect(() =>
      init({
        appId: 'test-app',
        onAuth: () => {},
        onError: () => {},
        onExtensionDetect: () => {},
        challengeExpiry: 120,
        minTrustScore: 50,
        minBadgeTier: 'silver',
        buttonStyle: { theme: 'light' },
      })
    ).not.toThrow();
  });
});

// ============================================================
// RENDER BUTTON
// ============================================================

describe('renderButton', () => {
  it('should render a button into a container', () => {
    init({ onAuth: () => {} });

    const container = document.createElement('div');
    container.id = 'gns-login';
    document.body.appendChild(container);

    renderButton('#gns-login');

    const button = container.querySelector('button');
    expect(button).toBeTruthy();
    expect(button!.getAttribute('data-gns-auth-button')).toBe('true');
  });

  it('should render button with "Sign in with GNS" text', () => {
    init({ onAuth: () => {} });

    const container = document.createElement('div');
    container.id = 'target';
    document.body.appendChild(container);

    renderButton('#target');

    const button = container.querySelector('button');
    expect(button!.textContent).toContain('Sign in with GNS');
  });

  it('should render "Human" verified badge', () => {
    init({ onAuth: () => {} });

    const container = document.createElement('div');
    container.id = 'target';
    document.body.appendChild(container);

    renderButton('#target');

    const button = container.querySelector('button');
    expect(button!.textContent).toContain('Human');
  });

  it('should warn for missing container', () => {
    init({ onAuth: () => {} });
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    renderButton('#nonexistent');

    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining('Container not found')
    );
    spy.mockRestore();
  });

  it('should apply custom button style', () => {
    init({ onAuth: () => {}, buttonStyle: { width: '300px', theme: 'light' } });

    const container = document.createElement('div');
    container.id = 'target';
    document.body.appendChild(container);

    renderButton('#target');

    const button = container.querySelector('button') as HTMLButtonElement;
    expect(button.style.width).toBe('300px');
  });

  it('should override style per-button', () => {
    init({ onAuth: () => {} });

    const container = document.createElement('div');
    container.id = 'target';
    document.body.appendChild(container);

    renderButton('#target', { height: '60px' });

    const button = container.querySelector('button') as HTMLButtonElement;
    expect(button.style.height).toBe('60px');
  });
});

// ============================================================
// EXTENSION DETECTION
// ============================================================

describe('isExtensionAvailable', () => {
  it('should return false by default', () => {
    init({ onAuth: () => {} });
    expect(isExtensionAvailable()).toBe(false);
  });

  it('should detect extension via postMessage', async () => {
    let detected: boolean | null = null;

    init({
      onAuth: () => {},
      onExtensionDetect: (d) => { detected = d; },
    });

    // Simulate extension presence response
    simulateExtensionMessage({ type: 'GNS_EXTENSION_PRESENT' });

    // Wait for async message processing
    await new Promise((r) => setTimeout(r, 50));

    expect(isExtensionAvailable()).toBe(true);
    expect(detected).toBe(true);
  });
});

// ============================================================
// AUTHENTICATE
// ============================================================

describe('authenticate', () => {
  it('should reject if not initialized', async () => {
    // destroy() is called in beforeEach, so SDK is not initialized
    await expect(authenticate()).rejects.toEqual(
      expect.objectContaining({ code: 'NOT_INITIALIZED' })
    );
  });

  it('should reject if extension not detected', async () => {
    init({ onAuth: () => {} });

    await expect(authenticate()).rejects.toEqual(
      expect.objectContaining({ code: 'NO_EXTENSION' })
    );
  });

  it('should send challenge via postMessage when extension available', async () => {
    init({ onAuth: () => {}, challengeExpiry: 1 });

    // Fake extension as available
    simulateExtensionMessage({ type: 'GNS_EXTENSION_PRESENT' });
    await new Promise((r) => setTimeout(r, 50));

    const messages: MessageEvent[] = [];
    const messageSpy = (e: MessageEvent) => messages.push(e);
    window.addEventListener('message', messageSpy);

    // Trigger authenticate — will reject with timeout, that's OK
    authenticate().catch(() => {}); // Intentionally unhandled

    // Wait for the challenge message
    await new Promise((r) => setTimeout(r, 100));

    // Check that a challenge was sent
    const challengeMsg = messages.find(
      (m) => m.data?.type === 'GNS_AUTH_SDK'
    );
    expect(challengeMsg).toBeDefined();
    expect(challengeMsg!.data.action).toBe('challenge');
    expect(challengeMsg!.data.challenge.nonce).toBeDefined();
    expect(challengeMsg!.data.challenge.origin).toBeDefined();

    window.removeEventListener('message', messageSpy);
    
    // Wait for timeout to clear
    await new Promise((r) => setTimeout(r, 1200));
  });

  it('should resolve with auth response from extension', async () => {
    const onAuth = vi.fn();
    init({ onAuth, challengeExpiry: 10 });

    // Fake extension
    simulateExtensionMessage({ type: 'GNS_EXTENSION_PRESENT' });

    // Spy on postMessage to capture challenge nonce
    let challengeNonce: string | null = null;
    const original = window.postMessage;
    window.postMessage = function(data: unknown) {
      const d = data as Record<string, unknown>;
      if (d?.type === 'GNS_AUTH_SDK') {
        challengeNonce = (d.challenge as Record<string, string>).nonce;
      }
      return original.call(window, data as never, '*' as never);
    } as typeof window.postMessage;

    const authPromise = authenticate();
    await new Promise((r) => setTimeout(r, 10));

    expect(challengeNonce).toBeTruthy();

    // Simulate extension response with matching nonce
    simulateExtensionMessage({
      type: 'GNS_AUTH_RESPONSE',
      response: {
        publicKey: 'a'.repeat(64),
        signature: 'f'.repeat(128),
        nonce: challengeNonce!,
        trustScore: 85,
        badgeTier: 'gold',
        handle: '@testuser',
        timestamp: new Date().toISOString(),
      },
    });

    const result = await authPromise;
    expect(result.publicKey).toBe('a'.repeat(64));
    expect(result.trustScore).toBe(85);
    expect(result.handle).toBe('@testuser');
    expect(onAuth).toHaveBeenCalled();

    window.postMessage = original;
  });

  it('should reject if extension returns error', async () => {
    init({ onAuth: () => {}, challengeExpiry: 10 });

    simulateExtensionMessage({ type: 'GNS_EXTENSION_PRESENT' });

    const authPromise = authenticate();
    await new Promise((r) => setTimeout(r, 10));

    simulateExtensionMessage({
      type: 'GNS_AUTH_RESPONSE',
      error: { code: 'VAULT_LOCKED', message: 'Vault is locked' },
    });

    await expect(authPromise).rejects.toEqual(
      expect.objectContaining({ code: 'VAULT_LOCKED' })
    );
  });

  it('should reject on nonce mismatch', async () => {
    init({ onAuth: () => {}, challengeExpiry: 10 });

    simulateExtensionMessage({ type: 'GNS_EXTENSION_PRESENT' });

    const authPromise = authenticate();
    await new Promise((r) => setTimeout(r, 10));

    simulateExtensionMessage({
      type: 'GNS_AUTH_RESPONSE',
      response: {
        publicKey: 'a'.repeat(64),
        signature: 'f'.repeat(128),
        nonce: 'wrong_nonce',
        trustScore: 85,
        badgeTier: 'gold',
        timestamp: new Date().toISOString(),
      },
    });

    await expect(authPromise).rejects.toEqual(
      expect.objectContaining({ code: 'NONCE_MISMATCH' })
    );
  });

  it('should enforce minimum trust score', async () => {
    init({ onAuth: () => {}, minTrustScore: 80, challengeExpiry: 10 });

    simulateExtensionMessage({ type: 'GNS_EXTENSION_PRESENT' });

    // Capture nonce via spy
    let challengeNonce: string | null = null;
    const original = window.postMessage;
    window.postMessage = function(data: unknown) {
      const d = data as Record<string, unknown>;
      if (d?.type === 'GNS_AUTH_SDK') {
        challengeNonce = (d.challenge as Record<string, string>).nonce;
      }
      return original.call(window, data as never, '*' as never);
    } as typeof window.postMessage;

    const authPromise = authenticate();
    await new Promise((r) => setTimeout(r, 10));

    simulateExtensionMessage({
      type: 'GNS_AUTH_RESPONSE',
      response: {
        publicKey: 'a'.repeat(64),
        signature: 'f'.repeat(128),
        nonce: challengeNonce!,
        trustScore: 30,
        badgeTier: 'bronze',
        timestamp: new Date().toISOString(),
      },
    });

    await expect(authPromise).rejects.toEqual(
      expect.objectContaining({ code: 'TRUST_TOO_LOW' })
    );

    window.postMessage = original;
  });
});

// ============================================================
// VERIFY LOCALLY
// ============================================================

describe('verifyLocally', () => {
  it('should accept a valid response structure', () => {
    const result = verifyLocally(
      {
        publicKey: 'a'.repeat(64),
        signature: 'f'.repeat(128),
        nonce: 'testnonce',
        trustScore: 50,
        badgeTier: 'silver',
        timestamp: new Date().toISOString(),
      },
      'https://example.com'
    );
    expect(result.valid).toBe(true);
  });

  it('should reject invalid public key length', () => {
    const result = verifyLocally(
      {
        publicKey: 'short',
        signature: 'f'.repeat(128),
        nonce: 'testnonce',
        trustScore: 50,
        badgeTier: 'silver',
        timestamp: new Date().toISOString(),
      },
      'https://example.com'
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('public key');
  });

  it('should reject invalid signature length', () => {
    const result = verifyLocally(
      {
        publicKey: 'a'.repeat(64),
        signature: 'short',
        nonce: 'testnonce',
        trustScore: 50,
        badgeTier: 'silver',
        timestamp: new Date().toISOString(),
      },
      'https://example.com'
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('signature');
  });

  it('should reject missing nonce', () => {
    const result = verifyLocally(
      {
        publicKey: 'a'.repeat(64),
        signature: 'f'.repeat(128),
        nonce: '',
        trustScore: 50,
        badgeTier: 'silver',
        timestamp: new Date().toISOString(),
      },
      'https://example.com'
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('nonce');
  });

  it('should warn about client-side verification', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    verifyLocally(
      {
        publicKey: 'a'.repeat(64),
        signature: 'f'.repeat(128),
        nonce: 'test',
        trustScore: 50,
        badgeTier: 'silver',
        timestamp: new Date().toISOString(),
      },
      'https://example.com'
    );

    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining('development only')
    );
    spy.mockRestore();
  });
});

// ============================================================
// DESTROY
// ============================================================

describe('destroy', () => {
  it('should clean up and prevent further authentication', async () => {
    init({ onAuth: () => {} });
    destroy();

    await expect(authenticate()).rejects.toEqual(
      expect.objectContaining({ code: 'NOT_INITIALIZED' })
    );
  });

  it('should be callable multiple times safely', () => {
    init({ onAuth: () => {} });
    expect(() => {
      destroy();
      destroy();
      destroy();
    }).not.toThrow();
  });
});

// ============================================================
// WINDOW.GNSAUTH
// ============================================================

describe('window.GNSAuth global', () => {
  it('should expose GNSAuth on window', () => {
    const gnsAuth = (window as unknown as Record<string, unknown>).GNSAuth as Record<string, unknown>;
    expect(gnsAuth).toBeDefined();
    expect(typeof gnsAuth.init).toBe('function');
    expect(typeof gnsAuth.renderButton).toBe('function');
    expect(typeof gnsAuth.authenticate).toBe('function');
    expect(typeof gnsAuth.isExtensionAvailable).toBe('function');
    expect(typeof gnsAuth.destroy).toBe('function');
    expect(typeof gnsAuth.verifyLocally).toBe('function');
  });
});
