/**
 * GNS Verify API — Test Suite
 *
 * Tests all endpoints using Hono's built-in test client (app.request).
 * No server startup needed — tests run against the Hono app directly.
 *
 * NOTE: The verify-api is a proxy to the GNS backend. Tests that depend
 * on identity data use the identityCache directly (simulating cached
 * responses from the backend) rather than a local identity store.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import app, { identityCache, apiKeyStore } from '../src/server.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// Configure noble ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

// ============================================================
// HELPERS
// ============================================================

const TEST_API_KEY = 'gns_test_key_development';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function generateTestIdentity() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    privateKey,
    publicKey,
  };
}

function req(path: string, options?: RequestInit) {
  return app.request(path, options);
}

function jsonPost(path: string, body: unknown, headers: Record<string, string> = {}) {
  return req(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

/**
 * Seed a cached identity (simulates a backend response).
 * The verify-api proxies requests to gns-backend; in tests we
 * populate the identityCache directly.
 */
function seedCachedIdentity(publicKey: string, overrides: Partial<{
  public_key: string; handle: string; display_name: string;
  trust_score: number; breadcrumb_count: number; created_at: string;
}> = {}) {
  identityCache.set(publicKey, {
    data: {
      public_key: publicKey,
      handle: overrides.handle,
      display_name: overrides.display_name,
      trust_score: overrides.trust_score ?? 0,
      breadcrumb_count: overrides.breadcrumb_count ?? 0,
      created_at: overrides.created_at ?? new Date().toISOString(),
    },
    fetchedAt: Date.now(),
  });
}

// ============================================================
// TESTS
// ============================================================

describe('Health Check', () => {
  it('should return ok status', async () => {
    const res = await req('/v1/health');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
    expect(data.service).toBe('gns-verify-api');
    expect(data.version).toBe('0.2.0');
    expect(data.timestamp).toBeDefined();
  });
});

describe('POST /v1/verify', () => {
  beforeEach(() => {
    identityCache.clear();
    // Reset the test API key usage
    apiKeyStore.set(TEST_API_KEY, {
      appName: 'Development',
      tier: 'starter',
      monthlyLimit: 10000,
      monthlyUsage: 0,
    });
  });

  it('should reject without API key', async () => {
    const res = await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.code).toBe('UNAUTHORIZED');
  });

  it('should reject invalid API key', async () => {
    const res = await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) }, {
      'X-API-Key': 'invalid_key',
    });
    expect(res.status).toBe(401);
  });

  it('should accept API key via X-API-Key header', async () => {
    const res = await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) }, {
      'X-API-Key': TEST_API_KEY,
    });
    expect(res.status).toBe(200);
  });

  it('should accept API key via Authorization Bearer', async () => {
    const res = await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) }, {
      'Authorization': `Bearer ${TEST_API_KEY}`,
    });
    expect(res.status).toBe(200);
  });

  it('should reject missing public_key', async () => {
    const res = await jsonPost('/v1/verify', {}, {
      'X-API-Key': TEST_API_KEY,
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.code).toBe('BAD_REQUEST');
  });

  it('should reject invalid public_key length', async () => {
    const res = await jsonPost('/v1/verify', { public_key: 'abc123' }, {
      'X-API-Key': TEST_API_KEY,
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.code).toBe('BAD_REQUEST');
  });

  it('should return unverified for unknown identity', async () => {
    const res = await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) }, {
      'X-API-Key': TEST_API_KEY,
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.human).toBe(false);
    expect(data.trust_score).toBe(0);
    expect(data.badge_tier).toBe('unverified');
    expect(data.meets_requirements).toBe(false);
  });

  it('should return verified data for cached identity', async () => {
    const id = await generateTestIdentity();

    seedCachedIdentity(id.publicKeyHex, {
      handle: '@testuser',
      trust_score: 85,
      breadcrumb_count: 5000,
      created_at: new Date(Date.now() - 90 * 86_400_000).toISOString(),
    });

    const res = await jsonPost('/v1/verify', { public_key: id.publicKeyHex }, {
      'X-API-Key': TEST_API_KEY,
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.human).toBe(true);
    expect(data.trust_score).toBe(85);
    expect(data.breadcrumbs).toBe(5000);
    expect(data.badge_tier).toBe('trailblazer'); // 5000 >= 1000
    expect(data.identity_age_days).toBeGreaterThanOrEqual(89);
    expect(data.meets_requirements).toBe(true);
  });

  it('should check minimum trust score', async () => {
    const id = await generateTestIdentity();

    seedCachedIdentity(id.publicKeyHex, {
      trust_score: 30,
      breadcrumb_count: 100,
      created_at: new Date().toISOString(),
    });

    const res = await jsonPost('/v1/verify', {
      public_key: id.publicKeyHex,
      min_trust_score: 50,
    }, { 'X-API-Key': TEST_API_KEY });

    const data = await res.json();
    expect(data.human).toBe(true);       // 100 breadcrumbs >= 10 && 30 >= 5
    expect(data.meets_requirements).toBe(false); // 30 < 50
  });

  it('should enforce rate limiting', async () => {
    apiKeyStore.set(TEST_API_KEY, {
      appName: 'Development',
      tier: 'starter',
      monthlyLimit: 1,
      monthlyUsage: 1, // Already at limit
    });

    const res = await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) }, {
      'X-API-Key': TEST_API_KEY,
    });
    expect(res.status).toBe(429);
    const data = await res.json();
    expect(data.code).toBe('RATE_LIMITED');
  });

  it('should increment usage counter', async () => {
    const before = apiKeyStore.get(TEST_API_KEY)!.monthlyUsage;

    await jsonPost('/v1/verify', { public_key: 'a'.repeat(64) }, {
      'X-API-Key': TEST_API_KEY,
    });

    const after = apiKeyStore.get(TEST_API_KEY)!.monthlyUsage;
    expect(after).toBe(before + 1);
  });
});

describe('POST /v1/auth/validate', () => {
  it('should validate a correct Ed25519 signature', async () => {
    const id = await generateTestIdentity();
    const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const origin = 'https://example.com';
    const timestamp = new Date().toISOString();

    // Sign the canonical message: nonce|origin|timestamp
    const canonicalMessage = `${nonce}|${origin}|${timestamp}`;
    const messageBytes = new TextEncoder().encode(canonicalMessage);
    const signature = await ed.signAsync(messageBytes, id.privateKey);

    const res = await jsonPost('/v1/auth/validate', {
      response: {
        nonce,
        publicKey: id.publicKeyHex,
        signature: bytesToHex(signature),
        trustScore: 75,
        badgeTier: 'silver',
        handle: '@test',
      },
      challenge: {
        nonce,
        origin,
        timestamp,
        expiresIn: 300,
      },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.valid).toBe(true);
    expect(data.public_key).toBe(id.publicKeyHex);
    expect(data.trust_score).toBe(75);
    expect(data.handle).toBe('@test');
    expect(data.validated_at).toBeDefined();
  });

  it('should reject an invalid signature', async () => {
    const id = await generateTestIdentity();
    const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));

    const res = await jsonPost('/v1/auth/validate', {
      response: {
        nonce,
        publicKey: id.publicKeyHex,
        signature: 'f'.repeat(128), // Fake signature
        trustScore: 0,
        badgeTier: 'unverified',
      },
      challenge: {
        nonce,
        origin: 'https://example.com',
        timestamp: new Date().toISOString(),
        expiresIn: 300,
      },
    });

    const data = await res.json();
    expect(data.valid).toBe(false);
    expect(data.reason).toContain('signature');
  });

  it('should reject nonce mismatch', async () => {
    const id = await generateTestIdentity();
    const nonce1 = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const nonce2 = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const origin = 'https://example.com';
    const timestamp = new Date().toISOString();

    // Sign with nonce1 but send challenge with nonce2
    const canonicalMessage = `${nonce1}|${origin}|${timestamp}`;
    const messageBytes = new TextEncoder().encode(canonicalMessage);
    const signature = await ed.signAsync(messageBytes, id.privateKey);

    const res = await jsonPost('/v1/auth/validate', {
      response: {
        nonce: nonce1,
        publicKey: id.publicKeyHex,
        signature: bytesToHex(signature),
        trustScore: 0,
        badgeTier: 'unverified',
      },
      challenge: {
        nonce: nonce2, // Different nonce!
        origin,
        timestamp,
        expiresIn: 300,
      },
    });

    const data = await res.json();
    // Either the signature is invalid (because it was signed with nonce1 but verified with nonce2)
    // or the nonce mismatch check catches it
    expect(data.valid).toBe(false);
  });

  it('should reject expired challenge', async () => {
    const id = await generateTestIdentity();
    const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const origin = 'https://example.com';
    // Timestamp 10 minutes ago
    const timestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();

    const canonicalMessage = `${nonce}|${origin}|${timestamp}`;
    const messageBytes = new TextEncoder().encode(canonicalMessage);
    const signature = await ed.signAsync(messageBytes, id.privateKey);

    const res = await jsonPost('/v1/auth/validate', {
      response: {
        nonce,
        publicKey: id.publicKeyHex,
        signature: bytesToHex(signature),
        trustScore: 0,
        badgeTier: 'unverified',
      },
      challenge: {
        nonce,
        origin,
        timestamp,
        expiresIn: 300, // 5 minute expiry, but timestamp is 10 min ago
      },
    });

    const data = await res.json();
    expect(data.valid).toBe(false);
    expect(data.reason).toContain('expired');
  });

  it('should reject missing response/challenge', async () => {
    const res = await jsonPost('/v1/auth/validate', {});
    expect(res.status).toBe(400);
  });
});

describe('GET /v1/identity/:publicKey', () => {
  beforeEach(() => {
    identityCache.clear();
  });

  it('should return 404 for unknown identity', async () => {
    const res = await req(`/v1/identity/${'a'.repeat(64)}`);
    expect(res.status).toBe(404);
  });

  it('should return 400 for invalid public key format', async () => {
    const res = await req('/v1/identity/tooshort');
    expect(res.status).toBe(400);
  });

  it('should return identity info for cached identity', async () => {
    const id = await generateTestIdentity();

    seedCachedIdentity(id.publicKeyHex, {
      handle: '@alice',
      trust_score: 92,
      breadcrumb_count: 12000,
      created_at: '2025-01-15T00:00:00.000Z',
    });

    const res = await req(`/v1/identity/${id.publicKeyHex}`);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.public_key).toBe(id.publicKeyHex);
    expect(data.handle).toBe('@alice');
    expect(data.badge_tier).toBe('trailblazer'); // 12000 >= 1000
    expect(data.trust_score).toBe(92);
    expect(data.human_verified).toBe(true);
    expect(data.created_at).toBe('2025-01-15T00:00:00.000Z');
  });
});

describe('GET /v1/usage', () => {
  beforeEach(() => {
    apiKeyStore.set(TEST_API_KEY, {
      appName: 'Development',
      tier: 'starter',
      monthlyLimit: 10000,
      monthlyUsage: 42,
    });
  });

  it('should reject without API key', async () => {
    const res = await req('/v1/usage');
    expect(res.status).toBe(401);
  });

  it('should return usage stats', async () => {
    const res = await req('/v1/usage', {
      headers: { 'X-API-Key': TEST_API_KEY },
    });
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.app_name).toBe('Development');
    expect(data.tier).toBe('starter');
    expect(data.monthly_limit).toBe(10000);
    expect(data.monthly_usage).toBe(42);
    expect(data.remaining).toBe(9958);
  });
});

describe('CORS', () => {
  it('should include CORS headers', async () => {
    const res = await req('/v1/health');
    expect(res.headers.get('access-control-allow-origin')).toBeDefined();
  });
});
