/**
 * GNS Verify API — Human Verification as a Service
 *
 * REST API that answers: "Is this GNS identity a verified human?"
 *
 * Endpoints:
 *   POST /v1/verify          — Verify a GNS identity's human status
 *   POST /v1/auth/validate   — Validate a GNS Auth challenge-response
 *   GET  /v1/identity/:key   — Get public identity information
 *   GET  /v1/health          — Health check
 *
 * Pricing (enforced via API keys):
 *   Starter:    $0.05/verification (up to 10K/month)
 *   Growth:     $0.02/verification (up to 100K/month)
 *   Scale:      $0.005/verification (1M+/month)
 *   Enterprise: Custom
 *
 * Runs on: Node.js, Deno, Bun, Cloudflare Workers (via Hono)
 *
 * @module @gns-vault/verify-api
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// Configure noble ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

// ============================================================
// TYPES
// ============================================================

interface VerifyRequest {
  /** GNS public key to verify (hex) */
  public_key: string;
  /** Challenge nonce (hex) */
  challenge?: string;
  /** Minimum trust score required */
  min_trust_score?: number;
  /** Minimum badge tier required */
  min_badge_tier?: string;
}

interface VerifyResponse {
  /** Whether the identity is verified as human */
  human: boolean;
  /** TrIP trust score (0-100) */
  trust_score: number;
  /** Total breadcrumbs collected */
  breadcrumbs: number;
  /** Days since identity creation */
  identity_age_days: number;
  /** Badge tier */
  badge_tier: string;
  /** Whether minimum requirements are met */
  meets_requirements: boolean;
  /** Ed25519 signature from the GNS Ledger attesting this data */
  attestation_signature: string;
  /** Timestamp of this verification */
  verified_at: string;
}

interface AuthValidateRequest {
  /** The auth response from the GNS Vault extension */
  response: {
    nonce: string;
    publicKey: string;
    signature: string;
    trustScore: number;
    badgeTier: string;
    handle?: string;
  };
  /** The original challenge that was issued */
  challenge: {
    nonce: string;
    origin: string;
    timestamp: string;
    expiresIn: number;
  };
}

interface IdentityInfo {
  /** Public key (hex) */
  public_key: string;
  /** @handle (if claimed) */
  handle: string | null;
  /** Badge tier */
  badge_tier: string;
  /** Trust score */
  trust_score: number;
  /** Identity creation date */
  created_at: string;
  /** Whether this identity is verified as human */
  human_verified: boolean;
}

// ============================================================
// IN-MEMORY STORE (replace with DB in production)
// ============================================================

// Simulated identity registry — in production, this reads from the GNS Ledger
const identityStore = new Map<string, {
  publicKey: string;
  handle?: string;
  trustScore: number;
  breadcrumbs: number;
  badgeTier: string;
  createdAt: string;
  humanVerified: boolean;
}>();

// API key store — in production, this is a database table
const apiKeyStore = new Map<string, {
  appName: string;
  tier: 'starter' | 'growth' | 'scale' | 'enterprise';
  monthlyLimit: number;
  monthlyUsage: number;
}>();

// Seed a test API key
apiKeyStore.set('gns_test_key_development', {
  appName: 'Development',
  tier: 'starter',
  monthlyLimit: 10000,
  monthlyUsage: 0,
});

// ============================================================
// APP
// ============================================================

const app = new Hono();

// Middleware
app.use('*', cors({
  origin: '*',
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
}));
app.use('*', logger());

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/v1/health', (c) => {
  return c.json({
    status: 'ok',
    service: 'gns-verify-api',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// VERIFY ENDPOINT
// ============================================================

app.post('/v1/verify', async (c) => {
  // Validate API key
  const apiKey = c.req.header('X-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  const keyData = apiKey ? apiKeyStore.get(apiKey) : null;

  if (!keyData) {
    return c.json({ error: 'Invalid or missing API key', code: 'UNAUTHORIZED' }, 401);
  }

  if (keyData.monthlyUsage >= keyData.monthlyLimit) {
    return c.json({ error: 'Monthly verification limit exceeded', code: 'RATE_LIMITED' }, 429);
  }

  // Parse request
  const body = await c.req.json<VerifyRequest>();

  if (!body.public_key || typeof body.public_key !== 'string') {
    return c.json({ error: 'public_key is required (Ed25519 hex string)', code: 'BAD_REQUEST' }, 400);
  }

  if (body.public_key.length !== 64) {
    return c.json({ error: 'public_key must be 64 hex characters (32 bytes)', code: 'BAD_REQUEST' }, 400);
  }

  // Look up identity
  const identity = identityStore.get(body.public_key);

  // Increment usage
  keyData.monthlyUsage++;

  if (!identity) {
    // Unknown identity — not registered on GNS Ledger
    const response: VerifyResponse = {
      human: false,
      trust_score: 0,
      breadcrumbs: 0,
      identity_age_days: 0,
      badge_tier: 'unverified',
      meets_requirements: false,
      attestation_signature: '', // Would be GNS Ledger attestation
      verified_at: new Date().toISOString(),
    };
    return c.json(response);
  }

  // Check requirements
  const minScore = body.min_trust_score ?? 0;
  const meetsRequirements =
    identity.trustScore >= minScore && identity.humanVerified;

  const response: VerifyResponse = {
    human: identity.humanVerified,
    trust_score: identity.trustScore,
    breadcrumbs: identity.breadcrumbs,
    identity_age_days: Math.floor(
      (Date.now() - new Date(identity.createdAt).getTime()) / 86_400_000
    ),
    badge_tier: identity.badgeTier,
    meets_requirements: meetsRequirements,
    attestation_signature: 'placeholder_ledger_attestation', // TODO: Real GNS Ledger signature
    verified_at: new Date().toISOString(),
  };

  return c.json(response);
});

// ============================================================
// AUTH VALIDATE ENDPOINT
// ============================================================

app.post('/v1/auth/validate', async (c) => {
  const body = await c.req.json<AuthValidateRequest>();
  const { response, challenge } = body;

  if (!response || !challenge) {
    return c.json({ error: 'Both response and challenge are required', code: 'BAD_REQUEST' }, 400);
  }

  // Verify Ed25519 signature
  try {
    const canonicalMessage = `${challenge.nonce}|${challenge.origin}|${challenge.timestamp}`;
    const messageBytes = new TextEncoder().encode(canonicalMessage);
    const signatureBytes = hexToBytes(response.signature);
    const publicKeyBytes = hexToBytes(response.publicKey);

    const valid = ed.verify(signatureBytes, messageBytes, publicKeyBytes);

    if (!valid) {
      return c.json({
        valid: false,
        reason: 'Ed25519 signature verification failed',
      });
    }

    // Verify nonce matches
    if (response.nonce !== challenge.nonce) {
      return c.json({
        valid: false,
        reason: 'Nonce mismatch between response and challenge',
      });
    }

    // Check challenge expiry
    const challengeTime = new Date(challenge.timestamp).getTime();
    if (Date.now() - challengeTime > challenge.expiresIn * 1000) {
      return c.json({
        valid: false,
        reason: 'Challenge has expired',
      });
    }

    return c.json({
      valid: true,
      public_key: response.publicKey,
      trust_score: response.trustScore,
      badge_tier: response.badgeTier,
      handle: response.handle,
      validated_at: new Date().toISOString(),
    });
  } catch (err) {
    return c.json({
      valid: false,
      reason: `Verification error: ${(err as Error).message}`,
    }, 400);
  }
});

// ============================================================
// IDENTITY LOOKUP
// ============================================================

app.get('/v1/identity/:publicKey', (c) => {
  const publicKey = c.req.param('publicKey');

  if (!publicKey || publicKey.length !== 64) {
    return c.json({ error: 'Invalid public key format', code: 'BAD_REQUEST' }, 400);
  }

  const identity = identityStore.get(publicKey);

  if (!identity) {
    return c.json({ error: 'Identity not found', code: 'NOT_FOUND' }, 404);
  }

  const info: IdentityInfo = {
    public_key: identity.publicKey,
    handle: identity.handle || null,
    badge_tier: identity.badgeTier,
    trust_score: identity.trustScore,
    created_at: identity.createdAt,
    human_verified: identity.humanVerified,
  };

  return c.json(info);
});

// ============================================================
// ADMIN: Register identity (development only)
// ============================================================

app.post('/v1/admin/register', async (c) => {
  const adminKey = c.req.header('X-Admin-Key');
  if (!adminKey || (adminKey !== process.env.ADMIN_KEY && adminKey !== 'dev_admin_key')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const body = await c.req.json<{
    public_key: string;
    handle?: string;
    trust_score?: number;
    breadcrumbs?: number;
    badge_tier?: string;
    human_verified?: boolean;
  }>();

  identityStore.set(body.public_key, {
    publicKey: body.public_key,
    handle: body.handle,
    trustScore: body.trust_score ?? 0,
    breadcrumbs: body.breadcrumbs ?? 0,
    badgeTier: body.badge_tier ?? 'unverified',
    createdAt: new Date().toISOString(),
    humanVerified: body.human_verified ?? false,
  });

  return c.json({ registered: true, public_key: body.public_key });
});

// ============================================================
// USAGE STATS
// ============================================================

app.get('/v1/usage', (c) => {
  const apiKey = c.req.header('X-API-Key');
  const keyData = apiKey ? apiKeyStore.get(apiKey) : null;

  if (!keyData) {
    return c.json({ error: 'Invalid API key' }, 401);
  }

  return c.json({
    app_name: keyData.appName,
    tier: keyData.tier,
    monthly_limit: keyData.monthlyLimit,
    monthly_usage: keyData.monthlyUsage,
    remaining: keyData.monthlyLimit - keyData.monthlyUsage,
  });
});

// ============================================================
// UTILITY
// ============================================================

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ============================================================
// EXPORT
// ============================================================

export default app;
export { app, identityStore, apiKeyStore };

// Start server only when running directly (not when imported by tests)
if (process.env.NODE_ENV !== 'test') {
  const port = Number(process.env.PORT) || 3847;
  import('@hono/node-server').then(({ serve }) => {
    serve({ fetch: app.fetch, port }, () => {
      console.log(`\n  🌐 GNS Verify API running on http://localhost:${port}`);
      console.log(`  📍 Health check: http://localhost:${port}/v1/health`);
      console.log(`  🔑 Test API key: gns_test_key_development\n`);
    });
  });
}
