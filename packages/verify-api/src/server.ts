/**
 * GNS Verify API — Human Verification as a Service (v0.2.0)
 *
 * REST API that answers: "Is this GNS identity a verified human?"
 *
 * Architecture (Option B — Proxy):
 *   vault.gcrumbs.com → gns-browser-production.up.railway.app
 *   No local identity store. The gns-backend is the source of truth.
 *   Flutter app syncs breadcrumbs to gns-backend as before.
 *   This API reads from there and presents a clean verification interface.
 *
 * Endpoints:
 *   POST /v1/verify          — Verify a GNS identity's human status
 *   POST /v1/auth/validate   — Validate a GNS Auth challenge-response
 *   GET  /v1/identity/:key   — Get public identity information
 *   GET  /v1/health          — Health check
 *   GET  /v1/stats           — Network-wide identity statistics
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
// CONFIGURATION
// ============================================================

/** GNS Backend — source of truth for all identity data */
const GNS_BACKEND_URL = process.env.GNS_BACKEND_URL
  || 'https://gns-browser-production.up.railway.app';

/** Cache TTL in milliseconds (identity data cached for 60 seconds) */
const CACHE_TTL_MS = 60_000;

// ============================================================
// TYPES
// ============================================================

interface BackendIdentity {
  public_key: string;
  encryption_key?: string;
  handle?: string;
  display_name?: string;
  bio?: string;
  avatar_url?: string;
  trust_score: number;
  breadcrumb_count: number;
  created_at: string;
}

interface VerifyRequest {
  public_key: string;
  challenge?: string;
  min_trust_score?: number;
  min_badge_tier?: string;
}

interface VerifyResponse {
  human: boolean;
  trust_score: number;
  breadcrumbs: number;
  identity_age_days: number;
  badge_tier: string;
  meets_requirements: boolean;
  attestation_signature: string;
  verified_at: string;
}

interface AuthValidateRequest {
  response: {
    nonce: string;
    publicKey: string;
    signature: string;
    trustScore: number;
    badgeTier: string;
    handle?: string;
  };
  challenge: {
    nonce: string;
    origin: string;
    timestamp: string;
    expiresIn: number;
  };
}

interface IdentityInfo {
  public_key: string;
  handle: string | null;
  badge_tier: string;
  trust_score: number;
  breadcrumbs: number;
  created_at: string;
  human_verified: boolean;
  display_name?: string | null;
}

// ============================================================
// IDENTITY CACHE (short-lived, avoids hammering gns-backend)
// ============================================================

interface CachedIdentity {
  data: BackendIdentity;
  fetchedAt: number;
}

const identityCache = new Map<string, CachedIdentity>();

/** Fetch identity from gns-backend (with short cache) */
async function fetchIdentity(publicKey: string): Promise<BackendIdentity | null> {
  // Check cache
  const cached = identityCache.get(publicKey);
  if (cached && (Date.now() - cached.fetchedAt) < CACHE_TTL_MS) {
    return cached.data;
  }

  try {
    const url = `${GNS_BACKEND_URL}/identities/${publicKey}`;
    const res = await fetch(url, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      if (res.status === 404) return null;
      console.error(`Backend returned ${res.status} for ${publicKey.substring(0, 16)}...`);
      return null;
    }

    const json = await res.json() as { success: boolean; data?: BackendIdentity };

    if (!json.success || !json.data) return null;

    // Cache it
    identityCache.set(publicKey, {
      data: json.data,
      fetchedAt: Date.now(),
    });

    return json.data;
  } catch (err) {
    console.error(`Backend fetch error for ${publicKey.substring(0, 16)}...:`, (err as Error).message);

    // Return stale cache if backend is down
    if (cached) {
      console.log('  ↳ Returning stale cached data');
      return cached.data;
    }
    return null;
  }
}

// ============================================================
// BADGE TIER CALCULATION
// ============================================================

function calculateBadgeTier(breadcrumbs: number): string {
  if (breadcrumbs >= 1000) return 'trailblazer';
  if (breadcrumbs >= 250) return 'navigator';
  if (breadcrumbs >= 50) return 'explorer';
  if (breadcrumbs >= 1) return 'seedling';
  return 'unverified';
}

function isHumanVerified(trustScore: number, breadcrumbs: number): boolean {
  return breadcrumbs >= 10 && trustScore >= 5;
}

// ============================================================
// API KEY STORE
// ============================================================

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

app.get('/v1/health', async (c) => {
  // Quick check if backend is reachable
  let backendStatus = 'unknown';
  try {
    const res = await fetch(`${GNS_BACKEND_URL}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    backendStatus = res.ok ? 'connected' : `error_${res.status}`;
  } catch {
    backendStatus = 'unreachable';
  }

  return c.json({
    status: 'ok',
    service: 'gns-verify-api',
    version: '0.2.0',
    backend: backendStatus,
    backend_url: GNS_BACKEND_URL,
    cache_entries: identityCache.size,
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

  // Increment usage
  keyData.monthlyUsage++;

  // Fetch from gns-backend
  const identity = await fetchIdentity(body.public_key.toLowerCase());

  if (!identity) {
    const response: VerifyResponse = {
      human: false,
      trust_score: 0,
      breadcrumbs: 0,
      identity_age_days: 0,
      badge_tier: 'unverified',
      meets_requirements: false,
      attestation_signature: '',
      verified_at: new Date().toISOString(),
    };
    return c.json(response);
  }

  const trustScore = identity.trust_score ?? 0;
  const breadcrumbs = identity.breadcrumb_count ?? 0;
  const badgeTier = calculateBadgeTier(breadcrumbs);
  const humanVerified = isHumanVerified(trustScore, breadcrumbs);
  const identityAgeDays = Math.floor(
    (Date.now() - new Date(identity.created_at).getTime()) / 86_400_000
  );

  // Check requirements
  const minScore = body.min_trust_score ?? 0;
  const meetsRequirements = trustScore >= minScore && humanVerified;

  const response: VerifyResponse = {
    human: humanVerified,
    trust_score: trustScore,
    breadcrumbs: breadcrumbs,
    identity_age_days: identityAgeDays,
    badge_tier: badgeTier,
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
      return c.json({ valid: false, reason: 'Ed25519 signature verification failed' });
    }

    // Verify nonce matches
    if (response.nonce !== challenge.nonce) {
      return c.json({ valid: false, reason: 'Nonce mismatch' });
    }

    // Check challenge expiry
    const challengeTime = new Date(challenge.timestamp).getTime();
    if (Date.now() - challengeTime > challenge.expiresIn * 1000) {
      return c.json({ valid: false, reason: 'Challenge has expired' });
    }

    // Enrich with live data from backend
    const identity = await fetchIdentity(response.publicKey.toLowerCase());
    const liveTrustScore = identity?.trust_score ?? response.trustScore;
    const liveBreadcrumbs = identity?.breadcrumb_count ?? 0;
    const liveBadgeTier = identity
      ? calculateBadgeTier(liveBreadcrumbs)
      : response.badgeTier;

    return c.json({
      valid: true,
      public_key: response.publicKey,
      handle: identity?.handle || response.handle,
      trust_score: liveTrustScore,
      badge_tier: liveBadgeTier,
      breadcrumbs: liveBreadcrumbs,
      human_verified: identity
        ? isHumanVerified(liveTrustScore, liveBreadcrumbs)
        : false,
      display_name: identity?.display_name || null,
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

app.get('/v1/identity/:publicKey', async (c) => {
  const publicKey = c.req.param('publicKey');

  if (!publicKey || publicKey.length !== 64) {
    return c.json({ error: 'Invalid public key format', code: 'BAD_REQUEST' }, 400);
  }

  const identity = await fetchIdentity(publicKey.toLowerCase());

  if (!identity) {
    return c.json({ error: 'Identity not found', code: 'NOT_FOUND' }, 404);
  }

  const breadcrumbs = identity.breadcrumb_count ?? 0;
  const trustScore = identity.trust_score ?? 0;

  const info: IdentityInfo = {
    public_key: identity.public_key,
    handle: identity.handle || null,
    display_name: identity.display_name || null,
    badge_tier: calculateBadgeTier(breadcrumbs),
    trust_score: trustScore,
    breadcrumbs: breadcrumbs,
    created_at: identity.created_at,
    human_verified: isHumanVerified(trustScore, breadcrumbs),
  };

  return c.json(info);
});

// ============================================================
// STATS — Network-wide identity statistics
// ============================================================

app.get('/v1/stats', (c) => {
  // Cache stats only (we can't enumerate the full backend from here)
  // For real stats, query the backend's database directly
  return c.json({
    cached_identities: identityCache.size,
    cache_ttl_seconds: CACHE_TTL_MS / 1000,
    backend_url: GNS_BACKEND_URL,
    note: 'Identity data is sourced from gns-backend. Cache is short-lived.',
    timestamp: new Date().toISOString(),
  });
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
// EXPORT & START
// ============================================================

app.route('/v1/dns', dnsVerifyRoutes);
app.route('/v1/aip', aipVerifyRoutes);

export default app;

const port = Number(process.env.PORT) || 3847;

import { serve } from '@hono/node-server';
import { dnsVerifyRoutes } from './dns-verify.js';
import { aipVerifyRoutes } from './aip-verify.js';

serve({ fetch: app.fetch, port }, () => {
  console.log(`\n  🌐 GNS Verify API v0.2.0 running on http://localhost:${port}`);
  console.log(`  📍 Health check: http://localhost:${port}/v1/health`);
  console.log(`  🔗 Backend: ${GNS_BACKEND_URL}`);
  console.log(`  🔑 Test API key: gns_test_key_development\n`);
});
