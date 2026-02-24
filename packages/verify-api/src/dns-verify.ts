/**
 * GNS DNS-TXT Identity Anchoring — Verify API Routes
 *
 * Adds DNS-based identity verification to the existing verify-api.
 * Resolves _gns.{domain} TXT records, verifies Ed25519 signatures,
 * and cross-checks against gns-backend identity data.
 *
 * New Endpoints:
 *   GET  /v1/dns/:domain          — Full L0–L3 domain verification
 *   GET  /v1/dns/:domain/badge    — Lightweight badge for extension
 *   POST /v1/dns/:domain/report   — Report suspicious anchoring
 *
 * Integration: Import and mount in server.ts:
 *   import { dnsVerifyRoutes } from './dns-verify';
 *   app.route('/v1/dns', dnsVerifyRoutes);
 *
 * @module @gns-vault/verify-api/dns-verify
 */

import { Hono } from 'hono';
import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';

// ============================================================
// TYPES
// ============================================================

export interface GnsTxtRecord {
  v: string;
  pk: string;
  handle?: string;
  enc?: string;
  epoch?: number;
  mr?: string;
  trust?: number;
  relay?: string;
  sig?: string;
  raw: string;
}

export type VerificationLevel = 'L0' | 'L1' | 'L2' | 'L3';

export interface BadgeResult {
  color: 'gray' | 'blue' | 'green' | 'red';
  label: string;
  detail?: string;
}

export interface DnsVerificationResult {
  domain: string;
  verified: boolean;
  level: VerificationLevel;
  level_name: string;
  pk?: string;
  handle?: string;
  enc?: string;
  epoch?: number;
  mr?: string;
  trust_self_reported?: number;
  relay?: string;
  sig_valid?: boolean;
  relay_confirmed?: boolean;
  relay_trust?: number;
  relay_epoch?: number;
  relay_breadcrumbs?: number;
  namespace_match?: boolean;
  namespace?: string;
  badge: BadgeResult;
  checked_at: string;
  dns_location?: string;
  warnings: string[];
  errors: string[];
}

// ============================================================
// CONFIGURATION
// ============================================================

const GNS_BACKEND_URL = process.env.GNS_BACKEND_URL
  || 'https://gns-browser-production.up.railway.app';

const DOH_GOOGLE     = 'https://dns.google/resolve';
const DOH_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

const DNS_CACHE_TTL = 5 * 60 * 1000;

// ============================================================
// UTILITY (matches server.ts pattern)
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
// CACHE
// ============================================================

interface CacheEntry {
  result: DnsVerificationResult;
  expires: number;
}

const dnsCache = new Map<string, CacheEntry>();

function getCached(domain: string): DnsVerificationResult | null {
  const entry = dnsCache.get(domain);
  if (entry && Date.now() < entry.expires) return entry.result;
  dnsCache.delete(domain);
  return null;
}

function setCache(domain: string, result: DnsVerificationResult): void {
  dnsCache.set(domain, { result, expires: Date.now() + DNS_CACHE_TTL });
  if (dnsCache.size > 1000) {
    const oldest = dnsCache.keys().next().value;
    if (oldest) dnsCache.delete(oldest);
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of dnsCache) {
    if (now >= v.expires) dnsCache.delete(k);
  }
}, 10 * 60 * 1000);

// ============================================================
// _gns TXT RECORD PARSER
// ============================================================

export function parseGnsTxt(txtValue: string): GnsTxtRecord | null {
  try {
    const raw = txtValue.trim();
    if (!raw.includes('v=gns1')) return null;

    const pairs: Record<string, string> = {};
    const parts = raw.split(';').map(s => s.trim()).filter(Boolean);

    for (const part of parts) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      pairs[part.substring(0, eq).trim().toLowerCase()] = part.substring(eq + 1).trim();
    }

    if (pairs.v !== 'gns1') return null;
    if (!pairs.pk || !/^[0-9a-fA-F]{64}$/.test(pairs.pk)) return null;

    const record: GnsTxtRecord = { v: 'gns1', pk: pairs.pk.toLowerCase(), raw };

    if (pairs.handle) record.handle = pairs.handle.startsWith('@') ? pairs.handle : `@${pairs.handle}`;
    if (pairs.enc && /^[0-9a-fA-F]{64}$/.test(pairs.enc)) record.enc = pairs.enc.toLowerCase();
    if (pairs.epoch && !isNaN(Number(pairs.epoch))) record.epoch = parseInt(pairs.epoch, 10);
    if (pairs.mr && /^[0-9a-fA-F]{40}$/.test(pairs.mr)) record.mr = pairs.mr.toLowerCase();
    if (pairs.trust && !isNaN(Number(pairs.trust))) {
      const t = parseInt(pairs.trust, 10);
      if (t >= 0 && t <= 100) record.trust = t;
    }
    if (pairs.relay) record.relay = pairs.relay;
    if (pairs.sig && /^[0-9a-fA-F]{128}$/.test(pairs.sig)) record.sig = pairs.sig.toLowerCase();

    return record;
  } catch {
    return null;
  }
}

// ============================================================
// DNS-over-HTTPS RESOLVER
// ============================================================

interface DoHResponse {
  Status: number;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

async function resolveTxtViaDoH(name: string): Promise<string[]> {
  for (const provider of [DOH_GOOGLE, DOH_CLOUDFLARE]) {
    try {
      const res = await fetch(
        `${provider}?name=${encodeURIComponent(name)}&type=TXT`,
        { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(4000) },
      );
      if (!res.ok) continue;

      const data = (await res.json()) as DoHResponse;
      if (!data.Answer) continue;

      return data.Answer
        .filter(a => a.type === 16)
        .map(a => (a.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
    } catch {
      // Try next provider
    }
  }
  return [];
}

async function lookupGnsTxt(domain: string): Promise<{ record: GnsTxtRecord | null; location: string }> {
  for (const loc of [`_gns.${domain}`, `gns-verify.${domain}`, domain]) {
    const txtRecords = await resolveTxtViaDoH(loc);
    for (const txt of txtRecords) {
      const parsed = parseGnsTxt(txt);
      if (parsed) {
        console.log(`[DNS-GNS] ✓ Found _gns record at ${loc}`);
        return { record: parsed, location: loc };
      }
    }
  }
  return { record: null, location: '' };
}

// ============================================================
// SIGNATURE VERIFICATION
// ============================================================

function buildCanonical(record: GnsTxtRecord): string {
  const parts: string[] = [];
  if (record.enc) parts.push(`enc=${record.enc}`);
  if (record.epoch !== undefined) parts.push(`epoch=${record.epoch}`);
  if (record.handle) parts.push(`handle=${record.handle}`);
  if (record.mr) parts.push(`mr=${record.mr}`);
  parts.push(`pk=${record.pk}`);
  if (record.relay) parts.push(`relay=${record.relay}`);
  if (record.trust !== undefined) parts.push(`trust=${record.trust}`);
  parts.push(`v=${record.v}`);
  return parts.join(';');
}

async function verifyRecordSignature(record: GnsTxtRecord): Promise<boolean> {
  if (!record.sig) return false;
  try {
    const canonical = buildCanonical(record);
    const hash = sha256(new TextEncoder().encode(canonical));
    return ed.verify(hexToBytes(record.sig), hash, hexToBytes(record.pk));
  } catch (e) {
    console.error('[DNS-GNS] Signature verification error:', (e as Error).message);
    return false;
  }
}

// ============================================================
// RELAY + NAMESPACE CROSS-CHECKS
// ============================================================

interface RelayCheckResult {
  confirmed: boolean;
  handle?: string;
  trust?: number;
  breadcrumbs?: number;
}

async function relayCheck(pk: string): Promise<RelayCheckResult> {
  try {
    const res = await fetch(`${GNS_BACKEND_URL}/identities/${pk}`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return { confirmed: false };

    const json = await res.json() as { success: boolean; data?: any };
    if (!json.success || !json.data) return { confirmed: false };

    return {
      confirmed: true,
      handle: json.data.handle ? `@${json.data.handle}` : undefined,
      trust: json.data.trust_score,
      breadcrumbs: json.data.breadcrumb_count,
    };
  } catch {
    return { confirmed: false };
  }
}

async function namespaceCheck(_pk: string, domain: string): Promise<{ match: boolean; namespace?: string }> {
  try {
    const res = await fetch(`${GNS_BACKEND_URL}/org/domain/${domain}`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return { match: false };

    const json = await res.json() as { success: boolean; data?: any };
    if (!json.success || !json.data) return { match: false };

    return { match: true, namespace: json.data.namespace };
  } catch {
    return { match: false };
  }
}

// ============================================================
// FULL VERIFICATION PIPELINE
// ============================================================

async function verifyDomain(domain: string): Promise<DnsVerificationResult> {
  const warnings: string[] = [];
  const errors: string[] = [];
  const now = new Date().toISOString();

  const clean = domain
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split(':')[0]
    .toLowerCase();

  const cached = getCached(clean);
  if (cached) return cached;

  // ── L0: DNS Lookup ───────────────────────────────────────
  const { record, location } = await lookupGnsTxt(clean);

  if (!record) {
    const result: DnsVerificationResult = {
      domain: clean, verified: false, level: 'L0', level_name: 'No Record',
      badge: { color: 'gray', label: 'No GNS identity', detail: 'No _gns TXT record found.' },
      checked_at: now, warnings: [], errors: ['No _gns TXT record found at any location'],
    };
    setCache(clean, result);
    return result;
  }

  let level: VerificationLevel = 'L0';

  // ── L1: Signature Verification ───────────────────────────
  let sigValid: boolean | undefined;
  if (record.sig) {
    sigValid = await verifyRecordSignature(record);
    if (sigValid) {
      level = 'L1';
    } else {
      errors.push('Ed25519 signature verification FAILED');
      const result: DnsVerificationResult = {
        domain: clean, verified: false, level: 'L0', level_name: 'Signature Failed',
        pk: record.pk, handle: record.handle, sig_valid: false,
        badge: { color: 'red', label: 'GNS Warning', detail: 'Signature verification failed — possible tampering.' },
        checked_at: now, dns_location: location, warnings, errors,
      };
      setCache(clean, result);
      return result;
    }
  } else {
    warnings.push('No sig field — record authenticity unverifiable');
  }

  // ── L2: Relay Cross-Check ────────────────────────────────
  const relay = await relayCheck(record.pk);
  let relayConfirmed = false;

  if (relay.confirmed) {
    relayConfirmed = true;
    level = 'L2';

    if (record.handle && relay.handle && record.handle !== relay.handle) {
      warnings.push(`Handle mismatch: DNS=${record.handle}, relay=${relay.handle}`);
    }
    if (record.trust !== undefined && relay.trust !== undefined && Math.abs(record.trust - relay.trust) > 10) {
      warnings.push(`Trust discrepancy: DNS=${record.trust}, relay=${relay.trust}`);
    }
  } else {
    warnings.push('Public key not found on GNS relay');
  }

  // ── L3: Namespace Check ──────────────────────────────────
  let nsResult = { match: false, namespace: undefined as string | undefined };
  if (relayConfirmed) {
    nsResult = await namespaceCheck(record.pk, clean);
    if (nsResult.match) level = 'L3';
  }

  // ── Badge ────────────────────────────────────────────────
  const displayName = record.handle || `${record.pk.slice(0, 12)}…`;
  const trustDisplay = relay.trust ?? record.trust;
  let badge: BadgeResult;

  if (errors.length > 0) {
    badge = { color: 'red', label: 'GNS Warning', detail: errors[0] };
  } else if (level === 'L2' || level === 'L3') {
    badge = {
      color: 'green', label: 'GNS Verified',
      detail: `${displayName} · Trust: ${trustDisplay}/100${nsResult.namespace ? ` · ${nsResult.namespace}@` : ''}`,
    };
  } else if (level === 'L1') {
    badge = { color: 'blue', label: 'GNS Claimed', detail: `${displayName} · Sig valid · Relay unconfirmed` };
  } else {
    badge = { color: 'blue', label: 'GNS Claimed', detail: `${displayName} · Unverified` };
  }

  const result: DnsVerificationResult = {
    domain: clean, verified: level >= 'L1', level,
    level_name: level === 'L3' ? 'Org Verified' : level === 'L2' ? 'Relay Confirmed' : level === 'L1' ? 'Key Verified' : 'DNS Present',
    pk: record.pk, handle: record.handle, enc: record.enc,
    epoch: record.epoch, mr: record.mr, trust_self_reported: record.trust, relay: record.relay,
    sig_valid: sigValid, relay_confirmed: relayConfirmed,
    relay_trust: relay.trust, relay_breadcrumbs: relay.breadcrumbs,
    namespace_match: nsResult.match, namespace: nsResult.namespace,
    badge, checked_at: now, dns_location: location, warnings, errors,
  };

  setCache(clean, result);
  return result;
}

// ============================================================
// HONO ROUTES
// ============================================================

export const dnsVerifyRoutes = new Hono();

dnsVerifyRoutes.get('/:domain', async (c) => {
  const domain = c.req.param('domain');
  if (!domain || domain.length < 3) {
    return c.json({ error: 'Invalid domain', code: 'BAD_REQUEST' }, 400);
  }

  const result = await verifyDomain(domain);
  console.log(`[DNS-GNS] ${result.domain} → ${result.level} (${result.badge.color})`);
  return c.json({ success: true, data: result });
});

dnsVerifyRoutes.get('/:domain/badge', async (c) => {
  const domain = c.req.param('domain');
  if (!domain) return c.json({ error: 'Invalid domain' }, 400);

  const result = await verifyDomain(domain);
  return c.json({
    success: true,
    data: {
      ...result.badge,
      level: result.level,
      handle: result.handle,
      trust: result.relay_trust ?? result.trust_self_reported,
    },
  });
});

dnsVerifyRoutes.post('/:domain/report', async (c) => {
  const domain = c.req.param('domain');
  const body = await c.req.json<{ reporter_pk: string; reason: string }>();

  if (!domain || !body.reporter_pk || !body.reason) {
    return c.json({ error: 'Missing required fields', code: 'BAD_REQUEST' }, 400);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(body.reporter_pk)) {
    return c.json({ error: 'Invalid reporter public key', code: 'BAD_REQUEST' }, 400);
  }

  console.log(`[DNS-GNS] ⚠ REPORT: ${domain} by ${body.reporter_pk.slice(0, 16)}… — ${body.reason}`);

  return c.json({
    success: true,
    data: {
      domain, reported_at: new Date().toISOString(),
      status: 'received', message: 'Report received. GNS operators will review.',
    },
  }, 201);
});

// ============================================================
// UTILITY: Generate _gns TXT record value
// ============================================================

export function generateGnsTxtValue(params: {
  pk: string; handle?: string; enc?: string;
  epoch?: number; mr?: string; trust?: number; relay?: string;
}): string {
  const parts = [`v=gns1`, `pk=${params.pk}`];
  if (params.handle) parts.push(`handle=${params.handle}`);
  if (params.enc) parts.push(`enc=${params.enc}`);
  if (params.epoch !== undefined) parts.push(`epoch=${params.epoch}`);
  if (params.mr) parts.push(`mr=${params.mr}`);
  if (params.trust !== undefined) parts.push(`trust=${params.trust}`);
  if (params.relay) parts.push(`relay=${params.relay}`);
  return parts.join('; ');
}
