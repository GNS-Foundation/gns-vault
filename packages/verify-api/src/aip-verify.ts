/**
 * GNS Verify API — AI Agent Identity Protocol (AIP) Routes
 *
 * Server-side provenance chain verification for AI agents.
 * Complements the extension's client-side aip-verify.ts by offering
 * centralized verification that third-party apps can call.
 *
 * Endpoints (mounted at /v1/aip):
 *   POST /verify-chain         — Full three-layer provenance verification
 *   GET  /agent/:agentKey      — Agent identity lookup + provenance status
 *   GET  /jurisdiction/:h3cell — Resolve H3 cell to regulation frameworks
 *   POST /delegation/validate  — Validate a delegation certificate (Ed25519)
 *   GET  /health               — AIP subsystem health check
 *   GET  /well-known/:domain   — Proxy /.well-known/gns-aip.json fetch
 *
 * Reference: draft-ayerbe-sardar-rats-trip-ai-00
 *
 * @module @gns-vault/verify-api/aip-verify
 */

import { Hono } from 'hono';
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

interface AgentManifestEntry {
  agent_key: string;
  model_id?: string;
  creator_org?: string;
  deployer_org?: string;
  model_hash?: string;
  territory_cells?: number[];
  territory_resolution?: number;
  delegation_cert_url?: string;
  capabilities?: string[];
  safety_certs?: string[];
}

type ShieldTier = 'green' | 'amber' | 'red' | 'unknown';

interface LayerResult {
  layer: number;
  label: string;
  org?: string;
  verified: boolean;
  dns_verified: boolean;
  detail?: string;
  trust_score?: number;
}

interface VerifyChainResult {
  agent_key: string;
  model_id?: string;
  creator_org?: string;
  deployer_org?: string;
  shield: ShieldTier;
  layers: LayerResult[];
  verified_at: string;
  warnings: string[];
}

interface DoHResponse {
  Status: number;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

// ============================================================
// JURISDICTION MAP (H3 cells → regulations)
// ============================================================

const JURISDICTION_MAP: Record<string, {
  regulations: string[];
  risk_class: string;
  disclosure_required: boolean;
}> = {
  // European Union
  '821f87fffffffff': { regulations: ['EU AI Act'], risk_class: 'high', disclosure_required: true },
  '821f8ffffffffff': { regulations: ['EU AI Act', 'GDPR'], risk_class: 'high', disclosure_required: true },
  '821fabfffffffff': { regulations: ['EU AI Act', 'GDPR'], risk_class: 'medium', disclosure_required: true },
  // United States — California
  '822d57fffffffff': { regulations: ['CCPA', 'Cal. AI Transparency Act'], risk_class: 'medium', disclosure_required: true },
  // United States — General
  '822d5ffffffffff': { regulations: ['FTC Act §5'], risk_class: 'low', disclosure_required: false },
  // United Kingdom
  '821e27fffffffff': { regulations: ['UK AI Safety Act'], risk_class: 'medium', disclosure_required: true },
};

// ============================================================
// DNS-OVER-HTTPS
// ============================================================

const DOH_GOOGLE = 'https://dns.google/resolve';
const DOH_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

async function verifyOrgDns(org: string): Promise<{ found: boolean; pk?: string; reason: string }> {
  for (const prefix of ['_gns-aip', '_gns']) {
    for (const provider of [DOH_GOOGLE, DOH_CLOUDFLARE]) {
      try {
        const res = await fetch(
          `${provider}?name=${encodeURIComponent(`${prefix}.${org}`)}&type=TXT`,
          { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(3000) },
        );
        if (!res.ok) continue;

        const data = (await res.json()) as DoHResponse;
        if (!data.Answer) continue;

        for (const answer of data.Answer) {
          if (answer.type !== 16) continue;
          const txt = (answer.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '');
          if (txt.includes('v=gns-aip1') || txt.includes('v=gns1')) {
            const pkMatch = txt.match(/pk=([0-9a-fA-F]{64})/);
            return { found: true, pk: pkMatch?.[1]?.toLowerCase(), reason: `Via ${prefix}.${org}` };
          }
        }
      } catch {
        // next provider
      }
    }
  }
  return { found: false, reason: `No GNS TXT record at ${org}` };
}

// ============================================================
// PROVENANCE VERIFICATION
// ============================================================

const PARISI_ALPHA_MIN = 0.30;
const PARISI_ALPHA_MAX = 0.80;

async function verifyAgentChain(agent: AgentManifestEntry, domain: string): Promise<VerifyChainResult> {
  const warnings: string[] = [];
  const layers: LayerResult[] = [];

  // L1: Creator
  let l1 = false;
  if (agent.creator_org) {
    const dns = await verifyOrgDns(agent.creator_org);
    l1 = dns.found;
    layers.push({ layer: 1, label: 'Creator', org: agent.creator_org, verified: l1, dns_verified: l1, detail: l1 ? `${agent.model_id || 'Model'} by ${agent.creator_org}` : dns.reason });
    if (!l1) warnings.push(`Creator DNS failed: ${agent.creator_org}`);
  } else {
    layers.push({ layer: 1, label: 'Creator', verified: false, dns_verified: false, detail: 'No creator declared' });
  }

  // L2: Deployer
  let l2 = false;
  const deployerOrg = agent.deployer_org || domain;
  const deployerDns = await verifyOrgDns(deployerOrg);
  l2 = deployerDns.found;
  layers.push({ layer: 2, label: 'Deployer', org: deployerOrg, verified: l2, dns_verified: l2, detail: l2 ? `${agent.territory_cells?.length || 0} territory cells` : deployerDns.reason });
  if (!l2 && deployerOrg !== domain) warnings.push(`Deployer DNS failed: ${deployerOrg}`);

  // L3: Principal (delegation cert)
  let l3 = false;
  if (agent.delegation_cert_url) {
    try {
      const certRes = await fetch(agent.delegation_cert_url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(5000) });
      if (certRes.ok) {
        const cert = await certRes.json() as Record<string, unknown>;
        const alpha = typeof cert.poh_alpha === 'number' ? cert.poh_alpha : undefined;
        const trustScore = typeof cert.trust_score === 'number' ? cert.trust_score : 0;
        const notAfter = typeof cert.not_after === 'string' ? cert.not_after : undefined;
        const pohValid = alpha !== undefined && alpha >= PARISI_ALPHA_MIN && alpha <= PARISI_ALPHA_MAX;
        const trustValid = trustScore >= 50;
        const temporalValid = !notAfter || new Date(notAfter).getTime() > Date.now();
        l3 = pohValid && trustValid && temporalValid;
        const issues: string[] = [];
        if (!pohValid) issues.push('PoH α out of range');
        if (!trustValid) issues.push(`Trust ${trustScore} < 50`);
        if (!temporalValid) issues.push('Certificate expired');
        layers.push({ layer: 3, label: 'Principal', verified: l3, dns_verified: false, trust_score: trustScore, detail: l3 ? `Trust ${trustScore}/100 · PoH verified` : issues.join('; ') });
        if (!l3) warnings.push(...issues);
      } else {
        layers.push({ layer: 3, label: 'Principal', verified: false, dns_verified: false, detail: 'Certificate fetch failed' });
        warnings.push('Delegation certificate unreachable');
      }
    } catch {
      layers.push({ layer: 3, label: 'Principal', verified: false, dns_verified: false, detail: 'Certificate fetch error' });
    }
  } else {
    layers.push({ layer: 3, label: 'Principal', verified: false, dns_verified: false, detail: 'No delegation cert' });
  }

  let shield: ShieldTier = 'red';
  if (l1 && l2 && l3) shield = 'green';
  else if (l1) shield = 'amber';

  return { agent_key: agent.agent_key, model_id: agent.model_id, creator_org: agent.creator_org, deployer_org: agent.deployer_org || domain, shield, layers, verified_at: new Date().toISOString(), warnings };
}

// ============================================================
// CACHE
// ============================================================

const verificationCache = new Map<string, { result: VerifyChainResult; expires: number }>();

function getCached(key: string): VerifyChainResult | null {
  const entry = verificationCache.get(key);
  if (entry && Date.now() < entry.expires) return entry.result;
  verificationCache.delete(key);
  return null;
}

function setCache(key: string, result: VerifyChainResult): void {
  verificationCache.set(key, { result, expires: Date.now() + 60_000 });
  if (verificationCache.size > 1000) {
    const oldest = verificationCache.keys().next().value;
    if (oldest) verificationCache.delete(oldest);
  }
}

// ============================================================
// MANIFEST FETCH
// ============================================================

async function fetchManifest(domain: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(`https://${domain}/.well-known/gns-aip.json`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    return await res.json() as Record<string, unknown>;
  } catch {
    return null;
  }
}

// ============================================================
// HONO ROUTER
// ============================================================

export const aipVerifyRoutes = new Hono();

// --- Health ---

aipVerifyRoutes.get('/health', (c) => {
  return c.json({
    status: 'ok',
    subsystem: 'aip',
    cache_size: verificationCache.size,
    timestamp: new Date().toISOString(),
  });
});

// --- POST /verify-chain ---

aipVerifyRoutes.post('/verify-chain', async (c) => {
  try {
    const body = await c.req.json() as Record<string, unknown>;
    const domain = typeof body.domain === 'string' ? body.domain : null;
    const agents = Array.isArray(body.agents) ? body.agents : [];

    if (!domain) return c.json({ error: 'Missing domain', code: 'BAD_REQUEST' }, 400);
    if (agents.length === 0 || agents.length > 20) return c.json({ error: 'Provide 1-20 agents', code: 'BAD_REQUEST' }, 400);

    const results: VerifyChainResult[] = [];
    for (const raw of agents) {
      const agent = raw as AgentManifestEntry;
      if (!agent.agent_key || !/^[0-9a-fA-F]{64}$/.test(agent.agent_key)) continue;
      const cached = getCached(agent.agent_key);
      if (cached) { results.push(cached); continue; }
      const result = await verifyAgentChain(agent, domain);
      setCache(agent.agent_key, result);
      results.push(result);
    }

    const priority: ShieldTier[] = ['green', 'amber', 'red', 'unknown'];
    let bestShield: ShieldTier = 'unknown';
    for (const r of results) {
      if (priority.indexOf(r.shield) < priority.indexOf(bestShield)) bestShield = r.shield;
    }

    return c.json({ domain, agent_count: results.length, best_shield: bestShield, agents: results, checked_at: new Date().toISOString() });
  } catch (e) {
    console.error('[AIP] verify-chain error:', e);
    return c.json({ error: 'Internal error', code: 'INTERNAL_ERROR' }, 500);
  }
});

// --- GET /agent/:agentKey ---

aipVerifyRoutes.get('/agent/:agentKey', async (c) => {
  const agentKey = c.req.param('agentKey').toLowerCase();
  if (!/^[0-9a-fA-F]{64}$/.test(agentKey)) {
    return c.json({ error: 'Invalid agent key (expected 64 hex chars)', code: 'BAD_REQUEST' }, 400);
  }
  const cached = getCached(agentKey);
  if (cached) return c.json({ found: true, ...cached });
  return c.json({ found: false, agent_key: agentKey, message: 'Agent not recently verified. Use POST /verify-chain.' });
});

// --- GET /jurisdiction/:h3cell ---

aipVerifyRoutes.get('/jurisdiction/:h3cell', (c) => {
  const cell = c.req.param('h3cell').toLowerCase();
  const binding = JURISDICTION_MAP[cell];
  if (binding) return c.json({ cell, ...binding });
  return c.json({ cell, regulations: [], risk_class: 'unknown', disclosure_required: false, message: 'No jurisdiction mapping found' });
});

// --- POST /delegation/validate (Ed25519 signature verification) ---

aipVerifyRoutes.post('/delegation/validate', async (c) => {
  try {
    const body = await c.req.json() as Record<string, unknown>;

    const principalPk = typeof body.principal_pk === 'string' ? body.principal_pk : null;
    const agentPk = typeof body.agent_pk === 'string' ? body.agent_pk : null;
    const payload = typeof body.payload === 'string' ? body.payload : null;
    const signature = typeof body.signature === 'string' ? body.signature : null;

    if (!principalPk || !agentPk || !payload || !signature) {
      return c.json({ error: 'Missing required fields', code: 'BAD_REQUEST' }, 400);
    }
    if (!/^[0-9a-fA-F]{64}$/.test(principalPk) || !/^[0-9a-fA-F]{64}$/.test(agentPk)) {
      return c.json({ error: 'Invalid public key format', code: 'BAD_REQUEST' }, 400);
    }
    if (!/^[0-9a-fA-F]{128}$/.test(signature)) {
      return c.json({ error: 'Invalid signature format (expected 128 hex chars)', code: 'BAD_REQUEST' }, 400);
    }

    // Verify Ed25519 signature
    let sigValid = false;
    try {
      const sigBytes = hexToBytes(signature);
      const msgBytes = new TextEncoder().encode(payload);
      const pkBytes = hexToBytes(principalPk);
      sigValid = ed.verify(sigBytes, msgBytes, pkBytes);
    } catch {
      sigValid = false;
    }

    // Parse payload for field validation
    let payloadObj: Record<string, unknown> = {};
    try {
      payloadObj = JSON.parse(payload);
    } catch {
      return c.json({ error: 'Invalid payload JSON', code: 'BAD_REQUEST' }, 400);
    }

    // PoH exponents
    const pohAlpha = typeof payloadObj.poh_alpha === 'number' ? payloadObj.poh_alpha : undefined;
    const pohValid = pohAlpha !== undefined
      ? pohAlpha >= PARISI_ALPHA_MIN && pohAlpha <= PARISI_ALPHA_MAX
      : true;

    // Temporal bounds
    const notAfter = typeof payloadObj.not_after === 'string' ? payloadObj.not_after : undefined;
    const temporalValid = !notAfter || new Date(notAfter).getTime() > Date.now();

    // Trust score
    const trustScore = typeof payloadObj.trust_score === 'number' ? payloadObj.trust_score : 0;
    const trustFloor = typeof payloadObj.trust_floor === 'number' ? payloadObj.trust_floor : 50;
    const trustValid = trustScore >= trustFloor;

    return c.json({
      valid: sigValid && pohValid && temporalValid && trustValid,
      signature_valid: sigValid,
      poh_valid: pohValid,
      temporal_valid: temporalValid,
      trust_valid: trustValid,
      overall_valid: sigValid && pohValid && temporalValid && trustValid,
      principal_pk: principalPk,
      agent_pk: agentPk,
      trust_score: trustScore,
      validated_at: new Date().toISOString(),
    });
  } catch (e) {
    console.error('[AIP] delegation/validate error:', e);
    return c.json({ error: 'Internal error', code: 'INTERNAL_ERROR' }, 500);
  }
});

// --- GET /well-known/:domain ---

aipVerifyRoutes.get('/well-known/:domain', async (c) => {
  const domain = c.req.param('domain')?.toLowerCase().replace(/^www\./, '');
  if (!domain || domain.length > 253) {
    return c.json({ error: 'BAD_REQUEST', message: 'Invalid domain' }, 400);
  }
  const manifest = await fetchManifest(domain);
  if (!manifest) {
    return c.json({ domain, found: false, message: `No manifest at ${domain}` });
  }
  return c.json({ domain, found: true, manifest });
});

// ============================================================
// UTILITY
// ============================================================

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
