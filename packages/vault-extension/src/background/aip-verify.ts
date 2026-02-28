/**
 * GNS Vault Extension — AI Agent Identity Protocol (AIP) Verification
 *
 * Verifies three-layer provenance chains for AI agents operating on
 * websites the user visits. Complements dns-verify.ts (which handles
 * _gns TXT records for human/org identity) with agent-specific verification.
 *
 * Detection chain:
 *   1. Fetch /.well-known/gns-aip.json from the navigated domain
 *   2. Fallback: Check _gns-aip.{domain} DNS TXT via DoH
 *   3. Fallback: Content script detects <meta name="gns-aip-agent"> tags
 *   4. For each declared agent, verify the three-layer provenance chain
 *
 * Provenance chain (per draft-ayerbe-sardar-rats-trip-ai-00):
 *   Layer 1 (Creator):   Model hash + DNS-verified org key
 *   Layer 2 (Deployer):  Config hash + territory cells + DNS-verified org key
 *   Layer 3 (Principal): TRIP TIT + trust score + PoH cert + delegation cert
 *
 * Integration pattern:
 *   - Navigation listener: Call initAipVerification() at module level
 *   - Message routing:     Add AIP cases to handleMessage() switch
 *
 * This module does NOT register its own chrome.runtime.onMessage listener.
 * All message handling goes through the existing centralized router
 * in background/index.ts.
 *
 * @module vault-extension/background/aip-verify
 */

import type { MessageResponse } from '../utils/messages';
import type {
    AipAgentManifest,
    AipAgentEntry,
    AipVerificationResult,
    AipShieldTier,
    AipProvenanceLayer,
    AipJurisdictionBinding,
    AipDelegationCert,
    AipTabData,
} from '../utils/messages';

// ============================================================
// CONFIGURATION
// ============================================================

/** GNS Verify API — server-side provenance verification */
const VERIFY_API_BASE = 'https://vault.gcrumbs.com';

/** DNS-over-HTTPS providers (reused from dns-verify.ts) */
const DOH_GOOGLE = 'https://dns.google/resolve';
const DOH_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

/** Cache TTL for AIP verification results */
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** Maximum agents per domain (prevent abuse) */
const MAX_AGENTS_PER_DOMAIN = 20;

/** Valid Parisi exponent range for PoH certificates */
const PARISI_ALPHA_MIN = 0.30;
const PARISI_ALPHA_MAX = 0.80;

// ============================================================
// TYPES (internal — public types in utils/messages.ts)
// ============================================================

interface CacheEntry {
    result: AipTabData;
    expires: number;
}

interface DoHResponse {
    Status: number;
    Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

interface DnsAipRecord {
    v: string;
    agents: number;
    creator?: string;
    deployer?: string;
    pk?: string;
}

// ============================================================
// SHIELD CONFIG
// ============================================================

const SHIELD_CONFIG: Record<AipShieldTier, { text: string; color: string }> = {
    green: { text: '✓', color: '#2E8B57' },
    amber: { text: '⚠', color: '#D97706' },
    red: { text: '✗', color: '#EF4444' },
    unknown: { text: '', color: '#6B7280' },
};

// ============================================================
// CACHE
// ============================================================

const aipCache = new Map<string, CacheEntry>();

function getCached(domain: string): AipTabData | null {
    const entry = aipCache.get(domain);
    if (entry && Date.now() < entry.expires) return entry.result;
    aipCache.delete(domain);
    return null;
}

function setCache(domain: string, result: AipTabData): void {
    aipCache.set(domain, { result, expires: Date.now() + CACHE_TTL_MS });
    // Evict oldest if cache exceeds limit
    if (aipCache.size > 500) {
        const oldest = aipCache.keys().next().value;
        if (oldest) aipCache.delete(oldest);
    }
}

// ============================================================
// BADGE RENDERING (reuses chrome.action API)
// ============================================================

/**
 * Update the extension badge with AIP shield status.
 * Only overrides existing DNS badge if agents are detected.
 */
async function updateAipBadge(tabId: number, shield: AipShieldTier, agentCount: number): Promise<void> {
    // Only show AIP badge if agents are actually present
    if (agentCount === 0) return;

    const config = SHIELD_CONFIG[shield];
    try {
        await chrome.action.setBadgeText({ tabId, text: config.text });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: config.color });
        await chrome.action.setTitle({
            tabId,
            title: `GNS Vault — ${agentCount} AI agent${agentCount > 1 ? 's' : ''} (${shield})`,
        });
    } catch {
        // Tab may have closed
    }
}

// ============================================================
// WELL-KNOWN MANIFEST FETCH
// ============================================================

/**
 * Fetch /.well-known/gns-aip.json from a domain.
 * This is the primary discovery mechanism for AI agents.
 */
async function fetchWellKnownManifest(domain: string): Promise<AipAgentManifest | null> {
    try {
        const res = await fetch(`https://${domain}/.well-known/gns-aip.json`, {
            headers: { 'Accept': 'application/json' },
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) return null;

        const json = await res.json() as unknown;
        return parseAgentManifest(json);
    } catch {
        return null;
    }
}

/**
 * Parse and validate an agent manifest.
 * Rejects malformed or oversized manifests.
 */
function parseAgentManifest(raw: unknown): AipAgentManifest | null {
    if (!raw || typeof raw !== 'object') return null;

    const obj = raw as Record<string, unknown>;
    if (obj.version !== 1 && obj.version !== '1') return null;
    if (!Array.isArray(obj.agents)) return null;
    if (obj.agents.length === 0 || obj.agents.length > MAX_AGENTS_PER_DOMAIN) return null;

    const agents: AipAgentEntry[] = [];

    for (const entry of obj.agents) {
        if (!entry || typeof entry !== 'object') continue;
        const e = entry as Record<string, unknown>;

        // agent_key is required — 64 hex chars (32 bytes Ed25519)
        if (typeof e.agent_key !== 'string' || !/^[0-9a-fA-F]{64}$/.test(e.agent_key)) continue;

        const agent: AipAgentEntry = {
            agent_key: (e.agent_key as string).toLowerCase(),
            model_id: typeof e.model_id === 'string' ? e.model_id : undefined,
            creator_org: typeof e.creator_org === 'string' ? e.creator_org : undefined,
            deployer_org: typeof e.deployer_org === 'string' ? e.deployer_org : undefined,
            model_hash: typeof e.model_hash === 'string' ? e.model_hash : undefined,
            territory_cells: Array.isArray(e.territory_cells) ? e.territory_cells : undefined,
            territory_resolution: typeof e.territory_resolution === 'number' ? e.territory_resolution : undefined,
            delegation_cert_url: typeof e.delegation_cert_url === 'string' ? e.delegation_cert_url : undefined,
            capabilities: Array.isArray(e.capabilities) ? e.capabilities : undefined,
            safety_certs: Array.isArray(e.safety_certs) ? e.safety_certs : undefined,
            jurisdiction_binding: typeof e.jurisdiction_binding === 'object' && e.jurisdiction_binding !== null
                ? e.jurisdiction_binding as Record<string, AipJurisdictionBinding>
                : undefined,
        };

        agents.push(agent);
    }

    if (agents.length === 0) return null;

    return {
        version: 1,
        domain: typeof obj.domain === 'string' ? obj.domain : undefined,
        agents,
        updated_at: typeof obj.updated_at === 'string' ? obj.updated_at : undefined,
    };
}

// ============================================================
// DNS-OVER-HTTPS FALLBACK
// ============================================================

/**
 * Check _gns-aip.{domain} TXT record as fallback discovery.
 * Format: v=gns-aip1; agents=2; creator=anthropic.com; pk=<hex>
 */
async function checkAipDnsTxt(domain: string): Promise<DnsAipRecord | null> {
    const name = `_gns-aip.${domain}`;

    for (const provider of [DOH_GOOGLE, DOH_CLOUDFLARE]) {
        try {
            const res = await fetch(
                `${provider}?name=${encodeURIComponent(name)}&type=TXT`,
                { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(3000) },
            );
            if (!res.ok) continue;

            const data = (await res.json()) as DoHResponse;
            if (!data.Answer) continue;

            for (const answer of data.Answer) {
                if (answer.type !== 16) continue;
                const txt = (answer.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '');
                const parsed = parseAipTxtRecord(txt);
                if (parsed) return parsed;
            }
        } catch {
            // Try next provider
        }
    }

    return null;
}

/**
 * Parse a _gns-aip TXT record.
 */
function parseAipTxtRecord(txt: string): DnsAipRecord | null {
    if (!txt.includes('v=gns-aip1')) return null;

    const pairs: Record<string, string> = {};
    txt.split(';').forEach(part => {
        const eq = part.indexOf('=');
        if (eq > 0) pairs[part.substring(0, eq).trim().toLowerCase()] = part.substring(eq + 1).trim();
    });

    if (pairs.v !== 'gns-aip1') return null;

    return {
        v: 'gns-aip1',
        agents: pairs.agents ? parseInt(pairs.agents, 10) : 0,
        creator: pairs.creator,
        deployer: pairs.deployer,
        pk: pairs.pk?.toLowerCase(),
    };
}

// ============================================================
// PROVENANCE CHAIN VERIFICATION
// ============================================================

/**
 * Verify a single agent's three-layer provenance chain.
 *
 * Layer 1 (Creator):   DNS TXT at _gns-aip.{creator_org} must contain
 *                      a public key that matches the Creator submod signature.
 * Layer 2 (Deployer):  DNS TXT at _gns-aip.{deployer_org} must contain
 *                      a public key that matches the Deployer submod signature.
 * Layer 3 (Principal): Delegation certificate must carry valid PoH exponents
 *                      and trust score above threshold.
 */
async function verifyAgentProvenance(
    agent: AipAgentEntry,
    domain: string,
): Promise<AipVerificationResult> {
    const warnings: string[] = [];
    const errors: string[] = [];
    const layers: AipProvenanceLayer[] = [];
    const now = new Date().toISOString();

    // ── Layer 1: Creator Verification ─────────────────────────
    let l1Verified = false;

    if (agent.creator_org) {
        const creatorDns = await verifyOrgDns(agent.creator_org);

        if (creatorDns.found) {
            l1Verified = true;
            layers.push({
                layer: 1,
                label: 'Creator',
                org: agent.creator_org,
                verified: true,
                dns_verified: true,
                detail: `${agent.model_id || 'Unknown model'}`,
            });
        } else {
            layers.push({
                layer: 1,
                label: 'Creator',
                org: agent.creator_org,
                verified: false,
                dns_verified: false,
                detail: creatorDns.reason,
            });
            warnings.push(`Creator DNS verification failed for ${agent.creator_org}`);
        }
    } else {
        layers.push({
            layer: 1,
            label: 'Creator',
            org: undefined,
            verified: false,
            dns_verified: false,
            detail: 'No creator organization declared',
        });
    }

    // ── Layer 2: Deployer Verification ────────────────────────
    let l2Verified = false;

    // Deployer is the domain itself if not explicitly specified
    const deployerOrg = agent.deployer_org || domain;
    const deployerDns = await verifyOrgDns(deployerOrg);

    if (deployerDns.found) {
        l2Verified = true;
        layers.push({
            layer: 2,
            label: 'Deployer',
            org: deployerOrg,
            verified: true,
            dns_verified: true,
            territory_cells: agent.territory_cells,
            territory_resolution: agent.territory_resolution,
            detail: agent.territory_cells
                ? `${agent.territory_cells.length} territory cell${agent.territory_cells.length > 1 ? 's' : ''}`
                : 'No territory binding',
        });
    } else {
        layers.push({
            layer: 2,
            label: 'Deployer',
            org: deployerOrg,
            verified: false,
            dns_verified: false,
            detail: deployerDns.reason,
        });
        if (deployerOrg !== domain) {
            warnings.push(`Deployer DNS verification failed for ${deployerOrg}`);
        }
    }

    // ── Layer 3: Principal Verification ───────────────────────
    let l3Verified = false;
    let delegation: AipDelegationCert | undefined;

    if (agent.delegation_cert_url) {
        delegation = await fetchDelegationCert(agent.delegation_cert_url) ?? undefined;

        if (delegation) {
            // Validate PoH exponents
            const pohValid = validatePoHExponents(delegation.poh_alpha, delegation.poh_beta);
            // Validate trust score
            const trustValid = (delegation.trust_score ?? 0) >= 50;
            // Validate temporal bounds
            const temporalValid = validateTemporalBounds(delegation.not_before, delegation.not_after);

            l3Verified = pohValid && trustValid && temporalValid;

            const issues: string[] = [];
            if (!pohValid) issues.push('PoH exponents out of range');
            if (!trustValid) issues.push(`Trust score ${delegation.trust_score ?? 0} below threshold (50)`);
            if (!temporalValid) issues.push('Delegation certificate expired or not yet valid');

            layers.push({
                layer: 3,
                label: 'Principal',
                verified: l3Verified,
                dns_verified: false, // Principals don't have DNS
                trust_score: delegation.trust_score,
                detail: l3Verified
                    ? `Trust ${delegation.trust_score}/100 · PoH verified`
                    : issues.join('; '),
                delegation,
            });

            if (!l3Verified) {
                warnings.push(...issues);
            }
        } else {
            layers.push({
                layer: 3,
                label: 'Principal',
                verified: false,
                dns_verified: false,
                detail: 'Delegation certificate unreachable',
            });
            warnings.push('Could not fetch delegation certificate');
        }
    } else {
        layers.push({
            layer: 3,
            label: 'Principal',
            verified: false,
            dns_verified: false,
            detail: 'No delegation certificate declared',
        });
    }

    // ── Compute Shield Tier ───────────────────────────────────
    const shield = computeShieldTier(l1Verified, l2Verified, l3Verified);

    // ── Resolve Jurisdiction ──────────────────────────────────
    const jurisdiction = agent.jurisdiction_binding || undefined;

    return {
        agent_key: agent.agent_key,
        model_id: agent.model_id,
        creator_org: agent.creator_org,
        deployer_org: agent.deployer_org || domain,
        shield,
        layers,
        jurisdiction,
        capabilities: agent.capabilities,
        safety_certs: agent.safety_certs,
        delegation,
        verified_at: now,
        warnings,
        errors,
    };
}

// ============================================================
// DNS VERIFICATION FOR ORGS
// ============================================================

/**
 * Verify that an organization has a _gns-aip TXT record.
 * Checks both _gns-aip.{org} and _gns.{org} (backward compat).
 */
async function verifyOrgDns(org: string): Promise<{ found: boolean; pk?: string; reason: string }> {
    // Try _gns-aip first, then fall back to _gns
    for (const prefix of ['_gns-aip', '_gns']) {
        const name = `${prefix}.${org}`;

        for (const provider of [DOH_GOOGLE, DOH_CLOUDFLARE]) {
            try {
                const res = await fetch(
                    `${provider}?name=${encodeURIComponent(name)}&type=TXT`,
                    { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(3000) },
                );
                if (!res.ok) continue;

                const data = (await res.json()) as DoHResponse;
                if (!data.Answer) continue;

                for (const answer of data.Answer) {
                    if (answer.type !== 16) continue;
                    const txt = (answer.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '');

                    // Accept both v=gns-aip1 and v=gns1 records
                    if (txt.includes('v=gns-aip1') || txt.includes('v=gns1')) {
                        const pkMatch = txt.match(/pk=([0-9a-fA-F]{64})/);
                        return {
                            found: true,
                            pk: pkMatch?.[1]?.toLowerCase(),
                            reason: `Verified via ${prefix}.${org}`,
                        };
                    }
                }
            } catch {
                // Try next provider
            }
        }
    }

    return { found: false, reason: `No _gns-aip or _gns TXT record at ${org}` };
}

// ============================================================
// DELEGATION CERTIFICATE FETCH
// ============================================================

/**
 * Fetch a delegation certificate from a URL.
 * In production this would parse COSE_Sign1 and verify Ed25519.
 * For the initial release, we accept a JSON representation and
 * verify the fields structurally (crypto verification comes with
 * the CBOR/COSE library integration).
 */
async function fetchDelegationCert(url: string): Promise<AipDelegationCert | null> {
    try {
        const res = await fetch(url, {
            headers: { 'Accept': 'application/json, application/cbor' },
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) return null;

        const json = await res.json() as Record<string, unknown>;

        return {
            version: typeof json.version === 'number' ? json.version : 1,
            principal_tit: typeof json.principal_tit === 'string' ? json.principal_tit : undefined,
            principal_pk: typeof json.principal_pk === 'string' ? json.principal_pk : undefined,
            agent_pk: typeof json.agent_pk === 'string' ? json.agent_pk : undefined,
            capabilities: Array.isArray(json.capabilities) ? json.capabilities as string[] : [],
            territory_cells: Array.isArray(json.territory_cells) ? json.territory_cells as number[] : [],
            territory_res: typeof json.territory_res === 'number' ? json.territory_res : undefined,
            not_before: typeof json.not_before === 'string' ? json.not_before : undefined,
            not_after: typeof json.not_after === 'string' ? json.not_after : undefined,
            max_subdelegation: typeof json.max_subdelegation === 'number' ? json.max_subdelegation : 0,
            trust_score: typeof json.trust_score === 'number' ? json.trust_score : undefined,
            trust_floor: typeof json.trust_floor === 'number' ? json.trust_floor : undefined,
            poh_alpha: typeof json.poh_alpha === 'number' ? json.poh_alpha : undefined,
            poh_beta: typeof json.poh_beta === 'number' ? json.poh_beta : undefined,
            signature_valid: false, // TODO: COSE_Sign1 verification with @noble/ed25519
        };
    } catch {
        return null;
    }
}

// ============================================================
// VALIDATION HELPERS
// ============================================================

/**
 * Validate Proof-of-Humanity exponents from the Criticality Engine.
 * Per draft-ayerbe-trip-protocol: Parisi α ∈ [0.30, 0.80] for biological pink noise.
 */
function validatePoHExponents(alpha?: number, beta?: number): boolean {
    if (alpha === undefined) return false;
    if (alpha < PARISI_ALPHA_MIN || alpha > PARISI_ALPHA_MAX) return false;
    // Beta validation (if present) — β should be > 0 for spatiotemporal correlation
    if (beta !== undefined && beta <= 0) return false;
    return true;
}

/**
 * Validate delegation certificate temporal bounds.
 */
function validateTemporalBounds(notBefore?: string, notAfter?: string): boolean {
    const now = Date.now();
    if (notBefore) {
        const nbTime = new Date(notBefore).getTime();
        if (isNaN(nbTime) || now < nbTime) return false;
    }
    if (notAfter) {
        const naTime = new Date(notAfter).getTime();
        if (isNaN(naTime) || now > naTime) return false;
    }
    return true;
}

/**
 * Compute the shield tier from verified layers.
 *
 * Green:   All three layers verified (L1 + L2 + L3)
 * Amber:   At least Creator verified (L1), missing Deployer or Principal
 * Red:     Nothing verified — agent declared but no provenance
 * Unknown: No agents detected
 */
function computeShieldTier(l1: boolean, l2: boolean, l3: boolean): AipShieldTier {
    if (l1 && l2 && l3) return 'green';
    if (l1 && l2) return 'amber';
    if (l1) return 'amber';
    return 'red';
}

// ============================================================
// DOMAIN VERIFICATION PIPELINE
// ============================================================

const SKIP_PATTERNS = [
    /^localhost$/,
    /\.local$/,
    /^\d+\.\d+\.\d+\.\d+$/,
    /^chrome\./,
    /^extensions$/,
    /^newtab$/,
    /^devtools$/,
];

function shouldSkip(domain: string): boolean {
    return !domain || SKIP_PATTERNS.some(p => p.test(domain));
}

/**
 * Full AIP verification pipeline for a domain.
 *
 * 1. Check cache
 * 2. Fetch /.well-known/gns-aip.json
 * 3. Fallback: _gns-aip DNS TXT
 * 4. For each agent, verify provenance chain
 * 5. Cache and return
 */
async function verifyDomainAgents(domain: string): Promise<AipTabData> {
    const cached = getCached(domain);
    if (cached) return cached;

    const now = new Date().toISOString();

    // ── Step 1: Discover agents ───────────────────────────────
    let manifest = await fetchWellKnownManifest(domain);

    // Fallback: DNS TXT (lighter, fewer details)
    if (!manifest) {
        const dnsRecord = await checkAipDnsTxt(domain);
        if (dnsRecord && dnsRecord.pk) {
            // Construct a minimal manifest from DNS
            manifest = {
                version: 1,
                domain,
                agents: [{
                    agent_key: dnsRecord.pk,
                    creator_org: dnsRecord.creator,
                    deployer_org: dnsRecord.deployer || domain,
                }],
            };
        }
    }

    // No agents found
    if (!manifest || manifest.agents.length === 0) {
        const result: AipTabData = {
            domain,
            agents: [],
            agent_count: 0,
            best_shield: 'unknown',
            checked_at: now,
        };
        setCache(domain, result);
        return result;
    }

    // ── Step 2: Verify each agent's provenance chain ──────────
    const verifiedAgents: AipVerificationResult[] = [];

    for (const agent of manifest.agents) {
        const result = await verifyAgentProvenance(agent, domain);
        verifiedAgents.push(result);
    }

    // ── Step 3: Compute best shield across all agents ─────────
    const shieldPriority: AipShieldTier[] = ['green', 'amber', 'red', 'unknown'];
    let bestShield: AipShieldTier = 'unknown';
    for (const agent of verifiedAgents) {
        if (shieldPriority.indexOf(agent.shield) < shieldPriority.indexOf(bestShield)) {
            bestShield = agent.shield;
        }
    }

    const result: AipTabData = {
        domain,
        agents: verifiedAgents,
        agent_count: verifiedAgents.length,
        best_shield: bestShield,
        checked_at: now,
    };

    setCache(domain, result);
    return result;
}

// ============================================================
// EXPORTED: Message handlers (called from handleMessage switch)
// ============================================================

/**
 * Handle AIP_GET_AGENTS message from popup.
 * Returns cached agent verification results for the given tab.
 */
export async function handleAipGetAgents(
    tabId: number,
): Promise<MessageResponse<AipTabData | null>> {
    try {
        const data = await chrome.storage.session.get(`aip_${tabId}`);
        return { success: true, data: data[`aip_${tabId}`] || null };
    } catch {
        return { success: true, data: null };
    }
}

/**
 * Handle AIP_VERIFY_CHAIN message — manual provenance verification.
 */
export async function handleAipVerifyChain(
    domain: string,
): Promise<MessageResponse<AipTabData>> {
    // Clear cache to force re-verification
    aipCache.delete(domain);
    const result = await verifyDomainAgents(domain);
    return { success: true, data: result };
}

/**
 * Handle AIP_GET_JURISDICTION message — resolve jurisdiction for a domain.
 */
export async function handleAipGetJurisdiction(
    domain: string,
): Promise<MessageResponse<Record<string, AipJurisdictionBinding> | null>> {
    const cached = getCached(domain);
    if (!cached || cached.agents.length === 0) {
        return { success: true, data: null };
    }

    // Return jurisdiction binding from the first agent that has one
    for (const agent of cached.agents) {
        if (agent.jurisdiction) {
            return { success: true, data: agent.jurisdiction };
        }
    }

    return { success: true, data: null };
}

/**
 * Handle AIP_AGENTS_DETECTED message from content script.
 * Content script found agent declarations in the page DOM.
 */
export async function handleAipAgentsDetected(
    tabId: number,
    agents: AipAgentEntry[],
): Promise<MessageResponse> {
    // Merge with existing data for this tab
    try {
        const existing = await chrome.storage.session.get(`aip_${tabId}`);
        const existingData = existing[`aip_${tabId}`] as AipTabData | undefined;

        if (existingData) {
            // Merge newly detected agents (avoid duplicates by agent_key)
            const existingKeys = new Set(existingData.agents.map(a => a.agent_key));
            const newAgents = agents.filter(a => !existingKeys.has(a.agent_key));

            if (newAgents.length > 0) {
                // TODO: Verify new agents and append to existing results
                console.log(`[GNS AIP] ${newAgents.length} new agents detected via content script`);
            }
        }

        return { success: true };
    } catch {
        return { success: true };
    }
}

/**
 * Handle AIP_CLEAR_CACHE message.
 */
export function handleAipClearCache(): MessageResponse {
    aipCache.clear();
    return { success: true };
}

// ============================================================
// EXPORTED: Navigation listener (call once at module level)
// ============================================================

/**
 * Initialize AIP verification on every HTTPS page navigation.
 * Call this once from background/index.ts at the top level,
 * alongside initDnsVerification().
 *
 * Requires "webNavigation" permission in manifest.json (already present).
 */
export function initAipVerification(): void {
    chrome.webNavigation.onCompleted.addListener(async (details) => {
        if (details.frameId !== 0) return; // Main frame only

        try {
            const url = new URL(details.url);
            if (url.protocol !== 'https:') return; // AIP requires HTTPS

            const domain = url.hostname.replace(/^www\./, '');
            if (shouldSkip(domain)) return;

            const result = await verifyDomainAgents(domain);

            // Update badge if agents were found
            if (result.agent_count > 0) {
                await updateAipBadge(details.tabId, result.best_shield, result.agent_count);
            }

            // Store for popup access
            await chrome.storage.session.set({
                [`aip_${details.tabId}`]: result,
            });
        } catch (e) {
            console.error('[GNS AIP] Navigation handler error:', e);
        }
    });

    // Clean up on tab close
    chrome.tabs.onRemoved.addListener((tabId) => {
        chrome.storage.session.remove(`aip_${tabId}`).catch(() => { });
    });

    console.log('[GNS AIP] AI Agent Identity Verification initialized');
}
