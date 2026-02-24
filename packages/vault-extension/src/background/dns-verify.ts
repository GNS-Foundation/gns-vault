/**
 * GNS Vault Extension — DNS-TXT Identity Verification
 *
 * Verifies _gns TXT records for sites the user visits.
 * Updates the extension badge with trust status (gray/blue/green/red).
 *
 * Integration pattern:
 *   - Navigation listener: Call initDnsVerification() at module level
 *   - Message routing:     Add DNS cases to handleMessage() switch
 *
 * This module does NOT register its own chrome.runtime.onMessage listener.
 * All message handling goes through the existing centralized router
 * in background/index.ts.
 *
 * @module vault-extension/background/dns-verify
 */

import type { MessageResponse } from '../utils/messages';

// ============================================================
// CONFIGURATION
// ============================================================

/** GNS Verify API — primary verification source */
const VERIFY_API_BASE = 'https://vault.gcrumbs.com';

/** DNS-over-HTTPS fallback endpoints */
const DOH_GOOGLE = 'https://dns.google/resolve';
const DOH_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

/** Cache TTL for verification results */
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ============================================================
// TYPES
// ============================================================

export interface DnsBadge {
  color: 'gray' | 'blue' | 'green' | 'red';
  label: string;
  detail?: string;
  level?: string;
  handle?: string;
  trust?: number;
}

export interface DnsVerificationResult {
  domain: string;
  verified: boolean;
  level: string;
  level_name: string;
  pk?: string;
  handle?: string;
  enc?: string;
  trust_self_reported?: number;
  relay_trust?: number;
  relay_breadcrumbs?: number;
  badge: DnsBadge;
  checked_at: string;
  warnings: string[];
  errors: string[];
}

interface CacheEntry {
  result: DnsVerificationResult;
  expires: number;
}

// ============================================================
// BADGE CONFIG
// ============================================================

const BADGE_CONFIG: Record<string, { text: string; color: string }> = {
  gray: { text: '', color: '#6B7280' },
  blue: { text: 'GNS', color: '#0EA5E9' },
  green: { text: '✓', color: '#2E8B57' },
  red: { text: '!', color: '#EF4444' },
};

// ============================================================
// CACHE
// ============================================================

const dnsCache = new Map<string, CacheEntry>();

function getCached(domain: string): DnsVerificationResult | null {
  const entry = dnsCache.get(domain);
  if (entry && Date.now() < entry.expires) return entry.result;
  dnsCache.delete(domain);
  return null;
}

function setCache(domain: string, result: DnsVerificationResult): void {
  dnsCache.set(domain, { result, expires: Date.now() + CACHE_TTL_MS });
  if (dnsCache.size > 500) {
    const oldest = dnsCache.keys().next().value;
    if (oldest) dnsCache.delete(oldest);
  }
}

// ============================================================
// BADGE RENDERING
// ============================================================

async function updateBadge(tabId: number, badge: DnsBadge): Promise<void> {
  const config = (BADGE_CONFIG[badge.color] ?? BADGE_CONFIG.gray)!;
  try {
    await chrome.action.setBadgeText({ tabId, text: config.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: config.color });
    await chrome.action.setTitle({
      tabId,
      title: `GNS Vault — ${badge.label}${badge.detail ? '\n' + badge.detail : ''}`,
    });
  } catch {
    // Tab may have closed
  }
}

// ============================================================
// VERIFICATION METHODS
// ============================================================

/** Primary: Call GNS Verify API /v1/dns/:domain/badge */
async function verifyViaApi(domain: string): Promise<DnsVerificationResult | null> {
  try {
    const res = await fetch(`${VERIFY_API_BASE}/v1/dns/${domain}/badge`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;

    const json = await res.json() as { success: boolean; data?: DnsBadge };
    if (!json.success || !json.data) return null;

    return {
      domain,
      verified: json.data.color === 'green' || json.data.color === 'blue',
      level: json.data.level || 'L0',
      level_name: json.data.label,
      handle: json.data.handle,
      trust_self_reported: json.data.trust,
      badge: json.data,
      checked_at: new Date().toISOString(),
      warnings: [],
      errors: [],
    };
  } catch {
    return null;
  }
}

/** Client-side _gns TXT parser (lightweight, no crypto verification) */
function parseGnsTxtClient(txt: string): { pk: string; handle?: string; trust?: number } | null {
  if (!txt.includes('v=gns1')) return null;

  const pairs: Record<string, string> = {};
  txt.split(';').forEach(part => {
    const eq = part.indexOf('=');
    if (eq > 0) pairs[part.substring(0, eq).trim().toLowerCase()] = part.substring(eq + 1).trim();
  });

  if (pairs.v !== 'gns1' || !pairs.pk || !/^[0-9a-fA-F]{64}$/.test(pairs.pk)) return null;

  return {
    pk: pairs.pk.toLowerCase(),
    handle: pairs.handle ? (pairs.handle.startsWith('@') ? pairs.handle : `@${pairs.handle}`) : undefined,
    trust: pairs.trust ? parseInt(pairs.trust, 10) : undefined,
  };
}

/** Fallback: Direct DNS-over-HTTPS lookup */
async function verifyViaDoH(domain: string): Promise<DnsVerificationResult | null> {
  const locations = [`_gns.${domain}`, `gns-verify.${domain}`, domain];

  for (const loc of locations) {
    for (const provider of [DOH_GOOGLE, DOH_CLOUDFLARE]) {
      try {
        const headers: Record<string, string> = { 'Accept': 'application/dns-json' };
        const res = await fetch(
          `${provider}?name=${encodeURIComponent(loc)}&type=TXT`,
          { headers, signal: AbortSignal.timeout(3000) },
        );
        if (!res.ok) continue;

        const data = await res.json() as { Answer?: Array<{ type: number; data?: string }> };
        if (!data.Answer) continue;

        for (const answer of data.Answer) {
          if (answer.type !== 16) continue;
          const txt = (answer.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '');
          const parsed = parseGnsTxtClient(txt);
          if (parsed) {
            return {
              domain,
              verified: true,
              level: 'L0',
              level_name: 'DNS Present',
              pk: parsed.pk,
              handle: parsed.handle,
              trust_self_reported: parsed.trust,
              badge: {
                color: 'blue',
                label: 'GNS Claimed',
                detail: `${parsed.handle || parsed.pk.slice(0, 12) + '…'} · Via DoH fallback`,
              },
              checked_at: new Date().toISOString(),
              warnings: ['Verified via DoH — relay cross-check not performed'],
              errors: [],
            };
          }
        }
      } catch {
        // Try next provider/location
      }
    }
  }

  return null;
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

async function verifyDomain(domain: string): Promise<DnsVerificationResult> {
  const cached = getCached(domain);
  if (cached) return cached;

  let result = await verifyViaApi(domain);
  if (!result) result = await verifyViaDoH(domain);

  if (!result) {
    result = {
      domain,
      verified: false,
      level: 'L0',
      level_name: 'No Record',
      badge: { color: 'gray', label: 'No GNS identity' },
      checked_at: new Date().toISOString(),
      warnings: [],
      errors: [],
    };
  }

  setCache(domain, result);
  return result;
}

// ============================================================
// EXPORTED: Message handlers (called from handleMessage switch)
// ============================================================

/**
 * Handle DNS_GET_VERIFICATION message from popup.
 * Returns the cached result for the given tab.
 */
export async function handleDnsGetVerification(
  tabId: number
): Promise<MessageResponse<{ domain: string; result: DnsVerificationResult; url: string } | null>> {
  try {
    const data = await chrome.storage.session.get(`dns_${tabId}`);
    return { success: true, data: data[`dns_${tabId}`] || null };
  } catch {
    return { success: true, data: null };
  }
}

/**
 * Handle DNS_VERIFY_DOMAIN message — manual verification trigger.
 */
export async function handleDnsVerifyDomain(
  domain: string
): Promise<MessageResponse<DnsVerificationResult>> {
  const result = await verifyDomain(domain);
  return { success: true, data: result };
}

/**
 * Handle DNS_CLEAR_CACHE message.
 */
export function handleDnsClearCache(): MessageResponse {
  dnsCache.clear();
  return { success: true };
}

// ============================================================
// EXPORTED: Navigation listener (call once at module level)
// ============================================================

/**
 * Initialize DNS verification on every page navigation.
 * Call this once from background/index.ts at the top level.
 *
 * Requires "webNavigation" permission in manifest.json.
 */
export function initDnsVerification(): void {
  chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return; // Main frame only

    try {
      const url = new URL(details.url);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') return;

      const domain = url.hostname.replace(/^www\./, '');
      if (shouldSkip(domain)) return;

      const result = await verifyDomain(domain);
      await updateBadge(details.tabId, result.badge);

      // Store for popup access
      await chrome.storage.session.set({
        [`dns_${details.tabId}`]: { domain, result, url: details.url },
      });
    } catch (e) {
      console.error('[GNS DNS] Navigation handler error:', e);
    }
  });

  // Clean up on tab close
  chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.session.remove(`dns_${tabId}`).catch(() => { });
  });

  console.log('[GNS DNS] DNS-TXT Identity Verification initialized');
}
