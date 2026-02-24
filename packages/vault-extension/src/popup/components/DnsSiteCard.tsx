/**
 * GNS Vault Extension — DNS Identity Card (React Component)
 *
 * Shows the current site's GNS identity verification status
 * in the popup. Integrates into IdentityTab or as standalone tab.
 *
 * Location: packages/vault-extension/src/popup/components/DnsSiteCard.tsx
 *
 * @module vault-extension/popup/components/DnsSiteCard
 */

import React, { useState, useEffect, useCallback } from 'react';
import { sendMessage } from '../helpers';

// ============================================================
// TYPES (mirrors background/dns-verify.ts)
// ============================================================

interface DnsBadge {
  color: 'gray' | 'blue' | 'green' | 'red';
  label: string;
  detail?: string;
}

interface DnsVerificationResult {
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

interface TabDnsData {
  domain: string;
  result: DnsVerificationResult;
  url: string;
}

// ============================================================
// COLORS
// ============================================================

const BADGE_STYLES: Record<string, { bg: string; border: string; text: string; icon: string }> = {
  gray: { bg: '#F3F4F6', border: '#D1D5DB', text: '#6B7280', icon: '⚪' },
  blue: { bg: '#EFF6FF', border: '#93C5FD', text: '#1D4ED8', icon: '🔵' },
  green: { bg: '#ECFDF5', border: '#6EE7B7', text: '#065F46', icon: '🟢' },
  red: { bg: '#FEF2F2', border: '#FCA5A5', text: '#991B1B', icon: '🔴' },
};

// ============================================================
// COMPONENT
// ============================================================

export function DnsSiteCard() {
  const [data, setData] = useState<TabDnsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchDnsData = useCallback(async () => {
    try {
      // Get current active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) {
        setLoading(false);
        return;
      }

      const res = await sendMessage<TabDnsData | null>({
        type: 'DNS_GET_VERIFICATION',
        tabId: tab.id,
      } as any);

      if (res.success && res.data) {
        setData(res.data);
      }
    } catch {
      // Silent fail
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDnsData();
  }, [fetchDnsData]);

  const handleRefresh = async () => {
    if (!data) return;
    setRefreshing(true);

    // Clear cache
    await sendMessage({ type: 'DNS_CLEAR_CACHE' } as any);

    // Re-verify
    const res = await sendMessage<DnsVerificationResult>({
      type: 'DNS_VERIFY_DOMAIN',
      domain: data.domain,
    } as any);

    if (res.success && res.data) {
      setData({ ...data, result: res.data });
    }

    setRefreshing(false);
  };

  // --- Loading state ---
  if (loading) {
    return (
      <div style={{ padding: '14px', textAlign: 'center', color: '#9CA3AF', fontSize: '12px' }}>
        Checking site identity…
      </div>
    );
  }

  // --- No data ---
  if (!data?.result) {
    return (
      <div style={{
        background: '#F9FAFB',
        borderRadius: 'var(--radius, 8px)',
        padding: '14px',
        textAlign: 'center',
        fontSize: '12px',
        color: '#9CA3AF',
        marginBottom: '12px',
      }}>
        🔍 Navigate to a website to check its GNS identity.
      </div>
    );
  }

  const { result } = data;
  const style = (BADGE_STYLES[result.badge.color] ?? BADGE_STYLES.gray)!;
  const trust = result.relay_trust ?? result.trust_self_reported;
  const handle = result.handle || (result.pk ? `${result.pk.slice(0, 16)}…` : null);

  return (
    <div style={{
      border: `1px solid ${style.border}`,
      borderRadius: 'var(--radius, 8px)',
      background: style.bg,
      padding: '12px',
      marginBottom: '12px',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
        <span style={{ fontSize: '18px' }}>{style.icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, color: style.text, fontSize: '13px' }}>
            {result.badge.label}
          </div>
          <div style={{ fontSize: '11px', color: '#6B7280' }}>
            {result.level} — {result.level_name}
          </div>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          title="Re-verify"
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: '14px', opacity: refreshing ? 0.4 : 0.7,
            transition: 'opacity 0.15s',
          }}
        >
          {refreshing ? '⏳' : '🔄'}
        </button>
      </div>

      {/* Domain */}
      <div style={{ fontSize: '12px', fontWeight: 500, color: '#374151', marginBottom: '4px' }}>
        {result.domain}
      </div>

      {/* Identity details (only for non-gray) */}
      {result.badge.color !== 'gray' && (
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px',
          fontSize: '11px', marginTop: '8px', paddingTop: '8px',
          borderTop: `1px solid ${style.border}`,
        }}>
          {handle && (
            <div>
              <span style={{ color: '#9CA3AF' }}>Handle: </span>
              <strong>{handle}</strong>
            </div>
          )}
          {trust !== undefined && (
            <div>
              <span style={{ color: '#9CA3AF' }}>Trust: </span>
              <strong>{trust}/100</strong>
            </div>
          )}
          {result.relay_breadcrumbs != null && (
            <div>
              <span style={{ color: '#9CA3AF' }}>Breadcrumbs: </span>
              <strong>{result.relay_breadcrumbs.toLocaleString()}</strong>
            </div>
          )}
          {result.enc && (
            <div>
              <span style={{ color: '#9CA3AF' }}>Encrypted: </span>
              ✅ TrIP ready
            </div>
          )}
        </div>
      )}

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div style={{
          marginTop: '8px', padding: '6px 8px', background: '#FEF3C7',
          borderRadius: '4px', fontSize: '10px', color: '#92400E',
        }}>
          ⚠️ {result.warnings[0]}
        </div>
      )}

      {/* Timestamp */}
      <div style={{ fontSize: '10px', color: '#9CA3AF', marginTop: '8px', textAlign: 'right' }}>
        Checked: {new Date(result.checked_at).toLocaleTimeString()}
      </div>
    </div>
  );
}
