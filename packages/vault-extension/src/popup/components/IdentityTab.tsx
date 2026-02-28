import React, { useState, useEffect } from 'react';
import { sendMessage, copyToClipboard, truncateKey, formatDate } from '../helpers';
import { DnsSiteCard } from './DnsSiteCard';
import { AgentCard } from './AgentCard';

interface IdentityData {
  publicKey: string;
  handle?: string;
  createdAt: string;
  stellarAddress?: string;
}

interface TrustData {
  score: number;
  breadcrumbs: number;
  identityAgeDays: number;
  tier: string;
}

export function IdentityTab() {
  const [identity, setIdentity] = useState<IdentityData | null>(null);
  const [trust, setTrust] = useState<TrustData | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    (async () => {
      const [idRes, trustRes] = await Promise.all([
        sendMessage<IdentityData>({ type: 'IDENTITY_GET' }),
        sendMessage<TrustData>({ type: 'IDENTITY_GET_TRUST_SCORE' }),
      ]);
      if (idRes.success && idRes.data) setIdentity(idRes.data);
      if (trustRes.success && trustRes.data) setTrust(trustRes.data);
    })();
  }, []);

  const handleCopyKey = async () => {
    if (!identity) return;
    await copyToClipboard(identity.publicKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const tierLabel = (tier: string) => {
    const labels: Record<string, string> = {
      unverified: '⬜ Unverified',
      bronze: '🟫 Bronze',
      silver: '⬜ Silver',
      gold: '🟨 Gold',
      platinum: '⬜ Platinum',
      diamond: '💎 Diamond',
    };
    return labels[tier] || tier;
  };

  if (!identity) {
    return (
      <div className="empty">
        <div className="empty-icon">🌐</div>
        <div className="empty-text">Loading identity...</div>
      </div>
    );
  }

  return (
    <div>
      {/* AI Agent Identity */}
      <AgentCard />

      {/* Current Site Identity */}
      <DnsSiteCard />

      {/* Identity Card */}
      <div className="identity-card">
        <div className="identity-label">YOUR GNS IDENTITY</div>
        <div
          className="identity-key"
          onClick={handleCopyKey}
          style={{ cursor: 'pointer' }}
          title="Click to copy full public key"
        >
          {copied ? '✓ Copied!' : truncateKey(identity.publicKey, 16)}
        </div>

        {identity.handle && (
          <div style={{ fontSize: '16px', fontWeight: '600', marginBottom: '8px' }}>
            @{identity.handle}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '11px', opacity: 0.7 }}>
            Created {formatDate(identity.createdAt)}
          </div>
          {trust && (
            <span className={`badge badge-${trust.tier}`}>
              {tierLabel(trust.tier)}
            </span>
          )}
        </div>

        {/* Trust Score Bar */}
        {trust && (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px', fontSize: '12px', opacity: 0.8 }}>
              <span>Trust Score</span>
              <span>{trust.score}/100</span>
            </div>
            <div className="trust-bar">
              <div className="trust-fill" style={{ width: `${trust.score}%` }} />
            </div>
          </>
        )}
      </div>

      {/* Stats */}
      {trust && (
        <div style={{ marginBottom: '16px' }}>
          <div className="stat-row">
            <span className="stat-label">Breadcrumbs</span>
            <span className="stat-value">
              {trust.breadcrumbs.toLocaleString()}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Identity Age</span>
            <span className="stat-value">
              {trust.identityAgeDays} day{trust.identityAgeDays !== 1 ? 's' : ''}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Badge Tier</span>
            <span className="stat-value">{tierLabel(trust.tier)}</span>
          </div>
        </div>
      )}

      {/* TrIP Explanation */}
      <div
        style={{
          background: 'var(--light-green)',
          borderRadius: 'var(--radius)',
          padding: '14px',
          fontSize: '12px',
          color: '#1E8449',
          lineHeight: 1.6,
        }}
      >
        <div style={{ fontWeight: '600', marginBottom: '6px', fontSize: '13px' }}>
          🏅 How to earn your Human Identity Badge
        </div>
        <div>
          Install the Globe Crumbs mobile app and enable TrIP (Trajectory Recognition
          Identity Protocol) breadcrumb collection. Your daily movement builds an
          unforgeable behavioral signature that proves you're a real human — no
          biometrics, no hardware, no third party.
        </div>
      </div>

      {/* What is this key */}
      <div
        style={{
          marginTop: '12px',
          padding: '14px',
          background: 'var(--light)',
          borderRadius: 'var(--radius)',
          fontSize: '12px',
          color: 'var(--medium)',
          lineHeight: 1.6,
        }}
      >
        <div style={{ fontWeight: '600', marginBottom: '4px', color: 'var(--primary)' }}>
          What is my GNS Identity?
        </div>
        <div>
          Your Ed25519 public key is your identity on the GNS Protocol. It secures your
          vault, proves your identity to websites, and doubles as a Stellar wallet address.
          One key for everything. You own it — no email, no phone number, no third party.
        </div>
      </div>
    </div>
  );
}
