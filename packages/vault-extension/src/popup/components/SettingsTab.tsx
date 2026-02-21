/**
 * GNS Vault — Settings Tab
 *
 * Import/Export, sync settings, auto-lock timer, vault health stats.
 */

import React, { useState, useEffect } from 'react';
import { sendMessage } from '../helpers';
import { ImportWizard } from './ImportWizard';

interface VaultStats {
  totalEntries: number;
  weakPasswords: number;
  reusedPasswords: number;
  averageStrength: number;
  byType: Record<string, number>;
}

interface Props {
  onRefreshVault: () => void;
}

export function SettingsTab({ onRefreshVault }: Props) {
  const [showImport, setShowImport] = useState(false);
  const [stats, setStats] = useState<VaultStats | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportDone, setExportDone] = useState(false);

  useEffect(() => {
    (async () => {
      const res = await sendMessage<VaultStats>({ type: 'VAULT_GET_STATS' });
      if (res.success && res.data) setStats(res.data);
    })();
  }, []);

  const handleExport = async (format: 'json' | 'csv', includePasswords: boolean) => {
    setExporting(true);
    const res = await sendMessage<{ exported: string }>({
      type: 'VAULT_EXPORT',
      options: { format, includePasswords },
    });

    if (res.success && res.data) {
      // Download the file
      const blob = new Blob([res.data.exported], {
        type: format === 'json' ? 'application/json' : 'text/csv',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `gns-vault-export-${Date.now()}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      setExportDone(true);
      setTimeout(() => setExportDone(false), 3000);
    }
    setExporting(false);
  };

  const handleImportDone = () => {
    setShowImport(false);
    onRefreshVault();
    // Refresh stats
    sendMessage<VaultStats>({ type: 'VAULT_GET_STATS' }).then((res) => {
      if (res.success && res.data) setStats(res.data);
    });
  };

  if (showImport) {
    return <ImportWizard onDone={handleImportDone} />;
  }

  return (
    <div>
      {/* Vault Health */}
      {stats && (
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--medium)', marginBottom: '10px', letterSpacing: '0.5px' }}>
            VAULT HEALTH
          </div>

          <div className="stat-row">
            <span className="stat-label">Total credentials</span>
            <span className="stat-value">{stats.totalEntries}</span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Average strength</span>
            <span className={`stat-value ${stats.averageStrength >= 60 ? 'stat-ok' : 'stat-warn'}`}>
              {stats.averageStrength}/100
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Weak passwords</span>
            <span className={`stat-value ${stats.weakPasswords === 0 ? 'stat-ok' : 'stat-warn'}`}>
              {stats.weakPasswords === 0 ? '✓ None' : stats.weakPasswords}
            </span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Reused passwords</span>
            <span className={`stat-value ${stats.reusedPasswords === 0 ? 'stat-ok' : 'stat-warn'}`}>
              {stats.reusedPasswords === 0 ? '✓ None' : stats.reusedPasswords}
            </span>
          </div>
        </div>
      )}

      {/* Import */}
      <div style={{ marginBottom: '20px' }}>
        <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--medium)', marginBottom: '10px', letterSpacing: '0.5px' }}>
          IMPORT
        </div>
        <button
          className="btn btn-ghost btn-full"
          onClick={() => setShowImport(true)}
          style={{ justifyContent: 'flex-start', display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          📥 Import from another password manager
        </button>
      </div>

      {/* Export */}
      <div style={{ marginBottom: '20px' }}>
        <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--medium)', marginBottom: '10px', letterSpacing: '0.5px' }}>
          EXPORT
        </div>

        {exportDone && (
          <div style={{
            background: 'var(--light-green)',
            borderRadius: 'var(--radius)',
            padding: '8px 12px',
            fontSize: '12px',
            color: 'var(--accent)',
            marginBottom: '8px',
          }}>
            ✓ Export downloaded successfully
          </div>
        )}

        <div style={{ display: 'flex', gap: '8px', marginBottom: '6px' }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => handleExport('json', true)}
            disabled={exporting}
            style={{ flex: 1 }}
          >
            📄 Export JSON
          </button>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => handleExport('csv', true)}
            disabled={exporting}
            style={{ flex: 1 }}
          >
            📊 Export CSV
          </button>
        </div>
        <div style={{ fontSize: '11px', color: 'var(--medium)', lineHeight: 1.5 }}>
          ⚠ Exported files contain plaintext passwords. Store securely and delete after use.
        </div>
      </div>

      {/* Sync */}
      <div style={{ marginBottom: '20px' }}>
        <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--medium)', marginBottom: '10px', letterSpacing: '0.5px' }}>
          SYNC
        </div>
        <div
          style={{
            background: 'var(--light)',
            borderRadius: 'var(--radius)',
            padding: '14px',
            fontSize: '12px',
            color: 'var(--medium)',
            lineHeight: 1.6,
          }}
        >
          <div style={{ fontWeight: '600', color: 'var(--primary)', marginBottom: '4px' }}>
            🔄 P2P Sync via GNS Relay
          </div>
          Peer-to-peer synchronization between your devices using end-to-end encrypted
          envelopes through the GNS Relay. The relay is a stateless forwarder — it never
          sees your vault data.
          <div style={{ marginTop: '8px', fontStyle: 'italic', color: '#AEB6BF' }}>
            Coming in v0.2.0
          </div>
        </div>
      </div>

      {/* About */}
      <div style={{ marginBottom: '8px' }}>
        <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--medium)', marginBottom: '10px', letterSpacing: '0.5px' }}>
          ABOUT
        </div>
        <div className="stat-row">
          <span className="stat-label">Version</span>
          <span className="stat-value" style={{ fontSize: '12px' }}>0.1.0</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Encryption</span>
          <span className="stat-value" style={{ fontSize: '12px' }}>XChaCha20-Poly1305</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">Identity</span>
          <span className="stat-value" style={{ fontSize: '12px' }}>Ed25519 (RFC 8032)</span>
        </div>
        <div className="stat-row">
          <span className="stat-label">KDF</span>
          <span className="stat-value" style={{ fontSize: '12px' }}>Argon2id (RFC 9106)</span>
        </div>
      </div>
    </div>
  );
}
