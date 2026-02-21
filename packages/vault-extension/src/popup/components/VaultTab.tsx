import React, { useState, useEffect, useCallback } from 'react';
import { sendMessage, copyToClipboard } from '../helpers';

interface Entry {
  id: string;
  type: string;
  name: string;
  urls: string[];
  username: string;
  password: string;
  favorite: boolean;
  passwordStrength?: number;
}

export function VaultTab() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [search, setSearch] = useState('');
  const [copied, setCopied] = useState<string | null>(null);

  const loadEntries = useCallback(async () => {
    const res = search
      ? await sendMessage<Entry[]>({ type: 'VAULT_SEARCH', query: search })
      : await sendMessage<Entry[]>({ type: 'VAULT_GET_ENTRIES' });
    if (res.success && res.data) {
      setEntries(res.data);
    }
  }, [search]);

  useEffect(() => {
    loadEntries();
  }, [loadEntries]);

  const handleCopy = async (text: string, label: string) => {
    await copyToClipboard(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 1500);
  };

  const getInitial = (name: string) => {
    return name.charAt(0).toUpperCase() || '?';
  };

  const getStrengthColor = (strength?: number) => {
    if (!strength) return 'var(--border)';
    if (strength < 30) return 'var(--danger)';
    if (strength < 50) return 'var(--warning)';
    if (strength < 70) return '#27AE60';
    return 'var(--accent)';
  };

  return (
    <div>
      {/* Search */}
      <input
        className="search-box"
        type="text"
        placeholder="Search credentials..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {/* Copied toast */}
      {copied && (
        <div
          style={{
            position: 'fixed',
            bottom: '16px',
            left: '50%',
            transform: 'translateX(-50%)',
            background: 'var(--primary)',
            color: 'white',
            padding: '8px 16px',
            borderRadius: '20px',
            fontSize: '12px',
            fontWeight: '500',
            zIndex: 100,
            boxShadow: '0 2px 8px rgba(0,0,0,0.2)',
          }}
        >
          ✓ {copied} copied
        </div>
      )}

      {/* Entry List */}
      {entries.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">{search ? '🔍' : '🔑'}</div>
          <div className="empty-text">
            {search ? 'No matching credentials' : 'No credentials yet'}
          </div>
          {!search && (
            <div style={{ fontSize: '12px', color: 'var(--medium)', marginTop: '8px' }}>
              Browse the web — GNS Vault will offer to save your logins automatically.
            </div>
          )}
        </div>
      ) : (
        <ul className="entry-list">
          {entries.map((entry) => (
            <li key={entry.id} className="entry-item">
              {/* Icon */}
              <div
                className="entry-icon"
                style={{
                  background: entry.favorite
                    ? 'linear-gradient(135deg, #FFD700, #FFA500)'
                    : undefined,
                  color: entry.favorite ? '#333' : undefined,
                }}
              >
                {getInitial(entry.name)}
              </div>

              {/* Info */}
              <div className="entry-info">
                <div className="entry-name">{entry.name}</div>
                <div className="entry-user">{entry.username}</div>
                {/* Strength indicator */}
                <div
                  style={{
                    height: '2px',
                    background: 'var(--border)',
                    borderRadius: '1px',
                    marginTop: '4px',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      width: `${entry.passwordStrength || 0}%`,
                      height: '100%',
                      background: getStrengthColor(entry.passwordStrength),
                      borderRadius: '1px',
                    }}
                  />
                </div>
              </div>

              {/* Actions */}
              <div className="entry-actions">
                <button
                  className="btn-icon"
                  title="Copy username"
                  onClick={() => handleCopy(entry.username, 'Username')}
                >
                  👤
                </button>
                <button
                  className="btn-icon"
                  title="Copy password"
                  onClick={() => handleCopy(entry.password, 'Password')}
                >
                  🔑
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* Stats footer */}
      {entries.length > 0 && (
        <div
          style={{
            textAlign: 'center',
            fontSize: '11px',
            color: 'var(--medium)',
            padding: '12px 0 4px',
            borderTop: '1px solid var(--border)',
            marginTop: '8px',
          }}
        >
          {entries.length} credential{entries.length !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  );
}
