import React, { useState } from 'react';
import { truncateKey } from '../helpers';

interface Props {
  onUnlock: (passphrase?: string) => Promise<void>;
  error: string;
  publicKey?: string;
}

export function LockScreen({ onUnlock, error, publicKey }: Props) {
  const [passphrase, setPassphrase] = useState('');
  const [unlocking, setUnlocking] = useState(false);

  const handleUnlock = async () => {
    setUnlocking(true);
    await onUnlock(passphrase || undefined);
    setUnlocking(false);
  };

  return (
    <div className="lock-screen">
      <div className="lock-icon">🔒</div>
      <div className="lock-title">Vault Locked</div>
      {publicKey && (
        <div style={{ fontSize: '11px', color: '#AEB6BF', fontFamily: 'monospace', marginBottom: '8px' }}>
          {truncateKey(publicKey, 12)}
        </div>
      )}
      <div className="lock-sub">Enter your passphrase to unlock</div>

      <div style={{ width: '100%', maxWidth: '280px' }}>
        <input
          className="input"
          type="password"
          placeholder="Master passphrase (or leave empty)"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
          autoFocus
          style={{ marginBottom: '12px' }}
        />

        {error && (
          <div style={{ color: '#C0392B', fontSize: '12px', marginBottom: '8px', textAlign: 'center' }}>
            {error}
          </div>
        )}

        <button
          className="btn btn-primary btn-full"
          onClick={handleUnlock}
          disabled={unlocking}
        >
          {unlocking ? 'Unlocking...' : 'Unlock'}
        </button>
      </div>
    </div>
  );
}
