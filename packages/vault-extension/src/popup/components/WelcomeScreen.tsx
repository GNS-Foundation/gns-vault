import React, { useState } from 'react';

interface Props {
  onCreate: (passphrase?: string) => Promise<void>;
  error: string;
}

export function WelcomeScreen({ onCreate, error }: Props) {
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [usePassphrase, setUsePassphrase] = useState(false);
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    if (usePassphrase && passphrase !== confirm) return;
    setCreating(true);
    await onCreate(usePassphrase ? passphrase : undefined);
    setCreating(false);
  };

  return (
    <div className="lock-screen" style={{ height: 'auto', minHeight: '500px', padding: '32px 28px' }}>
      <div style={{ fontSize: '40px', marginBottom: '8px' }}>🌐</div>
      <div className="lock-title">GNS Vault</div>
      <div className="lock-sub" style={{ maxWidth: '280px', marginBottom: '20px' }}>
        Your passwords. Your identity. Your key to a passwordless future.
      </div>

      {/* Feature bullets */}
      <div style={{ textAlign: 'left', width: '100%', marginBottom: '24px' }}>
        {[
          ['🔐', 'Zero-cloud credential vault — nothing leaves your device'],
          ['🌍', 'Ed25519 cryptographic identity — yours forever'],
          ['🏅', 'Earn a Human Identity Badge through TrIP'],
          ['⚡', 'Passwordless login on GNS-enabled websites'],
        ].map(([icon, text], i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              gap: '10px',
              alignItems: 'flex-start',
              marginBottom: '10px',
              fontSize: '13px',
              color: '#566573',
            }}
          >
            <span style={{ fontSize: '16px', flexShrink: 0 }}>{icon}</span>
            <span>{text}</span>
          </div>
        ))}
      </div>

      {/* Passphrase toggle */}
      <label
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          fontSize: '12px',
          color: '#566573',
          marginBottom: '12px',
          cursor: 'pointer',
        }}
      >
        <input
          type="checkbox"
          checked={usePassphrase}
          onChange={(e) => setUsePassphrase(e.target.checked)}
        />
        Add master passphrase (extra protection)
      </label>

      {usePassphrase && (
        <>
          <div className="input-group">
            <input
              className="input"
              type="password"
              placeholder="Master passphrase"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
            />
          </div>
          <div className="input-group">
            <input
              className="input"
              type="password"
              placeholder="Confirm passphrase"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </div>
          {passphrase && confirm && passphrase !== confirm && (
            <div style={{ color: '#C0392B', fontSize: '12px', marginBottom: '8px' }}>
              Passphrases don't match
            </div>
          )}
        </>
      )}

      {error && (
        <div style={{ color: '#C0392B', fontSize: '12px', marginBottom: '8px' }}>
          {error}
        </div>
      )}

      <button
        className="btn btn-primary btn-full"
        onClick={handleCreate}
        disabled={creating || (usePassphrase && (!passphrase || passphrase !== confirm))}
        style={{ padding: '12px', fontSize: '15px', marginTop: '4px' }}
      >
        {creating ? 'Creating your identity...' : 'Create My Vault'}
      </button>

      <div style={{ fontSize: '11px', color: '#AEB6BF', marginTop: '12px' }}>
        This generates an Ed25519 keypair — your GNS identity.
        <br />
        No email. No phone number. No third party.
      </div>
    </div>
  );
}
