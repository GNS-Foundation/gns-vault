/**
 * GNS Vault Extension — Popup App
 *
 * State machine:
 *   LOADING → WELCOME (no vault) → CREATE → UNLOCKED
 *   LOADING → LOCKED (vault exists) → UNLOCKED
 *   UNLOCKED → LOCKED (on lock/timeout)
 *
 * Tabs (when unlocked):
 *   Vault | Identity | Generator
 */

import React, { useState, useEffect, useCallback } from 'react';
import { sendMessage } from './helpers';
import { WelcomeScreen } from './components/WelcomeScreen';
import { LockScreen } from './components/LockScreen';
import { VaultTab } from './components/VaultTab';
import { IdentityTab } from './components/IdentityTab';
import { GeneratorTab } from './components/GeneratorTab';
import { SettingsTab } from './components/SettingsTab';
import type { VaultStatusData } from '../utils/messages';

type AppState = 'loading' | 'welcome' | 'locked' | 'unlocked';
type Tab = 'vault' | 'identity' | 'generator' | 'settings';

export function App() {
  const [state, setState] = useState<AppState>('loading');
  const [tab, setTab] = useState<Tab>('vault');
  const [status, setStatus] = useState<VaultStatusData | null>(null);
  const [error, setError] = useState('');

  const refreshStatus = useCallback(async () => {
    const res = await sendMessage<VaultStatusData>({ type: 'VAULT_GET_STATUS' });
    if (res.success && res.data) {
      setStatus(res.data);
      if (!res.data.exists) {
        setState('welcome');
      } else if (res.data.isUnlocked) {
        setState('unlocked');
      } else {
        setState('locked');
      }
    }
  }, []);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const handleCreate = async (passphrase?: string) => {
    setError('');
    const res = await sendMessage({ type: 'VAULT_CREATE', passphrase });
    if (res.success) {
      await refreshStatus();
      setState('unlocked');
    } else {
      setError(res.error || 'Failed to create vault');
    }
  };

  const handleUnlock = async (passphrase?: string) => {
    setError('');
    const res = await sendMessage({ type: 'VAULT_UNLOCK', passphrase });
    if (res.success) {
      await refreshStatus();
      setState('unlocked');
    } else {
      setError(res.error || 'Failed to unlock');
    }
  };

  const handleLock = async () => {
    await sendMessage({ type: 'VAULT_LOCK' });
    setState('locked');
  };

  // ---- RENDER ----

  if (state === 'loading') {
    return (
      <div className="lock-screen">
        <div className="lock-icon">⏳</div>
        <div className="lock-title">Loading...</div>
      </div>
    );
  }

  if (state === 'welcome') {
    return <WelcomeScreen onCreate={handleCreate} error={error} />;
  }

  if (state === 'locked') {
    return (
      <LockScreen
        onUnlock={handleUnlock}
        error={error}
        publicKey={status?.identity?.publicKey}
      />
    );
  }

  // === UNLOCKED ===
  return (
    <div>
      {/* Header */}
      <div className="header">
        <div className="header-brand">
          <span className="header-dot" />
          GNS Vault
        </div>
        <div className="header-actions">
          <button
            className="btn-icon"
            onClick={handleLock}
            title="Lock vault"
            style={{ color: 'rgba(255,255,255,0.7)' }}
          >
            🔒
          </button>
        </div>
      </div>

      {/* Tab Bar */}
      <div className="tab-bar">
        <button
          className={`tab ${tab === 'vault' ? 'active' : ''}`}
          onClick={() => setTab('vault')}
        >
          🔑 Vault
        </button>
        <button
          className={`tab ${tab === 'identity' ? 'active' : ''}`}
          onClick={() => setTab('identity')}
        >
          🌐 Identity
        </button>
        <button
          className={`tab ${tab === 'generator' ? 'active' : ''}`}
          onClick={() => setTab('generator')}
        >
          ⚡ Generator
        </button>
        <button
          className={`tab ${tab === 'settings' ? 'active' : ''}`}
          onClick={() => setTab('settings')}
        >
          ⚙ Settings
        </button>
      </div>

      {/* Tab Content */}
      <div className="content">
        {tab === 'vault' && <VaultTab />}
        {tab === 'identity' && <IdentityTab />}
        {tab === 'generator' && <GeneratorTab />}
        {tab === 'settings' && <SettingsTab onRefreshVault={() => { setTab('vault'); refreshStatus(); }} />}
      </div>
    </div>
  );
}
