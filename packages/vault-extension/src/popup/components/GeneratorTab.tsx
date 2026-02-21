import React, { useState, useEffect, useCallback } from 'react';
import { sendMessage, copyToClipboard } from '../helpers';

interface GenResult {
  password: string;
  strength: number;
}

export function GeneratorTab() {
  const [password, setPassword] = useState('');
  const [strength, setStrength] = useState(0);
  const [copied, setCopied] = useState(false);

  // Options
  const [length, setLength] = useState(24);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);

  const generate = useCallback(async () => {
    const res = await sendMessage<GenResult>({
      type: 'VAULT_GENERATE_PASSWORD',
      options: { length, uppercase, lowercase, digits, symbols, excludeAmbiguous },
    });
    if (res.success && res.data) {
      setPassword(res.data.password);
      setStrength(res.data.strength);
    }
  }, [length, uppercase, lowercase, digits, symbols, excludeAmbiguous]);

  useEffect(() => {
    generate();
  }, [generate]);

  const handleCopy = async () => {
    await copyToClipboard(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const strengthLabel = () => {
    if (strength < 30) return { text: 'Weak', class: 'strength-weak' };
    if (strength < 50) return { text: 'Fair', class: 'strength-fair' };
    if (strength < 70) return { text: 'Good', class: 'strength-good' };
    return { text: 'Strong', class: 'strength-strong' };
  };

  const sl = strengthLabel();

  return (
    <div>
      <div style={{ fontSize: '13px', fontWeight: '600', color: 'var(--primary)', marginBottom: '8px' }}>
        Password Generator
      </div>

      {/* Password Display */}
      <div className="pw-display" onClick={handleCopy} title="Click to copy">
        {password}
      </div>

      {/* Strength Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--medium)' }}>
        <span>Strength</span>
        <span style={{ fontWeight: '600' }}>{sl.text} ({strength}/100)</span>
      </div>
      <div className="strength-bar">
        <div className={`strength-fill ${sl.class}`} style={{ width: `${strength}%` }} />
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: '8px', margin: '12px 0' }}>
        <button className="btn btn-primary" onClick={generate} style={{ flex: 1 }}>
          ⟳ Regenerate
        </button>
        <button className="btn btn-accent" onClick={handleCopy} style={{ flex: 1 }}>
          {copied ? '✓ Copied!' : '📋 Copy'}
        </button>
      </div>

      {/* Options */}
      <div style={{ borderTop: '1px solid var(--border)', paddingTop: '12px' }}>
        <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--medium)', marginBottom: '10px' }}>
          OPTIONS
        </div>

        {/* Length slider */}
        <div style={{ marginBottom: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '4px' }}>
            <span>Length</span>
            <span style={{ fontWeight: '600', color: 'var(--primary)' }}>{length}</span>
          </div>
          <input
            type="range"
            min={8}
            max={64}
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
            style={{ width: '100%', accentColor: 'var(--primary)' }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--medium)' }}>
            <span>8</span>
            <span>64</span>
          </div>
        </div>

        {/* Character set toggles */}
        {[
          { label: 'Uppercase (A-Z)', checked: uppercase, set: setUppercase },
          { label: 'Lowercase (a-z)', checked: lowercase, set: setLowercase },
          { label: 'Digits (0-9)', checked: digits, set: setDigits },
          { label: 'Symbols (!@#$...)', checked: symbols, set: setSymbols },
          { label: 'Exclude ambiguous (0, O, l, 1)', checked: excludeAmbiguous, set: setExcludeAmbiguous },
        ].map(({ label, checked, set }) => (
          <label
            key={label}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '13px',
              padding: '6px 0',
              cursor: 'pointer',
              color: checked ? 'var(--dark)' : 'var(--medium)',
            }}
          >
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => set(e.target.checked)}
              style={{ accentColor: 'var(--primary)' }}
            />
            {label}
          </label>
        ))}
      </div>
    </div>
  );
}
