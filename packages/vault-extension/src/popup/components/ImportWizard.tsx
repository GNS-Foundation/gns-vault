/**
 * GNS Vault — Import Wizard Component
 *
 * Step-by-step import flow:
 *   1. Select source (1Password, Bitwarden, LastPass, Chrome, Generic CSV)
 *   2. Upload/paste file
 *   3. Preview parsed results
 *   4. Confirm import
 *   5. Show results with stats
 */

import React, { useState, useRef } from 'react';
import { sendMessage } from '../helpers';

type ImportSource = '1password' | 'bitwarden' | 'lastpass' | 'chrome_csv' | 'generic_csv';
type Step = 'select' | 'upload' | 'importing' | 'results';

interface ImportResults {
  totalParsed: number;
  totalImported: number;
  skipped: number;
  errors: string[];
  newTotal: number;
}

const SOURCES: Array<{ id: ImportSource; name: string; icon: string; format: string; help: string }> = [
  {
    id: 'bitwarden',
    name: 'Bitwarden',
    icon: '🔷',
    format: 'JSON',
    help: 'Settings → Export Vault → File format: .json',
  },
  {
    id: '1password',
    name: '1Password',
    icon: '🔑',
    format: 'CSV',
    help: 'File → Export → All Items → CSV format',
  },
  {
    id: 'lastpass',
    name: 'LastPass',
    icon: '🔴',
    format: 'CSV',
    help: 'Account Options → Advanced → Export → CSV',
  },
  {
    id: 'chrome_csv',
    name: 'Chrome',
    icon: '🌐',
    format: 'CSV',
    help: 'Settings → Passwords → ⋮ → Export passwords',
  },
  {
    id: 'generic_csv',
    name: 'Other (CSV)',
    icon: '📄',
    format: 'CSV',
    help: 'Any CSV with name, url, username, password columns',
  },
];

interface Props {
  onDone: () => void;
}

export function ImportWizard({ onDone }: Props) {
  const [step, setStep] = useState<Step>('select');
  const [source, setSource] = useState<ImportSource | null>(null);
  const [fileContent, setFileContent] = useState('');
  const [fileName, setFileName] = useState('');
  const [results, setResults] = useState<ImportResults | null>(null);
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  const selectedSource = SOURCES.find((s) => s.id === source);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    setError('');

    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      if (!text || text.trim().length === 0) {
        setError('File appears to be empty');
        return;
      }
      setFileContent(text);
    };
    reader.onerror = () => setError('Failed to read file');
    reader.readAsText(file);
  };

  const handleImport = async () => {
    if (!source || !fileContent) return;

    setStep('importing');
    setError('');

    const res = await sendMessage<ImportResults>({
      type: 'VAULT_IMPORT',
      data: fileContent,
      format: source,
    });

    if (res.success && res.data) {
      setResults(res.data);
      setStep('results');
    } else {
      setError(res.error || 'Import failed');
      setStep('upload');
    }
  };

  // ===== STEP: SELECT SOURCE =====
  if (step === 'select') {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--primary)' }}>
            Import Credentials
          </div>
          <button className="btn-icon" onClick={onDone} title="Cancel">✕</button>
        </div>

        <div style={{ fontSize: '12px', color: 'var(--medium)', marginBottom: '14px' }}>
          Select where you're importing from:
        </div>

        {SOURCES.map((s) => (
          <div
            key={s.id}
            onClick={() => { setSource(s.id); setStep('upload'); }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '12px',
              borderRadius: 'var(--radius)',
              cursor: 'pointer',
              transition: 'background 0.15s',
              marginBottom: '4px',
              border: '1px solid transparent',
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLDivElement).style.background = 'var(--light)';
              (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)';
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLDivElement).style.background = 'transparent';
              (e.currentTarget as HTMLDivElement).style.borderColor = 'transparent';
            }}
          >
            <span style={{ fontSize: '24px' }}>{s.icon}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '14px', fontWeight: '500' }}>{s.name}</div>
              <div style={{ fontSize: '11px', color: 'var(--medium)' }}>{s.format} format</div>
            </div>
            <span style={{ color: 'var(--medium)' }}>→</span>
          </div>
        ))}
      </div>
    );
  }

  // ===== STEP: UPLOAD FILE =====
  if (step === 'upload') {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <button
            className="btn-icon"
            onClick={() => { setStep('select'); setFileContent(''); setFileName(''); setError(''); }}
            title="Back"
          >
            ←
          </button>
          <div style={{ fontSize: '14px', fontWeight: '600', color: 'var(--primary)' }}>
            {selectedSource?.icon} Import from {selectedSource?.name}
          </div>
        </div>

        {/* Instructions */}
        <div
          style={{
            background: 'var(--light)',
            borderRadius: 'var(--radius)',
            padding: '12px',
            fontSize: '12px',
            color: 'var(--medium)',
            marginBottom: '16px',
            lineHeight: 1.6,
          }}
        >
          <div style={{ fontWeight: '600', marginBottom: '4px', color: 'var(--primary)' }}>
            How to export from {selectedSource?.name}:
          </div>
          {selectedSource?.help}
        </div>

        {/* File picker */}
        <input
          ref={fileRef}
          type="file"
          accept={selectedSource?.format === 'JSON' ? '.json' : '.csv,.txt'}
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />

        <div
          onClick={() => fileRef.current?.click()}
          style={{
            border: '2px dashed var(--border)',
            borderRadius: 'var(--radius)',
            padding: '32px 16px',
            textAlign: 'center',
            cursor: 'pointer',
            transition: 'all 0.2s',
            marginBottom: '12px',
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--secondary)';
            (e.currentTarget as HTMLDivElement).style.background = 'var(--light)';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)';
            (e.currentTarget as HTMLDivElement).style.background = 'transparent';
          }}
        >
          {fileName ? (
            <>
              <div style={{ fontSize: '24px', marginBottom: '6px' }}>📄</div>
              <div style={{ fontSize: '14px', fontWeight: '500', color: 'var(--primary)' }}>{fileName}</div>
              <div style={{ fontSize: '11px', color: 'var(--medium)', marginTop: '4px' }}>
                {fileContent.length.toLocaleString()} characters — Click to change
              </div>
            </>
          ) : (
            <>
              <div style={{ fontSize: '24px', marginBottom: '6px' }}>📂</div>
              <div style={{ fontSize: '14px', color: 'var(--primary)' }}>
                Click to select your export file
              </div>
              <div style={{ fontSize: '11px', color: 'var(--medium)', marginTop: '4px' }}>
                Accepts .{selectedSource?.format === 'JSON' ? 'json' : 'csv'} files
              </div>
            </>
          )}
        </div>

        {error && (
          <div style={{ color: 'var(--danger)', fontSize: '12px', marginBottom: '8px' }}>
            ⚠ {error}
          </div>
        )}

        {/* Security notice */}
        <div style={{ fontSize: '11px', color: 'var(--medium)', marginBottom: '16px', lineHeight: 1.5 }}>
          🔒 Your file is processed locally — nothing is uploaded to any server.
          After import, we recommend deleting the export file.
        </div>

        <button
          className="btn btn-primary btn-full"
          onClick={handleImport}
          disabled={!fileContent}
          style={{ padding: '10px' }}
        >
          Import Credentials
        </button>
      </div>
    );
  }

  // ===== STEP: IMPORTING =====
  if (step === 'importing') {
    return (
      <div style={{ textAlign: 'center', padding: '60px 16px' }}>
        <div style={{ fontSize: '36px', marginBottom: '12px' }}>⏳</div>
        <div style={{ fontSize: '15px', fontWeight: '600', color: 'var(--primary)' }}>
          Importing credentials...
        </div>
        <div style={{ fontSize: '12px', color: 'var(--medium)', marginTop: '8px' }}>
          Encrypting each entry with XChaCha20-Poly1305
        </div>
      </div>
    );
  }

  // ===== STEP: RESULTS =====
  if (step === 'results' && results) {
    const hasErrors = results.errors.length > 0;

    return (
      <div>
        <div style={{ textAlign: 'center', marginBottom: '20px' }}>
          <div style={{ fontSize: '40px', marginBottom: '8px' }}>
            {hasErrors ? '⚠️' : '✅'}
          </div>
          <div style={{ fontSize: '18px', fontWeight: '700', color: 'var(--primary)' }}>
            {results.totalImported} Credentials Imported
          </div>
          {results.skipped > 0 && (
            <div style={{ fontSize: '12px', color: 'var(--medium)', marginTop: '4px' }}>
              {results.skipped} skipped (empty or duplicate)
            </div>
          )}
        </div>

        {/* Stats */}
        <div style={{ marginBottom: '16px' }}>
          <div className="stat-row">
            <span className="stat-label">Parsed from file</span>
            <span className="stat-value">{results.totalParsed}</span>
          </div>
          <div className="stat-row">
            <span className="stat-label">Successfully imported</span>
            <span className="stat-value stat-ok">{results.totalImported}</span>
          </div>
          {results.skipped > 0 && (
            <div className="stat-row">
              <span className="stat-label">Skipped</span>
              <span className="stat-value">{results.skipped}</span>
            </div>
          )}
          <div className="stat-row">
            <span className="stat-label">Total in vault</span>
            <span className="stat-value" style={{ color: 'var(--primary)' }}>{results.newTotal}</span>
          </div>
        </div>

        {/* Errors */}
        {hasErrors && (
          <div
            style={{
              background: '#FEF5F5',
              borderRadius: 'var(--radius)',
              padding: '10px 12px',
              marginBottom: '16px',
              fontSize: '12px',
              maxHeight: '100px',
              overflowY: 'auto',
            }}
          >
            <div style={{ fontWeight: '600', color: 'var(--danger)', marginBottom: '4px' }}>
              {results.errors.length} error{results.errors.length > 1 ? 's' : ''}:
            </div>
            {results.errors.map((err, i) => (
              <div key={i} style={{ color: '#666', marginBottom: '2px' }}>{err}</div>
            ))}
          </div>
        )}

        <button
          className="btn btn-primary btn-full"
          onClick={onDone}
          style={{ padding: '10px' }}
        >
          Done
        </button>
      </div>
    );
  }

  return null;
}
