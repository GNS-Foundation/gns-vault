/**
 * GNS Vault — Import / Export
 *
 * Import credentials from:
 *   - 1Password (.1pif, .csv)
 *   - Bitwarden (.json)
 *   - LastPass (.csv)
 *   - Chrome (.csv)
 *   - Generic CSV
 *
 * Export credentials to:
 *   - JSON (GNS Vault native format)
 *   - CSV (universal)
 *
 * @module @gns-vault/core/import-export
 */

import type {
  VaultEntry,
  ImportResult,
  ImportFormat,
  ExportOptions,
} from './types.js';
import { EntryType } from './types.js';
import { uuid } from './keys.js';
import { passwordStrength } from './crypto.js';

// ============================================================
// IMPORT
// ============================================================

/**
 * Import credentials from a competitor format.
 *
 * @param data - Raw file contents (string)
 * @param format - Source format
 * @returns Import result with entries and statistics
 */
export function importCredentials(
  data: string,
  format: ImportFormat
): ImportResult {
  switch (format) {
    case 'bitwarden':
      return importBitwarden(data);
    case 'lastpass':
      return importLastPassCsv(data);
    case 'chrome_csv':
      return importChromeCsv(data);
    case '1password':
      return import1PasswordCsv(data);
    case 'generic_csv':
      return importGenericCsv(data);
    default:
      return { entries: [], totalParsed: 0, totalImported: 0, skipped: 0, errors: [`Unknown format: ${format}`] };
  }
}

/**
 * Import from Bitwarden JSON export.
 */
function importBitwarden(data: string): ImportResult {
  const errors: string[] = [];
  let parsed: { items?: Array<Record<string, unknown>> };

  try {
    parsed = JSON.parse(data);
  } catch {
    return { entries: [], totalParsed: 0, totalImported: 0, skipped: 0, errors: ['Invalid JSON'] };
  }

  const items = parsed.items || [];
  const entries: VaultEntry[] = [];

  for (const item of items) {
    try {
      const login = item.login as Record<string, unknown> | undefined;
      const now = new Date().toISOString();
      const password = (login?.password as string) || '';

      const entry: VaultEntry = {
        id: uuid(),
        type: item.type === 2 ? EntryType.SecureNote : EntryType.Login,
        name: (item.name as string) || 'Untitled',
        urls: login?.uris
          ? (login.uris as Array<{ uri: string }>).map(u => u.uri).filter(Boolean)
          : [],
        username: (login?.username as string) || '',
        password,
        totpSecret: (login?.totp as string) || undefined,
        notes: (item.notes as string) || undefined,
        folder: (item.folderId as string) || undefined,
        favorite: (item.favorite as boolean) || false,
        createdAt: now,
        updatedAt: now,
        passwordStrength: password ? passwordStrength(password) : undefined,
      };

      entries.push(entry);
    } catch (err) {
      errors.push(`Failed to import item: ${(err as Error).message}`);
    }
  }

  return {
    entries,
    totalParsed: items.length,
    totalImported: entries.length,
    skipped: items.length - entries.length,
    errors,
  };
}

/**
 * Import from LastPass CSV export.
 * Format: url, username, password, totp, extra, name, grouping, fav
 */
function importLastPassCsv(data: string): ImportResult {
  return importCsvWithMapping(data, {
    url: ['url'],
    username: ['username'],
    password: ['password'],
    name: ['name'],
    notes: ['extra'],
    folder: ['grouping'],
    totp: ['totp'],
  });
}

/**
 * Import from Chrome CSV export.
 * Format: name, url, username, password, note
 */
function importChromeCsv(data: string): ImportResult {
  return importCsvWithMapping(data, {
    url: ['url'],
    username: ['username'],
    password: ['password'],
    name: ['name'],
    notes: ['note'],
  });
}

/**
 * Import from 1Password CSV export.
 * Format: Title, Url, Username, Password, Notes, Type
 */
function import1PasswordCsv(data: string): ImportResult {
  return importCsvWithMapping(data, {
    url: ['url', 'website'],
    username: ['username', 'login'],
    password: ['password'],
    name: ['title', 'name'],
    notes: ['notes', 'extra'],
  });
}

/**
 * Import from generic CSV with auto-detected columns.
 */
function importGenericCsv(data: string): ImportResult {
  return importCsvWithMapping(data, {
    url: ['url', 'website', 'site', 'login_uri', 'uri'],
    username: ['username', 'user', 'email', 'login', 'account'],
    password: ['password', 'pass', 'pwd', 'secret'],
    name: ['name', 'title', 'label', 'site_name'],
    notes: ['notes', 'note', 'extra', 'comments'],
    folder: ['folder', 'group', 'category', 'grouping'],
    totp: ['totp', 'otp', 'totp_secret', '2fa'],
  });
}

// ============================================================
// CSV PARSER
// ============================================================

/**
 * Parse CSV data with column mapping.
 */
function importCsvWithMapping(
  data: string,
  mapping: Record<string, string[]>
): ImportResult {
  const errors: string[] = [];
  const rows = parseCsv(data);

  if (rows.length < 2) {
    return { entries: [], totalParsed: 0, totalImported: 0, skipped: 0, errors: ['CSV has no data rows'] };
  }

  // Map header columns
  const headers = rows[0]!.map(h => h.toLowerCase().trim());
  const colMap: Record<string, number> = {};

  for (const [field, aliases] of Object.entries(mapping)) {
    for (const alias of aliases) {
      const idx = headers.indexOf(alias.toLowerCase());
      if (idx !== -1) {
        colMap[field] = idx;
        break;
      }
    }
  }

  if (!colMap['password'] && !colMap['username']) {
    errors.push('Could not detect username or password columns');
    return { entries: [], totalParsed: rows.length - 1, totalImported: 0, skipped: rows.length - 1, errors };
  }

  const entries: VaultEntry[] = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i]!;
    try {
      const get = (field: string): string => {
        const idx = colMap[field];
        return idx !== undefined ? (row[idx] || '').trim() : '';
      };

      const pass = get('password');
      const url = get('url');
      const now = new Date().toISOString();

      const entry: VaultEntry = {
        id: uuid(),
        type: EntryType.Login,
        name: get('name') || extractDomain(url) || 'Imported Entry',
        urls: url ? [url] : [],
        username: get('username'),
        password: pass,
        totpSecret: get('totp') || undefined,
        notes: get('notes') || undefined,
        folder: get('folder') || undefined,
        favorite: false,
        createdAt: now,
        updatedAt: now,
        passwordStrength: pass ? passwordStrength(pass) : undefined,
      };

      // Skip empty entries
      if (!entry.username && !entry.password && entry.urls.length === 0) {
        continue;
      }

      entries.push(entry);
    } catch (err) {
      errors.push(`Row ${i}: ${(err as Error).message}`);
    }
  }

  return {
    entries,
    totalParsed: rows.length - 1,
    totalImported: entries.length,
    skipped: rows.length - 1 - entries.length,
    errors,
  };
}

/**
 * Simple CSV parser that handles quoted fields.
 */
function parseCsv(data: string): string[][] {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < data.length; i++) {
    const char = data[i]!;
    const next = data[i + 1];

    if (inQuotes) {
      if (char === '"' && next === '"') {
        currentField += '"';
        i++; // Skip escaped quote
      } else if (char === '"') {
        inQuotes = false;
      } else {
        currentField += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === ',') {
        currentRow.push(currentField);
        currentField = '';
      } else if (char === '\n' || (char === '\r' && next === '\n')) {
        currentRow.push(currentField);
        currentField = '';
        if (currentRow.some(f => f.trim())) {
          rows.push(currentRow);
        }
        currentRow = [];
        if (char === '\r') i++; // Skip \n in \r\n
      } else {
        currentField += char;
      }
    }
  }

  // Last field/row
  currentRow.push(currentField);
  if (currentRow.some(f => f.trim())) {
    rows.push(currentRow);
  }

  return rows;
}

/**
 * Extract domain name from a URL for display.
 */
function extractDomain(url: string): string {
  try {
    const hostname = new URL(url).hostname;
    // Remove www. prefix
    return hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

// ============================================================
// EXPORT
// ============================================================

/**
 * Export vault entries to a portable format.
 *
 * WARNING: Exported data contains plaintext passwords.
 * The user must be explicitly warned before export.
 *
 * @param entries - Vault entries to export
 * @param options - Export format and options
 * @returns Exported data as string
 */
export function exportCredentials(
  entries: VaultEntry[],
  options: ExportOptions
): string {
  let filtered = entries;
  if (options.folder) {
    filtered = entries.filter(e => e.folder === options.folder);
  }

  if (options.format === 'json') {
    return exportJson(filtered, options);
  } else {
    return exportCsv(filtered, options);
  }
}

function exportJson(entries: VaultEntry[], options: ExportOptions): string {
  const exported = entries.map(entry => ({
    name: entry.name,
    type: entry.type,
    urls: entry.urls,
    username: entry.username,
    password: options.includePasswords ? entry.password : '********',
    notes: entry.notes,
    folder: entry.folder,
    totp: options.includePasswords ? entry.totpSecret : undefined,
    createdAt: entry.createdAt,
  }));

  return JSON.stringify({
    format: 'gns-vault-export',
    version: 1,
    exportedAt: new Date().toISOString(),
    count: exported.length,
    entries: exported,
  }, null, 2);
}

function exportCsv(entries: VaultEntry[], options: ExportOptions): string {
  const headers = ['name', 'url', 'username', 'password', 'notes', 'folder', 'type'];
  const rows = [headers.join(',')];

  for (const entry of entries) {
    const row = [
      csvEscape(entry.name),
      csvEscape(entry.urls[0] || ''),
      csvEscape(entry.username),
      csvEscape(options.includePasswords ? entry.password : '********'),
      csvEscape(entry.notes || ''),
      csvEscape(entry.folder || ''),
      csvEscape(entry.type),
    ];
    rows.push(row.join(','));
  }

  return rows.join('\n');
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
