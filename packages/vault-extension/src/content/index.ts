/**
 * GNS Vault Extension — Content Script
 *
 * Injected into every page. Responsibilities:
 *   1. Detect login/signup forms (username + password fields)
 *   2. Request matching credentials from background
 *   3. Display auto-fill UI overlay
 *   4. Detect form submissions to offer credential saving
 *   5. Detect GNS Auth SDK presence for passwordless login
 *
 * @module vault-extension/content
 */

import type { AutofillData } from '../utils/messages';
import { initAuthBridge } from './auth-bridge';
import { initAipDetector } from './aip-detector';
import './content.css';

// ============================================================
// CONSTANTS
// ============================================================

const GNS_VAULT_ATTR = 'data-gns-vault';
const GNS_OVERLAY_ID = 'gns-vault-overlay';
const DEBOUNCE_MS = 300;

// ============================================================
// FORM DETECTION
// ============================================================

interface DetectedForm {
  form: HTMLFormElement | null;
  usernameField: HTMLInputElement;
  passwordField: HTMLInputElement;
}

/**
 * Find login forms on the current page.
 *
 * Heuristics:
 *   - Look for password fields (type="password")
 *   - Walk backward to find associated username/email field
 *   - Handle forms without <form> tags (single-page apps)
 */
function detectLoginForms(): DetectedForm[] {
  const detected: DetectedForm[] = [];
  const passwordFields = document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]:not([data-gns-vault="processed"])'
  );

  for (const pwField of passwordFields) {
    const form = pwField.closest('form');
    const usernameField = findUsernameField(pwField, form);

    if (usernameField) {
      detected.push({
        form,
        usernameField,
        passwordField: pwField,
      });

      // Mark as processed
      pwField.setAttribute(GNS_VAULT_ATTR, 'processed');
      usernameField.setAttribute(GNS_VAULT_ATTR, 'processed');
    }
  }

  return detected;
}

/**
 * Find the username/email field associated with a password field.
 *
 * Strategy:
 *   1. Look within the same <form> for email/text/tel inputs
 *   2. Look at preceding siblings
 *   3. Walk up the DOM and look at previous visible inputs
 */
function findUsernameField(
  pwField: HTMLInputElement,
  form: HTMLFormElement | null
): HTMLInputElement | null {
  const candidates: HTMLInputElement[] = [];

  // Strategy 1: Fields in the same form
  const container = form || pwField.parentElement?.parentElement;
  if (container) {
    const inputs = container.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
    );
    for (const input of inputs) {
      if (input !== pwField && isVisible(input)) {
        candidates.push(input);
      }
    }
  }

  if (candidates.length === 0) return null;

  // Prioritize by attribute hints
  const prioritized = candidates.sort((a, b) => {
    const scoreA = usernameScore(a);
    const scoreB = usernameScore(b);
    return scoreB - scoreA;
  });

  return prioritized[0] || null;
}

/**
 * Score how likely an input is to be a username/email field.
 */
function usernameScore(input: HTMLInputElement): number {
  let score = 0;
  const attrs = [
    input.type,
    input.name,
    input.id,
    input.autocomplete,
    input.placeholder,
    input.getAttribute('aria-label') || '',
  ]
    .join(' ')
    .toLowerCase();

  if (attrs.includes('email')) score += 10;
  if (attrs.includes('username')) score += 10;
  if (attrs.includes('user')) score += 5;
  if (attrs.includes('login')) score += 5;
  if (attrs.includes('account')) score += 3;
  if (input.type === 'email') score += 8;
  if (input.autocomplete === 'username') score += 10;
  if (input.autocomplete === 'email') score += 8;

  // Penalize fields that are likely not usernames
  if (attrs.includes('search')) score -= 10;
  if (attrs.includes('phone') && !attrs.includes('email')) score -= 3;
  if (attrs.includes('first') || attrs.includes('last')) score -= 5;

  return score;
}

/**
 * Check if an element is visible in the DOM.
 */
function isVisible(el: HTMLElement): boolean {
  if (el.offsetParent === null && el.style.position !== 'fixed') return false;
  const style = window.getComputedStyle(el);
  return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
}

// ============================================================
// AUTO-FILL UI
// ============================================================

let activeOverlay: HTMLDivElement | null = null;
let activeTarget: DetectedForm | null = null;

/**
 * Show the auto-fill overlay near a field.
 */
function showAutofillOverlay(
  field: HTMLInputElement,
  entries: AutofillData['entries'],
  detectedForm: DetectedForm
): void {
  removeOverlay();

  if (entries.length === 0) return;

  activeTarget = detectedForm;
  const overlay = document.createElement('div');
  overlay.id = GNS_OVERLAY_ID;

  // Position below the focused field
  const rect = field.getBoundingClientRect();
  Object.assign(overlay.style, {
    position: 'fixed',
    top: `${rect.bottom + 4}px`,
    left: `${rect.left}px`,
    width: `${Math.max(rect.width, 280)}px`,
    maxHeight: '240px',
    overflowY: 'auto',
    zIndex: '2147483647',
    background: '#ffffff',
    border: '1px solid #e0e0e0',
    borderRadius: '8px',
    boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontSize: '14px',
    color: '#1C2833',
  });

  // Header
  const header = document.createElement('div');
  Object.assign(header.style, {
    padding: '8px 12px',
    borderBottom: '1px solid #f0f0f0',
    fontSize: '11px',
    fontWeight: '600',
    color: '#566573',
    letterSpacing: '0.5px',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  });
  header.innerHTML = `<span style="color:#1A3C5E;font-size:13px;">&#9679;</span> GNS Vault`;
  overlay.appendChild(header);

  // Entry items
  for (const entry of entries) {
    const item = document.createElement('div');
    Object.assign(item.style, {
      padding: '10px 12px',
      cursor: 'pointer',
      borderBottom: '1px solid #f8f8f8',
      transition: 'background 0.15s',
    });
    item.addEventListener('mouseenter', () => {
      item.style.background = '#EBF5FB';
    });
    item.addEventListener('mouseleave', () => {
      item.style.background = 'transparent';
    });

    const nameEl = document.createElement('div');
    nameEl.style.fontWeight = '500';
    nameEl.style.marginBottom = '2px';
    nameEl.textContent = entry.name;

    const userEl = document.createElement('div');
    userEl.style.fontSize = '12px';
    userEl.style.color = '#566573';
    userEl.textContent = entry.username;

    item.appendChild(nameEl);
    item.appendChild(userEl);

    item.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      fillCredential(detectedForm, entry.username, entry.password);
      removeOverlay();
    });

    overlay.appendChild(item);
  }

  document.body.appendChild(overlay);
  activeOverlay = overlay;
}

/**
 * Fill credential into form fields.
 */
function fillCredential(
  target: DetectedForm,
  username: string,
  password: string
): void {
  setInputValue(target.usernameField, username);
  setInputValue(target.passwordField, password);

  // Flash green border to confirm fill
  for (const field of [target.usernameField, target.passwordField]) {
    const originalBorder = field.style.border;
    field.style.border = '2px solid #1E8449';
    field.style.borderRadius = '4px';
    setTimeout(() => {
      field.style.border = originalBorder;
      field.style.borderRadius = '';
    }, 800);
  }
}

/**
 * Set input value in a way that triggers React/Vue/Angular change detection.
 */
function setInputValue(input: HTMLInputElement, value: string): void {
  // Native value setter (bypasses React's synthetic events)
  const nativeSetter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    'value'
  )?.set;

  if (nativeSetter) {
    nativeSetter.call(input, value);
  } else {
    input.value = value;
  }

  // Dispatch events that frameworks listen for
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  input.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
  input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
}

function removeOverlay(): void {
  if (activeOverlay) {
    activeOverlay.remove();
    activeOverlay = null;
    activeTarget = null;
  }
}

// ============================================================
// FORM SUBMISSION DETECTION (Save Credentials)
// ============================================================

function watchFormSubmissions(forms: DetectedForm[]): void {
  for (const detected of forms) {
    const { form, usernameField, passwordField } = detected;

    const onSubmit = () => {
      const username = usernameField.value.trim();
      const password = passwordField.value;

      if (!username || !password) return;

      // Notify background to save/update credential
      chrome.runtime.sendMessage({
        type: 'AUTOFILL_SAVE',
        url: window.location.href,
        username,
        password,
      });
    };

    if (form) {
      form.addEventListener('submit', onSubmit);
    }

    // Also detect button clicks (for SPAs without form submit)
    const submitBtn =
      form?.querySelector<HTMLButtonElement>(
        'button[type="submit"], input[type="submit"], button:not([type])'
      ) ||
      passwordField.parentElement?.querySelector<HTMLButtonElement>('button');

    if (submitBtn) {
      submitBtn.addEventListener('click', () => {
        // Slight delay to let validation happen
        setTimeout(onSubmit, 100);
      });
    }

    // Detect Enter key on password field
    passwordField.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        setTimeout(onSubmit, 100);
      }
    });
  }
}

// ============================================================
// FOCUS HANDLER (Triggers Auto-fill)
// ============================================================

let currentForms: DetectedForm[] = [];

function handleFocus(e: FocusEvent): void {
  const target = e.target as HTMLInputElement;
  if (!target || target.tagName !== 'INPUT') return;

  // Find which detected form this field belongs to
  const form = currentForms.find(
    (f) => f.usernameField === target || f.passwordField === target
  );
  if (!form) return;

  // Request credentials from background
  chrome.runtime.sendMessage(
    { type: 'AUTOFILL_REQUEST', url: window.location.href },
    (response) => {
      if (chrome.runtime.lastError) return;
      if (!response?.success || !response.data) return;

      const data = response.data as AutofillData;
      if (data.entries.length > 0) {
        showAutofillOverlay(target, data.entries, form);
      }
    }
  );
}

// ============================================================
// INITIALIZATION
// ============================================================

function init(): void {
  // Initialize GNS Auth bridge (connects Auth SDK on page ↔ extension)
  initAuthBridge();

  // Initialize AIP agent detector (meta tags, globals, SDK events)
  initAipDetector();

  // Initial scan
  currentForms = detectLoginForms();
  watchFormSubmissions(currentForms);

  // Listen for focus on input fields
  document.addEventListener('focusin', handleFocus, true);

  // Dismiss overlay on outside click
  document.addEventListener('click', (e) => {
    if (activeOverlay && !activeOverlay.contains(e.target as Node)) {
      removeOverlay();
    }
  });

  // Dismiss overlay on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') removeOverlay();
  });

  // Watch for dynamically added forms (SPAs)
  const observer = new MutationObserver(
    debounce(() => {
      const newForms = detectLoginForms();
      if (newForms.length > 0) {
        currentForms = [...currentForms, ...newForms];
        watchFormSubmissions(newForms);
      }
    }, DEBOUNCE_MS)
  );

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

function debounce<T extends (...args: unknown[]) => void>(fn: T, ms: number): MutationCallback {
  let timer: ReturnType<typeof setTimeout>;
  return (...args: Parameters<MutationCallback>) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...(args as unknown as Parameters<T>)), ms);
  };
}

// Run when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
