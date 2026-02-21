/**
 * GNS Vault — Auth Consent Overlay
 *
 * When a website requests GNS Auth for the first time, we show
 * a slide-down consent overlay asking the user to approve or deny.
 *
 * @module vault-extension/content/consent-overlay
 */

export interface ConsentRequest {
  origin: string;
  appId?: string;
}

/**
 * Show the consent overlay and return the user's decision.
 */
export function showConsentOverlay(request: ConsentRequest): Promise<boolean> {
  return new Promise((resolve) => {
    // Remove any existing overlay
    const existing = document.getElementById('gns-consent-overlay');
    if (existing) existing.remove();

    // Create overlay
    const overlay = document.createElement('div');
    overlay.id = 'gns-consent-overlay';
    Object.assign(overlay.style, {
      all: 'initial',
      position: 'fixed',
      top: '0',
      left: '0',
      right: '0',
      zIndex: '2147483647',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '14px',
      color: '#1C2833',
      animation: 'gnsSlideDown 0.3s ease',
    });

    // Inject keyframes
    if (!document.getElementById('gns-consent-styles')) {
      const style = document.createElement('style');
      style.id = 'gns-consent-styles';
      style.textContent = `
        @keyframes gnsSlideDown {
          from { transform: translateY(-100%); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      `;
      document.head.appendChild(style);
    }

    // Card
    const card = document.createElement('div');
    Object.assign(card.style, {
      background: '#ffffff',
      borderBottom: '1px solid #e0e0e0',
      boxShadow: '0 4px 20px rgba(0,0,0,0.12)',
      padding: '16px 24px',
      display: 'flex',
      alignItems: 'center',
      gap: '16px',
    });

    // GNS branding
    const brand = document.createElement('div');
    Object.assign(brand.style, {
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      flexShrink: '0',
    });
    const dot = document.createElement('span');
    Object.assign(dot.style, {
      width: '12px',
      height: '12px',
      borderRadius: '50%',
      background: '#1E8449',
      display: 'inline-block',
    });
    const brandText = document.createElement('span');
    Object.assign(brandText.style, {
      fontWeight: '700',
      fontSize: '14px',
      color: '#1A3C5E',
    });
    brandText.textContent = 'GNS Vault';
    brand.appendChild(dot);
    brand.appendChild(brandText);

    // Message
    const msg = document.createElement('div');
    Object.assign(msg.style, {
      flex: '1',
      fontSize: '13px',
      lineHeight: '1.5',
    });

    const originBold = document.createElement('strong');
    originBold.textContent = request.origin;
    originBold.style.color = '#1A3C5E';

    msg.appendChild(document.createTextNode(''));
    const msgText = document.createElement('span');
    msgText.innerHTML = `<strong style="color:#1A3C5E">${escapeHtml(request.origin)}</strong> wants to verify your GNS identity. This will share your public key and trust score.`;
    msg.appendChild(msgText);

    // Buttons
    const buttons = document.createElement('div');
    Object.assign(buttons.style, {
      display: 'flex',
      gap: '8px',
      flexShrink: '0',
    });

    const denyBtn = document.createElement('button');
    Object.assign(denyBtn.style, {
      padding: '8px 16px',
      borderRadius: '6px',
      border: '1px solid #E5E8EB',
      background: '#ffffff',
      color: '#566573',
      fontSize: '13px',
      fontWeight: '500',
      cursor: 'pointer',
      fontFamily: 'inherit',
      transition: 'all 0.15s',
    });
    denyBtn.textContent = 'Deny';
    denyBtn.addEventListener('mouseenter', () => { denyBtn.style.background = '#F4F6F7'; });
    denyBtn.addEventListener('mouseleave', () => { denyBtn.style.background = '#ffffff'; });

    const approveBtn = document.createElement('button');
    Object.assign(approveBtn.style, {
      padding: '8px 20px',
      borderRadius: '6px',
      border: 'none',
      background: '#1A3C5E',
      color: '#ffffff',
      fontSize: '13px',
      fontWeight: '500',
      cursor: 'pointer',
      fontFamily: 'inherit',
      transition: 'all 0.15s',
    });
    approveBtn.textContent = 'Approve';
    approveBtn.addEventListener('mouseenter', () => { approveBtn.style.background = '#15324e'; });
    approveBtn.addEventListener('mouseleave', () => { approveBtn.style.background = '#1A3C5E'; });

    const cleanup = () => {
      overlay.style.animation = 'none';
      overlay.style.transition = 'transform 0.2s ease, opacity 0.2s ease';
      overlay.style.transform = 'translateY(-100%)';
      overlay.style.opacity = '0';
      setTimeout(() => overlay.remove(), 250);
    };

    denyBtn.addEventListener('click', () => { cleanup(); resolve(false); });
    approveBtn.addEventListener('click', () => { cleanup(); resolve(true); });

    buttons.appendChild(denyBtn);
    buttons.appendChild(approveBtn);

    card.appendChild(brand);
    card.appendChild(msg);
    card.appendChild(buttons);
    overlay.appendChild(card);

    document.body.appendChild(overlay);

    // Auto-deny after 30 seconds
    setTimeout(() => {
      if (document.getElementById('gns-consent-overlay')) {
        cleanup();
        resolve(false);
      }
    }, 30000);
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
