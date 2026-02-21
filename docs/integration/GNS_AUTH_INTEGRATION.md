# GNS Auth — Integration Guide

## Quick Start (5 minutes)

### 1. Add the SDK

```html
<script src="https://auth.globecrumbs.com/v1/gns-auth.js"></script>
```

Or via npm:

```bash
npm install @gns-vault/auth-sdk
```

```javascript
import { init, renderButton } from '@gns-vault/auth-sdk';
```

### 2. Initialize and Render

```html
<div id="gns-login"></div>

<script>
  GNSAuth.init({
    appId: 'your-app-id',    // Optional: registered app ID
    onAuth: (response) => {
      console.log('User authenticated!');
      console.log('Public Key:', response.publicKey);
      console.log('Trust Score:', response.trustScore);
      console.log('Badge:', response.badgeTier);

      // Send to your server for verification
      fetch('/api/auth/gns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(response),
      });
    },
    onError: (err) => {
      console.error('Auth failed:', err.message);
    },
    onExtensionDetect: (detected) => {
      if (!detected) {
        document.getElementById('install-prompt').style.display = 'block';
      }
    },
  });

  GNSAuth.renderButton('#gns-login');
</script>
```

### 3. Verify on Your Server

```javascript
// Node.js server
const response = await fetch('https://verify.globecrumbs.com/v1/auth/validate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': process.env.GNS_API_KEY,
  },
  body: JSON.stringify({
    response: req.body,          // The GNS Auth response from the client
    challenge: {                  // The challenge you originally issued
      nonce: req.body.nonce,
      origin: 'https://yoursite.com',
      timestamp: req.body.timestamp,
      expiresIn: 300,
    },
  }),
});

const result = await response.json();
// result: { valid: true, public_key: "...", trust_score: 87.3, badge_tier: "gold" }

if (result.valid) {
  // Create or find user by public_key
  const user = await findOrCreateUser(result.public_key);
  // Issue session token
  const token = createSessionToken(user);
  res.json({ token });
}
```

## Button Themes

```javascript
// Dark (default)
GNSAuth.renderButton('#login', { theme: 'dark' });

// Light
GNSAuth.renderButton('#login', { theme: 'light' });

// Outline
GNSAuth.renderButton('#login', { theme: 'outline' });
```

## Requiring Minimum Verification

```javascript
GNSAuth.init({
  minTrustScore: 65,          // Require Gold badge or higher
  minBadgeTier: 'gold',       // Explicit tier requirement
  onAuth: (response) => { ... },
  onError: (err) => {
    if (err.code === 'TRUST_TOO_LOW') {
      showMessage('Please earn a Gold badge to access this feature.');
    }
  },
});
```

## Programmatic Authentication

```javascript
// Trigger auth without a button
try {
  const response = await GNSAuth.authenticate();
  console.log('Authenticated:', response.publicKey);
} catch (err) {
  console.error('Failed:', err.message);
}
```

## Human Verification Only (No Login)

Use the Verify API directly to check if a public key belongs to a verified human:

```javascript
const result = await fetch('https://verify.globecrumbs.com/v1/verify', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'your-api-key',
  },
  body: JSON.stringify({
    public_key: userPublicKey,
    min_trust_score: 40,
  }),
});

const data = await result.json();
// data: { human: true, trust_score: 87.3, breadcrumbs: 2847, badge_tier: "gold" }
```

## React Integration

```jsx
import { useEffect, useState } from 'react';
import * as GNSAuth from '@gns-vault/auth-sdk';

function LoginPage() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    GNSAuth.init({
      onAuth: (response) => setUser(response),
    });
    GNSAuth.renderButton('#gns-btn');

    return () => GNSAuth.destroy();
  }, []);

  if (user) {
    return <div>Welcome, {user.handle || user.publicKey.slice(0, 8)}!</div>;
  }

  return <div id="gns-btn" />;
}
```

## API Reference

| Function | Description |
|----------|-------------|
| `GNSAuth.init(config)` | Initialize the SDK |
| `GNSAuth.renderButton(selector, style?)` | Render a "Sign in with GNS" button |
| `GNSAuth.authenticate()` | Trigger authentication programmatically |
| `GNSAuth.isExtensionAvailable()` | Check if GNS Vault is installed |
| `GNSAuth.destroy()` | Clean up listeners (for SPAs) |
