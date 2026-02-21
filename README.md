# GNS Vault

**The credential vault with a built-in decentralized human identity.**

GNS Vault replaces passwords with cryptographic identity. One Ed25519 key secures your credentials, proves you're human, and serves as your Stellar wallet. No cloud. No biometrics. No third party.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GNS Vault Monorepo                       │
├─────────────────┬─────────────────┬──────────────┬──────────────┤
│   vault-core    │ vault-extension │   auth-sdk   │  verify-api  │
│   ───────────   │ ───────────────  │  ──────────  │ ──────────── │
│ Ed25519 keys    │ Chrome Manifest │ <script> tag │ POST /verify │
│ XChaCha20-Poly  │ V3 extension    │ "Sign in     │ Signature    │
│ Argon2id KDF    │ Auto-fill       │  with GNS"   │  validation  │
│ HMAC integrity  │ React popup     │ Challenge-   │ Trust score  │
│ P2P sync        │ Content scripts │  response    │ Rate limiting│
│ Import/export   │ GNS Auth bridge │ 5.1KB min    │ Hono/Node.js │
├─────────────────┴─────────────────┼──────────────┴──────────────┤
│            Browser (User)         │       Server (Website)      │
└───────────────────────────────────┴─────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │  demo-store │
                    │  ─────────  │
                    │  Reference  │
                    │  e-commerce │
                    │  with GNS   │
                    │  Auth       │
                    └─────────────┘
```

## Packages

| Package | Status | Tests | Description |
|---------|--------|-------|-------------|
| `@gns-vault/core` | ✅ Complete | 60 | Cryptographic engine — Ed25519, XChaCha20-Poly1305, Argon2id |
| `@gns-vault/extension` | ✅ Complete | — | Chrome/Firefox extension with auto-fill and GNS Auth |
| `@gns-vault/auth-sdk` | ✅ Complete | 25 | Website integration SDK — "Sign in with GNS" (5.1KB) |
| `@gns-vault/verify-api` | ✅ Complete | 26 | Human verification REST API — Hono/Node.js |
| `demo-store` | ✅ Complete | — | Reference implementation showing GNS Auth integration |

**Total: 111 tests passing across 4 test suites.**

## Cryptographic Stack

| Primitive | Algorithm | Standard | Purpose |
|-----------|-----------|----------|---------|
| Identity | Ed25519 | RFC 8032 | Signing, authentication, Stellar wallet |
| Encryption | XChaCha20-Poly1305 | AEAD | Vault entry encryption (192-bit nonce) |
| KDF | Argon2id | RFC 9106 | Passphrase → encryption key (t=3, m=64MiB, p=4) |
| Key Derivation | HKDF-SHA256 | RFC 5869 | Identity key → vault key separation |
| Integrity | HMAC-SHA256 | RFC 2104 | Vault tamper detection |
| Sync | X25519 + XChaCha20 | RFC 7748 | P2P encrypted device sync |

All primitives from [**@noble**](https://paulmillr.com/noble/) — audited, zero-dependency implementations.

## Quick Start

```bash
# Clone and install
git clone https://github.com/GNS-Foundation/gns-vault.git
cd gns-vault
pnpm install

# Run all tests (111 tests)
pnpm -r test

# Build everything
pnpm -r build

# Load extension in Chrome
# 1. Open chrome://extensions
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select packages/vault-extension/dist/
```

## SDK Integration (10 lines)

```html
<!-- 1. Include the SDK (5.1KB) -->
<script src="https://auth.globecrumbs.com/v1/gns-auth.js"></script>

<!-- 2. Add a button container -->
<div id="gns-login"></div>

<!-- 3. Initialize -->
<script>
  GNSAuth.init({
    onAuth: (response) => {
      // response.publicKey  — user's GNS identity
      // response.signature  — Ed25519 signed challenge
      // response.trustScore — TrIP human verification (0-100)
      // response.badgeTier  — human badge level
      fetch('/api/auth', {
        method: 'POST',
        body: JSON.stringify(response)
      });
    }
  });
  GNSAuth.renderButton('#gns-login');
</script>
```

## Server-Side Verification

```bash
curl -X POST https://verify.globecrumbs.com/v1/verify \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"public_key": "a1b2c3..."}'
```

Response:
```json
{
  "human": true,
  "trust_score": 87.3,
  "breadcrumbs": 5200,
  "badge_tier": "gold",
  "meets_requirements": true
}
```

## Human Identity Badges (TrIP)

GNS Vault integrates with **TrIP** (Trajectory Recognition Identity Protocol) — IETF-submitted — to prove users are human through daily movement patterns. No biometrics, no hardware.

| Tier | Breadcrumbs | Age | Score |
|------|-------------|-----|-------|
| 🟫 Bronze | 100+ | 1 week | 20+ |
| ⬜ Silver | 500+ | 1 month | 40+ |
| 🟨 Gold | 2,000+ | 3 months | 65+ |
| ⬜ Platinum | 10,000+ | 6 months | 85+ |
| 💎 Diamond | 50,000+ | 12 months | 95+ |

## Patent & Standards

- **Patent**: US Provisional #63/948,788 (TrIP — Trajectory Recognition Identity Protocol)
- **IETF**: TrIP RFC submission (Trajectory Recognition Identity Protocol)
- **License**: COSS (Commercial Open Source Software)

## Development

```bash
pnpm -r test          # Run all 111 tests
pnpm -r build         # Build all packages
pnpm -r typecheck     # TypeScript strict checking
pnpm -r clean         # Clean dist/ directories
```

---

Built by [GNS Foundation](https://globecrumbs.com) · Identity = Public Key
