# GNS Auth Protocol Specification v0.1

## Overview

GNS Auth is a passwordless authentication protocol based on Ed25519 challenge-response.
Websites integrate a lightweight JavaScript SDK (<3KB gzipped) that communicates with the
user's GNS Vault browser extension to prove identity without transmitting any secrets.

## Authentication Flow

```
  Website                     GNS Auth SDK                GNS Vault Extension
    |                              |                              |
    |  1. User clicks button       |                              |
    |----------------------------->|                              |
    |                              |  2. Generate nonce           |
    |                              |  3. window.postMessage       |
    |                              |----------------------------->|
    |                              |                              |  4. Sign(nonce||origin||ts)
    |                              |  5. Return signed response   |     with Ed25519 private key
    |                              |<-----------------------------|
    |  6. onAuth(response)         |                              |
    |<-----------------------------|                              |
    |                                                             |
    |  7. POST /v1/auth/validate (response + challenge)           |
    |------------------------------------------------------------>|  GNS Verify API
    |  8. { valid: true, trust_score: 87.3, badge_tier: "gold" }  |
    |<------------------------------------------------------------|
```

## Challenge Message Format

```json
{
  "nonce": "<32 bytes, hex>",
  "origin": "https://example.com",
  "timestamp": "2026-02-21T12:00:00.000Z",
  "expiresIn": 300
}
```

## Canonical Signing Payload

```
nonce || "|" || origin || "|" || timestamp
```

The extension signs this canonical string with the user's Ed25519 private key (RFC 8032).

## Response Format

```json
{
  "nonce": "<echoed nonce>",
  "publicKey": "<Ed25519 public key, 64 hex chars>",
  "signature": "<Ed25519 signature, 128 hex chars>",
  "trustScore": 87.3,
  "badgeTier": "gold",
  "handle": "@username",
  "timestamp": "2026-02-21T12:00:00.000Z"
}
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Replay protection | Random nonce + timestamp + expiry |
| Phishing immunity | Origin bound into signed payload |
| No secret transmission | Only public key and signature cross the wire |
| Human verification | TrIP trust score included (cryptographically attested) |
| Tamper detection | Ed25519 signature covers all fields |

## Server-Side Verification

Websites verify responses either:

1. **GNS Verify API** — `POST /v1/auth/validate` (recommended, includes trust attestation)
2. **Local Ed25519 verification** — Using any Ed25519 library (faster, no network call)

## Badge Tier Requirements

| Tier | Breadcrumbs | Age | Trust Score |
|------|------------|-----|-------------|
| Unverified | 0 | — | 0 |
| Bronze | 100+ | 1 week | 20+ |
| Silver | 500+ | 1 month | 40+ |
| Gold | 2,000+ | 3 months | 65+ |
| Platinum | 10,000+ | 6 months | 85+ |
| Diamond | 50,000+ | 12 months | 95+ |

## Trust Score Dimensions

- Trajectory length (30%)
- Spatial diversity (25%)
- Temporal consistency (20%)
- Velocity plausibility (15%)
- Chain integrity (10%)
