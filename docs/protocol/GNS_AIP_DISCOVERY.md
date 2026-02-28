# GNS-AIP Discovery Endpoint Specification

## `/.well-known/gns-aip.json`

**Version:** 1.0  
**Status:** Draft  
**Date:** 2026-02-28  
**Authors:** Camilo Ayerbe, Usama Sardar

## 1. Overview

The `/.well-known/gns-aip.json` endpoint is the primary discovery mechanism for AI agents operating on a website. When a user navigates to any HTTPS page, the GNS Vault browser extension fetches this endpoint to discover which AI agents are active and what provenance chain backs them.

This follows the RFC 8615 (Well-Known URIs) convention, placing the discovery file at a predictable path that requires no page-level changes — the platform operator simply serves a JSON file.

## 2. Discovery Chain

The extension attempts agent discovery in this order:

| Priority | Method | Trigger |
|----------|--------|---------|
| 1 | `GET /.well-known/gns-aip.json` | Background on navigation |
| 2 | `_gns-aip.{domain}` DNS TXT record | Background fallback |
| 3 | `<meta name="gns-aip-agent">` HTML tag | Content script scan |
| 4 | `window.__GNS_AIP_AGENTS__` JS global | Content script scan |
| 5 | `<script data-gns-aip>` attributes | Content script scan |
| 6 | `GNSAuth.declareAgent()` SDK call | Content script event |

Methods 1-2 run in the service worker (no DOM access needed).  
Methods 3-6 run in the content script (DOM access required).

## 3. JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "GNS-AIP Agent Manifest",
  "description": "AI agent declarations for the GNS Vault browser extension",
  "type": "object",
  "required": ["version", "agents"],
  "properties": {
    "version": {
      "type": "integer",
      "const": 1,
      "description": "Schema version (always 1 for this draft)"
    },
    "domain": {
      "type": "string",
      "description": "Domain this manifest applies to (informational)"
    },
    "agents": {
      "type": "array",
      "minItems": 1,
      "maxItems": 20,
      "items": { "$ref": "#/definitions/AgentEntry" }
    },
    "updated_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of last manifest update"
    }
  },
  "definitions": {
    "AgentEntry": {
      "type": "object",
      "required": ["agent_key"],
      "properties": {
        "agent_key": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$",
          "description": "Agent's Ed25519 public key (32 bytes, hex-encoded)"
        },
        "model_id": {
          "type": "string",
          "description": "Model identifier (e.g., 'claude-sonnet-4-5-20250929')"
        },
        "creator_org": {
          "type": "string",
          "format": "hostname",
          "description": "Domain of the organization that created the model"
        },
        "deployer_org": {
          "type": "string",
          "format": "hostname",
          "description": "Domain of the organization that deployed the agent"
        },
        "model_hash": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$",
          "description": "SHA-256 hash of the model weights (32 bytes, hex)"
        },
        "territory_cells": {
          "type": "array",
          "items": { "type": "integer" },
          "description": "H3 cell indices defining the agent's operational territory"
        },
        "territory_resolution": {
          "type": "integer",
          "minimum": 0,
          "maximum": 15,
          "description": "H3 resolution for the territory cells"
        },
        "delegation_cert_url": {
          "type": "string",
          "format": "uri",
          "description": "URL to fetch the COSE_Sign1 delegation certificate"
        },
        "capabilities": {
          "type": "array",
          "items": { "type": "string" },
          "description": "GNS facets this agent is authorized to operate on"
        },
        "safety_certs": {
          "type": "array",
          "items": { "type": "string", "format": "uri" },
          "description": "URIs to safety evaluation documentation"
        },
        "jurisdiction_binding": {
          "type": "object",
          "additionalProperties": {
            "$ref": "#/definitions/JurisdictionBinding"
          },
          "description": "Map of region identifiers to applicable regulations"
        }
      }
    },
    "JurisdictionBinding": {
      "type": "object",
      "required": ["regulations"],
      "properties": {
        "regulations": {
          "type": "array",
          "items": { "type": "string" },
          "description": "List of applicable regulation names"
        },
        "risk_class": {
          "type": "string",
          "enum": ["low", "medium", "high", "unacceptable"],
          "description": "AI Act risk classification"
        },
        "disclosure_required": {
          "type": "boolean",
          "description": "Whether the agent must disclose AI identity to users"
        }
      }
    }
  }
}
```

## 4. Example Manifest

A platform deploying an Anthropic Claude agent for customer support:

```json
{
  "version": 1,
  "domain": "shop.example.com",
  "agents": [
    {
      "agent_key": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      "model_id": "claude-sonnet-4-5-20250929",
      "creator_org": "anthropic.com",
      "deployer_org": "shop.example.com",
      "model_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "territory_cells": [596538758865788927, 596538758865854463],
      "territory_resolution": 4,
      "delegation_cert_url": "https://shop.example.com/.well-known/gns-aip-delegation/a1b2c3d4.json",
      "capabilities": ["chat@", "support@", "orders@"],
      "safety_certs": [
        "https://anthropic.com/safety/claude-4-5-eval-card",
        "https://shop.example.com/ai-transparency"
      ],
      "jurisdiction_binding": {
        "EU": {
          "regulations": ["EU AI Act", "GDPR"],
          "risk_class": "medium",
          "disclosure_required": true
        },
        "US-CA": {
          "regulations": ["CCPA", "Cal. AI Transparency Act"],
          "risk_class": "medium",
          "disclosure_required": true
        }
      }
    }
  ],
  "updated_at": "2026-02-28T12:00:00Z"
}
```

## 5. DNS TXT Fallback

If serving `.well-known` files is impractical, operators can declare agents via DNS TXT:

```
_gns-aip.shop.example.com. 3600 IN TXT "v=gns-aip1; agents=1; creator=anthropic.com; deployer=shop.example.com; pk=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

DNS TXT records carry fewer fields. The extension uses them as lightweight presence indicators, then fetches the full manifest from `.well-known` if available.

## 6. Content Script Fallback

For SPAs that don't control server-side `.well-known` paths:

### Meta Tag
```html
<meta name="gns-aip-agent"
      content="key=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2; model=claude-sonnet; creator=anthropic.com">
```

### JavaScript Global
```javascript
window.__GNS_AIP_AGENTS__ = [{
  agent_key: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  model_id: 'claude-sonnet',
  creator_org: 'anthropic.com',
}];
```

### GNS Auth SDK
```javascript
GNSAuth.declareAgent({
  agent_key: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
  model_id: 'claude-sonnet',
  creator_org: 'anthropic.com',
  capabilities: ['chat@', 'support@'],
});
```

## 7. HTTP Headers (Optional)

Platforms may also advertise agent presence via response headers:

```
X-GNS-AIP-Agent: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
X-GNS-AIP-Creator: anthropic.com
```

## 8. Verification Flow

```
Extension navigates to shop.example.com
    │
    ├─ Background: GET /.well-known/gns-aip.json → finds 1 agent
    │
    ├─ For each agent in manifest:
    │   ├─ L1 Creator:   DNS check _gns-aip.anthropic.com → ✓ found
    │   ├─ L2 Deployer:  DNS check _gns-aip.shop.example.com → ✓ found
    │   └─ L3 Principal: Fetch delegation cert → verify PoH + trust + temporal → ✓
    │
    ├─ Shield = 🟢 Green (all 3 layers verified)
    │
    ├─ Store in chrome.storage.session
    ├─ Update badge: "✓" green
    │
    └─ Popup opens → AgentCard renders provenance chain
```

## 9. CORS Requirements

The `/.well-known/gns-aip.json` endpoint **MUST** include CORS headers to allow the extension to fetch it:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET
Access-Control-Allow-Headers: Accept
```

Most CDNs and static hosting platforms include these by default for `.well-known` paths.

## 10. Security Considerations

- **HTTPS only**: The extension only fetches `.well-known` from HTTPS origins.
- **No executable content**: The manifest is pure JSON; no scripts, no dynamic evaluation.
- **Max 20 agents**: Prevents abuse via oversized manifests.
- **Key validation**: Agent keys must be valid 64-char hex (32-byte Ed25519 public keys).
- **Cache TTL**: Extension caches results for 5 minutes to limit fetch frequency.
- **DNS cross-check**: Creator and deployer claims are verified against DNS TXT records that only the domain owner can set.
