/**
 * GNS AIP (AI Agent Identity Protocol) — Test Suite
 *
 * Tests the AIP endpoints using Hono's built-in test client.
 * Focuses on:
 *   - POST /v1/aip/verify-chain — provenance chain verification
 *   - GET  /v1/aip/agent/:key   — agent lookup
 *   - GET  /v1/aip/jurisdiction/:cell — H3 jurisdiction resolution
 *   - POST /v1/aip/delegation/validate — delegation certificate validation
 *   - GET  /v1/aip/health — subsystem health check
 *
 * NOTE: These tests DO NOT hit real DNS or remote delegation URLs.
 * They verify request validation, response shapes, caching, and
 * Ed25519 signature verification for delegation certificates.
 */

import { describe, it, expect } from 'vitest';
import app from '../src/server.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// Configure noble ed25519
ed.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => {
  const h = sha512.create();
  for (const msg of m) h.update(msg);
  return h.digest();
};

// ============================================================
// HELPERS
// ============================================================

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function req(path: string, options?: RequestInit) {
  return app.request(path, options);
}

function jsonPost(path: string, body: unknown) {
  return req(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function generateTestKeypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
    privateKey,
    publicKey,
  };
}

// ============================================================
// AIP HEALTH
// ============================================================

describe('GET /v1/aip/health', () => {
  it('should return ok status', async () => {
    const res = await req('/v1/aip/health');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
    expect(data.subsystem).toBe('aip');
    expect(data.timestamp).toBeDefined();
    expect(typeof data.cache_size).toBe('number');
  });
});

// ============================================================
// POST /v1/aip/verify-chain
// ============================================================

describe('POST /v1/aip/verify-chain', () => {
  it('should reject missing domain', async () => {
    const res = await jsonPost('/v1/aip/verify-chain', {
      agents: [{ agent_key: 'a'.repeat(64) }],
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.code).toBe('BAD_REQUEST');
  });

  it('should reject empty agents array', async () => {
    const res = await jsonPost('/v1/aip/verify-chain', {
      domain: 'example.com',
      agents: [],
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.code).toBe('BAD_REQUEST');
  });

  it('should reject more than 20 agents', async () => {
    const agents = Array.from({ length: 21 }, (_, i) => ({
      agent_key: i.toString(16).padStart(64, '0'),
    }));
    const res = await jsonPost('/v1/aip/verify-chain', {
      domain: 'example.com',
      agents,
    });
    expect(res.status).toBe(400);
  });

  it('should skip agents with invalid keys', async () => {
    const res = await jsonPost('/v1/aip/verify-chain', {
      domain: 'example.com',
      agents: [
        { agent_key: 'too-short' },
        { agent_key: 'x'.repeat(64) }, // non-hex
      ],
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.agent_count).toBe(0);
    expect(data.agents).toHaveLength(0);
  });

  it('should return verification result for valid agent', async () => {
    const agentKey = 'a'.repeat(64);
    const res = await jsonPost('/v1/aip/verify-chain', {
      domain: 'test-platform.example.com',
      agents: [{
        agent_key: agentKey,
        model_id: 'test-model-v1',
        creator_org: 'nonexistent-creator.test',
        deployer_org: 'nonexistent-deployer.test',
      }],
    });

    expect(res.status).toBe(200);
    const data = await res.json();

    expect(data.domain).toBe('test-platform.example.com');
    expect(data.agent_count).toBe(1);
    expect(data.best_shield).toBeDefined();
    expect(data.checked_at).toBeDefined();
    expect(data.agents).toHaveLength(1);

    const agent = data.agents[0];
    expect(agent.agent_key).toBe(agentKey);
    expect(agent.model_id).toBe('test-model-v1');
    expect(agent.layers).toHaveLength(3);
    expect(agent.verified_at).toBeDefined();
    expect(Array.isArray(agent.warnings)).toBe(true);

    // Verify layer structure
    expect(agent.layers[0].layer).toBe(1);
    expect(agent.layers[0].label).toBe('Creator');
    expect(agent.layers[1].layer).toBe(2);
    expect(agent.layers[1].label).toBe('Deployer');
    expect(agent.layers[2].layer).toBe(3);
    expect(agent.layers[2].label).toBe('Principal');
  });

  it('should return red shield when no DNS records exist', async () => {
    const res = await jsonPost('/v1/aip/verify-chain', {
      domain: 'no-records.test',
      agents: [{
        agent_key: 'b'.repeat(64),
        creator_org: 'fake-creator.test',
      }],
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    // With no DNS records, shield should be red or amber at best
    expect(['red', 'amber']).toContain(data.best_shield);
  });

  it('should return shield from green/amber/red set', async () => {
    const res = await jsonPost('/v1/aip/verify-chain', {
      domain: 'example.com',
      agents: [{ agent_key: 'c'.repeat(64) }],
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(['green', 'amber', 'red', 'unknown']).toContain(data.best_shield);
  });
});

// ============================================================
// GET /v1/aip/agent/:agentKey
// ============================================================

describe('GET /v1/aip/agent/:agentKey', () => {
  it('should reject invalid key format', async () => {
    const res = await req('/v1/aip/agent/tooshort');
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.code).toBe('BAD_REQUEST');
  });

  it('should return not-found for unverified agent', async () => {
    const res = await req(`/v1/aip/agent/${'d'.repeat(64)}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.found).toBe(false);
    expect(data.agent_key).toBe('d'.repeat(64));
  });

  it('should return cached agent after verify-chain', async () => {
    const agentKey = 'e'.repeat(64);

    // First: verify the agent
    await jsonPost('/v1/aip/verify-chain', {
      domain: 'cached-test.example.com',
      agents: [{ agent_key: agentKey, model_id: 'cached-model' }],
    });

    // Then: lookup should find the cached result
    const res = await req(`/v1/aip/agent/${agentKey}`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.found).toBe(true);
    expect(data.agent_key).toBe(agentKey);
    expect(data.shield).toBeDefined();
  });
});

// ============================================================
// GET /v1/aip/jurisdiction/:h3cell
// ============================================================

describe('GET /v1/aip/jurisdiction/:h3cell', () => {
  it('should return EU AI Act for known EU cell', async () => {
    const res = await req('/v1/aip/jurisdiction/821f87fffffffff');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.cell).toBe('821f87fffffffff');
    expect(data.regulations).toContain('EU AI Act');
    expect(data.risk_class).toBe('high');
    expect(data.disclosure_required).toBe(true);
  });

  it('should return CCPA for known California cell', async () => {
    const res = await req('/v1/aip/jurisdiction/822d57fffffffff');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.regulations).toContain('CCPA');
  });

  it('should return empty for unknown cell', async () => {
    const res = await req('/v1/aip/jurisdiction/000000000000000');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.regulations).toHaveLength(0);
    expect(data.risk_class).toBe('unknown');
  });
});

// ============================================================
// POST /v1/aip/delegation/validate
// ============================================================

describe('POST /v1/aip/delegation/validate', () => {
  it('should reject missing fields', async () => {
    const res = await jsonPost('/v1/aip/delegation/validate', {});
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.code).toBe('BAD_REQUEST');
  });

  it('should reject invalid public key format', async () => {
    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: 'bad',
      agent_pk: 'also-bad',
      payload: '{}',
      signature: 'f'.repeat(128),
    });
    expect(res.status).toBe(400);
  });

  it('should reject invalid signature format', async () => {
    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: 'a'.repeat(64),
      agent_pk: 'b'.repeat(64),
      payload: '{}',
      signature: 'tooshort',
    });
    expect(res.status).toBe(400);
  });

  it('should validate a correct Ed25519 delegation signature', async () => {
    const principal = await generateTestKeypair();
    const agent = await generateTestKeypair();

    const payload = JSON.stringify({
      agent_pk: agent.publicKeyHex,
      capabilities: ['chat', 'search'],
      trust_score: 75,
      trust_floor: 50,
      poh_alpha: 0.55,
      not_before: new Date(Date.now() - 86400_000).toISOString(),
      not_after: new Date(Date.now() + 86400_000 * 30).toISOString(),
    });

    const msgBytes = new TextEncoder().encode(payload);
    const signature = await ed.signAsync(msgBytes, principal.privateKey);

    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: principal.publicKeyHex,
      agent_pk: agent.publicKeyHex,
      payload,
      signature: bytesToHex(signature),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.signature_valid).toBe(true);
    expect(data.poh_valid).toBe(true);
    expect(data.temporal_valid).toBe(true);
    expect(data.trust_valid).toBe(true);
    expect(data.overall_valid).toBe(true);
    expect(data.trust_score).toBe(75);
  });

  it('should reject invalid signature', async () => {
    const principal = await generateTestKeypair();
    const agent = await generateTestKeypair();

    const payload = JSON.stringify({ agent_pk: agent.publicKeyHex });

    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: principal.publicKeyHex,
      agent_pk: agent.publicKeyHex,
      payload,
      signature: 'f'.repeat(128), // Fake signature
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.signature_valid).toBe(false);
    expect(data.overall_valid).toBe(false);
  });

  it('should flag expired delegation', async () => {
    const principal = await generateTestKeypair();
    const agent = await generateTestKeypair();

    const payload = JSON.stringify({
      agent_pk: agent.publicKeyHex,
      trust_score: 80,
      trust_floor: 50,
      poh_alpha: 0.50,
      not_after: new Date(Date.now() - 86400_000).toISOString(), // Expired yesterday
    });

    const msgBytes = new TextEncoder().encode(payload);
    const signature = await ed.signAsync(msgBytes, principal.privateKey);

    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: principal.publicKeyHex,
      agent_pk: agent.publicKeyHex,
      payload,
      signature: bytesToHex(signature),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.signature_valid).toBe(true);
    expect(data.temporal_valid).toBe(false);
    expect(data.overall_valid).toBe(false);
  });

  it('should flag PoH alpha out of range', async () => {
    const principal = await generateTestKeypair();
    const agent = await generateTestKeypair();

    const payload = JSON.stringify({
      agent_pk: agent.publicKeyHex,
      trust_score: 80,
      poh_alpha: 0.95, // Out of [0.30, 0.80] range
      not_after: new Date(Date.now() + 86400_000 * 30).toISOString(),
    });

    const msgBytes = new TextEncoder().encode(payload);
    const signature = await ed.signAsync(msgBytes, principal.privateKey);

    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: principal.publicKeyHex,
      agent_pk: agent.publicKeyHex,
      payload,
      signature: bytesToHex(signature),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.signature_valid).toBe(true);
    expect(data.poh_valid).toBe(false);
    expect(data.overall_valid).toBe(false);
  });

  it('should flag trust score below floor', async () => {
    const principal = await generateTestKeypair();
    const agent = await generateTestKeypair();

    const payload = JSON.stringify({
      agent_pk: agent.publicKeyHex,
      trust_score: 30,     // Below floor
      trust_floor: 50,
      poh_alpha: 0.55,
      not_after: new Date(Date.now() + 86400_000 * 30).toISOString(),
    });

    const msgBytes = new TextEncoder().encode(payload);
    const signature = await ed.signAsync(msgBytes, principal.privateKey);

    const res = await jsonPost('/v1/aip/delegation/validate', {
      principal_pk: principal.publicKeyHex,
      agent_pk: agent.publicKeyHex,
      payload,
      signature: bytesToHex(signature),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.signature_valid).toBe(true);
    expect(data.trust_valid).toBe(false);
    expect(data.overall_valid).toBe(false);
  });
});
