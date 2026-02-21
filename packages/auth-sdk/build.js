/**
 * Build script for @gns-vault/auth-sdk
 *
 * Produces:
 *   dist/gns-auth.js     — ES module (for npm imports)
 *   dist/gns-auth.d.ts   — TypeScript declarations
 *   dist/gns-auth.min.js — Standalone browser bundle (for <script> tag)
 */

import { buildSync } from 'esbuild';

// Browser bundle (standalone, IIFE)
buildSync({
  entryPoints: ['dist/gns-auth.js'],
  bundle: true,
  minify: true,
  format: 'iife',
  globalName: 'GNSAuthBundle',
  outfile: 'dist/gns-auth.min.js',
  target: ['es2020', 'chrome90', 'firefox90', 'safari14'],
  platform: 'browser',
});

console.log('✓ Built dist/gns-auth.min.js (standalone browser bundle)');
