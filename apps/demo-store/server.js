/**
 * GNS Auth Demo Store — Static Server
 *
 * Serves the demo-store index.html on Railway.
 * Includes /health endpoint for Railway health checks.
 */

const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Allow vault.gcrumbs.com API calls
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; " +
    "connect-src https://vault.gcrumbs.com https://*.gcrumbs.com; " +
    "img-src 'self' data:;"
  );
  next();
});

// Health check for Railway
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'gns-demo-store',
    version: '0.2.0',
    timestamp: new Date().toISOString(),
  });
});

// Serve static files from current directory
app.use(express.static(path.join(__dirname), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  },
}));

// SPA fallback — serve index.html for all routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[GNS Demo Store] Running on port ${PORT}`);
  console.log(`[GNS Demo Store] Health: http://localhost:${PORT}/health`);
});
