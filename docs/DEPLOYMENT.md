# GNS Vault — Deployment Playbook

Three deployments, one session. Follow in order.

---

## 1. GitHub Repository Setup

### Create the repo

```bash
cd ~/path-to/gns-vault

# Initialize if not already
git init
git branch -M main

# Create repo on GitHub (GNS-Foundation org)
gh repo create GNS-Foundation/gns-vault --private --source=. --push

# Or if repo already exists:
git remote add origin git@github.com:GNS-Foundation/gns-vault.git
git add -A
git commit -m "v0.2.0: Full P0-P2 roadmap — vault-core, extension, auth-sdk, verify-api, demo-store

- vault-core: Ed25519, XChaCha20-Poly1305, Argon2id, P2P sync (60 tests)
- vault-extension: Chrome Manifest V3, React popup, auto-fill, GNS Auth bridge
- auth-sdk: 5.1KB 'Sign in with GNS' SDK (25 tests)
- verify-api: Hono REST API with Ed25519 signature validation (26 tests)
- demo-store: Reference e-commerce with GNS Auth integration
- 111 tests passing across 4 suites
- CI pipeline with parallel test jobs and security audit
- TrIP terminology updated throughout (IETF submission)"

git push -u origin main
```

### Add GitHub Secrets (for Railway auto-deploy)

Go to: `Settings → Secrets and variables → Actions → New repository secret`

| Secret | Value | Where to get it |
|--------|-------|-----------------|
| `RAILWAY_TOKEN` | Your Railway API token | railway.app → Account → Tokens |

### Verify CI

After pushing, go to `Actions` tab. You should see:
- ✅ Lint & Type Check
- ✅ Test — vault-core (60 tests)
- ✅ Test — auth-sdk (25 tests)
- ✅ Test — verify-api (26 tests)
- ✅ Build All Packages
- ✅ Security Audit

---

## 2. Railway Deployment (Verify API)

### Option A: Railway Dashboard (Recommended first time)

1. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**

2. Select `GNS-Foundation/gns-vault`

3. Railway will detect the `railway.json` and Dockerfile. Configure:

   **Service Name:** `gns-verify-api`

   **Environment Variables:**
   ```
   PORT=3847
   NODE_ENV=production
   ADMIN_KEY=<generate a strong random key>
   ```

   To generate ADMIN_KEY:
   ```bash
   openssl rand -hex 32
   ```

4. Click **Deploy** → Wait for build (~2 minutes)

5. Railway assigns a URL like: `gns-verify-api-production.up.railway.app`

6. **Add custom domain** (optional):
   - Go to Service → Settings → Custom Domain
   - Add: `verify.globecrumbs.com`
   - Add CNAME record in Cloudflare:
     ```
     Type: CNAME
     Name: verify
     Target: <railway-provided-target>.up.railway.app
     Proxy: OFF (DNS only — Railway handles TLS)
     ```

### Option B: Railway CLI

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Link to project (if project already exists)
railway link

# Or create new project
railway init

# Set environment variables
railway variables set PORT=3847
railway variables set NODE_ENV=production
railway variables set ADMIN_KEY=$(openssl rand -hex 32)

# Deploy
railway up
```

### Verify Deployment

```bash
# Health check (replace URL with your Railway URL)
curl https://gns-verify-api-production.up.railway.app/v1/health

# Expected response:
# {"status":"ok","service":"gns-verify-api","version":"0.1.0","timestamp":"..."}

# Test verification endpoint
curl -X POST https://gns-verify-api-production.up.railway.app/v1/verify \
  -H "X-API-Key: gns_test_key_development" \
  -H "Content-Type: application/json" \
  -d '{"public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'

# Expected: {"human":false,"trust_score":0,...}

# Register a test identity
curl -X POST https://gns-verify-api-production.up.railway.app/v1/admin/register \
  -H "X-Admin-Key: <your-admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"public_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","handle":"@testuser","trust_score":85,"breadcrumbs":5000,"badge_tier":"gold","human_verified":true}'

# Now verify again — should return human:true
curl -X POST https://gns-verify-api-production.up.railway.app/v1/verify \
  -H "X-API-Key: gns_test_key_development" \
  -H "Content-Type: application/json" \
  -d '{"public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
```

### Update auth-sdk CDN URL

Once deployed, update the SDK to point to your production URL:

```typescript
// packages/auth-sdk/src/gns-auth.ts — update if you're self-hosting
// Default CDN: https://auth.globecrumbs.com/v1/gns-auth.js
```

### Set up auto-deploy

Railway auto-deploys on push to `main` by default when connected to GitHub. The `.github/workflows/deploy-verify-api.yml` adds a test gate — tests must pass before deploy triggers.

---

## 3. Railway Deployment (Demo Store)

The demo store is a static HTML page served by Express. Deploy as a separate Railway service in the same project.

### Railway Dashboard

1. Open your gns-vault project on [Railway](https://railway.app/dashboard)
2. Click **"+ New"** → **"GitHub Repo"** → select `GNS-Foundation/gns-vault`
3. Configure:
   - **Root Directory:** `apps/demo-store`
   - **Builder:** Dockerfile (auto-detected)
   - **Port:** `3000`
4. Click **Deploy**
5. Once deployed, go to **Settings → Networking → Generate Domain**

### Custom Domain

```
demo.gcrumbs.com → CNAME → <railway-generated-domain>
```

In Cloudflare DNS, add a CNAME record pointing to the Railway domain. Proxy: OFF.

### Railway CLI (alternative)

```bash
cd apps/demo-store
railway link  # Select gns-vault project, create "demo-store" service
railway up
```

### Verify

```bash
curl https://demo.gcrumbs.com/health
# {"status":"ok","service":"gns-demo-store","version":"0.2.0",...}
```

---

## 4. Chrome Web Store Submission

### Prerequisites

1. **Chrome Developer Account** — $5 one-time fee
   - Go to: https://chrome.google.com/webstore/devconsole
   - Register with your Google account
   - Pay $5 registration fee

2. **Extension build ready** — Already done:
   ```bash
   cd gns-vault
   pnpm --filter @gns-vault/extension build
   ls packages/vault-extension/dist/
   # background.js  content.css  content.js  icons/  manifest.json
   # popup.css  popup.html  popup.js  _locales/
   ```

### Step 1: Create the ZIP

```bash
cd packages/vault-extension

# Create submission ZIP from dist/
cd dist
zip -r ../gns-vault-chrome-v0.1.0.zip . \
  -x "*.map" \
  -x "*.LICENSE.txt" \
  -x "icons/logo-source.png"

cd ..
ls -lh gns-vault-chrome-v0.1.0.zip
# Should be ~250KB
```

### Step 2: Upload to Chrome Web Store

1. Go to: https://chrome.google.com/webstore/devconsole

2. Click **New Item** → Upload `gns-vault-chrome-v0.1.0.zip`

3. Fill in the listing:

   **Store Listing tab:**
   - Name: `GNS Vault — Password Manager & Human Identity`
   - Summary: `Secure password vault with Ed25519 decentralized identity. Auto-fill credentials. Prove you're human. Kill passwords forever.`
   - Description: (Copy from `store-assets/LISTING.md`)
   - Category: `Productivity`
   - Language: `English`

   **Graphic Assets tab:**
   Upload from `packages/vault-extension/store-assets/`:
   - Small promo tile: `promo-tile-440x280.png` (440×280)
   - Large promo tile: `promo-large-920x680.png` (920×680)
   - Marquee: `promo-marquee-1400x560.png` (1400×560)
   - Screenshots: Upload the 5 screenshot placeholders (replace with real ones later)
     - **To get real screenshots:** Load the extension unpacked, use it, take screenshots at 1280×800

   **Privacy tab:**
   - Privacy policy URL: `https://globecrumbs.com/privacy`
   - Single purpose: "Securely store credentials and provide decentralized identity authentication"
   - Permissions justification:
     - `storage`: "Store encrypted vault data locally on the user's device"
     - `activeTab`: "Detect login forms on the active page for auto-fill"
     - `alarms`: "Auto-lock vault after inactivity timeout"
     - `notifications`: "Notify user when credentials are saved"
     - `<all_urls>`: "Auto-fill credentials on any website the user visits"

4. Click **Submit for Review**

### Review Timeline

- First submission: 1-3 business days (sometimes longer)
- Updates after approval: Usually faster (hours to 1 day)
- Common rejection reasons:
  - Missing privacy policy → We have one ✅
  - Overly broad permissions without justification → Justified above ✅
  - Description doesn't match functionality → Matches ✅

### Post-Approval: Update Real Screenshots

Once approved and live:

1. Install from Chrome Web Store
2. Create a vault, add some test entries
3. Take real screenshots at 1280×800:
   - Vault tab with entries
   - Identity tab with badge
   - Generator tab
   - Auto-fill overlay on a login page
   - GNS Auth button on demo store
4. Upload as update in Developer Console

---

## 4. Post-Deployment Checklist

### Verify everything works end-to-end:

```
□ GitHub repo is live and CI passes
□ Railway verify-api health check returns 200
□ Railway verify-api /v1/verify returns valid responses
□ Extension loads in Chrome (developer mode)
□ Extension creates vault successfully
□ Extension auto-fills on a login page
□ Demo store GNS Auth button works
□ Chrome Web Store submission uploaded
```

### DNS Records to Add (Cloudflare)

```
verify    CNAME   <railway-url>.up.railway.app    (DNS only, no proxy)
auth      CNAME   <future-cdn-for-sdk>             (when auth-sdk is CDN-hosted)
```

### Environment Variable Summary

| Service | Variable | Value |
|---------|----------|-------|
| Railway (verify-api) | `PORT` | `3847` (Railway auto-sets) |
| Railway (verify-api) | `NODE_ENV` | `production` |
| Railway (verify-api) | `ADMIN_KEY` | Random 64-char hex |
| GitHub Actions | `RAILWAY_TOKEN` | From railway.app account |

---

## 5. Next Steps After Deployment

1. **Replace test API key** — Create production API keys in verify-api for real customers
2. **Host auth-sdk on CDN** — Upload `gns-auth.min.js` (5.1KB) to Cloudflare R2 or Pages at `auth.globecrumbs.com/v1/gns-auth.js`
3. **Host privacy policy** — Publish `PRIVACY_POLICY.md` at `globecrumbs.com/privacy`
4. **Real screenshots** — Replace placeholder screenshots with actual extension UI
5. **Firefox Add-ons** — Same extension works on Firefox, submit to addons.mozilla.org
6. **Production API keys** — Replace in-memory store with Supabase/PostgreSQL
