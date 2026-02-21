#!/bin/bash
# ============================================================
# GNS Vault — Push to GitHub + Deploy Demo Store to Railway
# Run from: ~/gns-vault
# ============================================================

set -e

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  GNS Vault — Deploy Demo Store + Push Git    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ----------------------------------------------------------
# 1. Verify we're in the right directory
# ----------------------------------------------------------
if [ ! -f "pnpm-workspace.yaml" ]; then
  echo "❌ Run this from ~/gns-vault"
  exit 1
fi

# ----------------------------------------------------------
# 2. Build everything to make sure it compiles
# ----------------------------------------------------------
echo "📦 Building all packages..."
pnpm install --frozen-lockfile 2>/dev/null || pnpm install
pnpm --filter @gns-vault/core build
pnpm --filter @gns-vault/extension build
echo "✅ All packages built"
echo ""

# ----------------------------------------------------------
# 3. Git add + commit + push
# ----------------------------------------------------------
echo "📝 Staging changes..."
git add -A

echo ""
echo "Changed files:"
git diff --cached --stat
echo ""

read -p "Commit message [feat: auth-bridge dual-protocol + demo-store Railway deploy]: " MSG
MSG=${MSG:-"feat: auth-bridge dual-protocol + demo-store Railway deploy"}

git commit -m "$MSG"
echo ""
echo "🚀 Pushing to GitHub..."
git push origin main
echo "✅ Pushed to GitHub"
echo ""

# ----------------------------------------------------------
# 4. Deploy demo-store to Railway
# ----------------------------------------------------------
echo "🚂 Deploying demo-store to Railway..."
echo ""

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
  echo "⚠️  Railway CLI not found. Install with:"
  echo "   npm install -g @railway/cli"
  echo ""
  echo "Then run manually:"
  echo "   cd apps/demo-store"
  echo "   railway login"
  echo "   railway link  (select your project)"
  echo "   railway up"
  echo ""
  echo "Or deploy from Railway dashboard:"
  echo "   1. Go to https://railway.app/dashboard"
  echo "   2. Open gns-vault project"
  echo "   3. Click '+ New' → 'Docker Image' or 'GitHub Repo'"
  echo "   4. Select gns-vault repo"
  echo "   5. Set Root Directory: apps/demo-store"
  echo "   6. It will auto-detect the Dockerfile"
  echo "   7. Add custom domain: demo.gcrumbs.com (optional)"
  echo ""
  exit 0
fi

# Deploy via Railway CLI
cd apps/demo-store

echo "Linking to Railway project..."
echo "(Select your gns-vault project, create new service 'demo-store')"
echo ""

railway up --detach

echo ""
echo "✅ Demo store deployed!"
echo ""
echo "Next steps:"
echo "  1. Go to Railway dashboard → demo-store service"
echo "  2. Settings → Networking → Generate Domain"
echo "  3. (Optional) Add custom domain: demo.gcrumbs.com"
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Done! Both GitHub and Railway are updated.  ║"
echo "╚══════════════════════════════════════════════╝"
