FROM node:20-alpine AS builder

WORKDIR /app

# Install pnpm
RUN npm install -g pnpm@9

# Copy workspace files
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json ./
COPY packages/verify-api/package.json packages/verify-api/
COPY packages/vault-core/package.json packages/vault-core/

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy source
COPY packages/vault-core/ packages/vault-core/
COPY packages/verify-api/ packages/verify-api/

# Build
RUN pnpm --filter @gns-vault/core build
RUN pnpm --filter @gns-vault/verify-api build

# Production image
FROM node:20-alpine

WORKDIR /app

RUN npm install -g pnpm@9

COPY --from=builder /app/pnpm-workspace.yaml /app/package.json /app/pnpm-lock.yaml ./
COPY --from=builder /app/packages/verify-api/package.json packages/verify-api/
COPY --from=builder /app/packages/verify-api/dist/ packages/verify-api/dist/
COPY --from=builder /app/packages/vault-core/package.json packages/vault-core/
COPY --from=builder /app/packages/vault-core/dist/ packages/vault-core/dist/

RUN pnpm install --frozen-lockfile --prod

EXPOSE 3847

ENV PORT=3847
ENV NODE_ENV=production

CMD ["node", "packages/verify-api/dist/server.js"]
