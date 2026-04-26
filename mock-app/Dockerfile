# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json .
RUN npm install --production

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Why alpine: minimal attack surface, smaller image, fewer CVEs.
FROM node:20-alpine

# Why non-root: matches the containerSecurityContext runAsUser: 1001.
# The app should not run as root even in the default (Solution 1) deployment.
RUN addgroup -g 1001 appgroup && \
    adduser  -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app

# Copy deps from build stage (avoids having npm in the final image)
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=appuser:appgroup . .

USER 1001

EXPOSE 3000

# Why node directly (not npm start): npm adds an extra process layer and
# doesn't forward signals properly, causing slow pod shutdown.
CMD ["node", "server.js"]
