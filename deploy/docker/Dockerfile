FROM node:22.16.0-bookworm-slim AS builder
WORKDIR /opt/build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:22.16.0-bookworm-slim
ENV NODE_ENV=production
WORKDIR /opt/authscope
COPY --from=builder --chown=node:node /opt/build/package.json ./
COPY --from=builder --chown=node:node /opt/build/node_modules ./node_modules
COPY --from=builder --chown=node:node /opt/build/dist ./dist
USER node
WORKDIR /workspace
ENTRYPOINT ["node", "/opt/authscope/dist/cli.js"]
