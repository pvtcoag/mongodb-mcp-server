FROM node:24-alpine AS builder

RUN corepack enable && corepack prepare pnpm@10.23.0 --activate

WORKDIR /build

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages ./packages
COPY eslint-rules ./eslint-rules
COPY tsconfig*.json ./
COPY api-extractor.json ./
COPY vite.ui.config.ts ./
COPY vitest.config.ts ./
COPY knip.json ./
COPY eslint.config.js ./

RUN pnpm install --frozen-lockfile

COPY scripts ./scripts
COPY resources ./resources
COPY src ./src

RUN pnpm run build && pnpm prune --prod

FROM node:24-alpine AS runner

RUN addgroup -S mcp && adduser -S mcp -G mcp

WORKDIR /home/mcp

COPY --from=builder --chown=mcp:mcp /build/dist ./dist
COPY --from=builder --chown=mcp:mcp /build/node_modules ./node_modules
COPY --from=builder --chown=mcp:mcp /build/packages ./packages
COPY --from=builder --chown=mcp:mcp /build/package.json ./package.json

USER mcp

ENV NODE_ENV=production
ENV MDB_MCP_TRANSPORT=http
ENV MDB_MCP_HTTP_HOST=0.0.0.0
ENV MDB_MCP_LOGGERS=stderr,mcp

ENTRYPOINT ["node", "dist/index.js"]

LABEL maintainer="pvtcoag"
LABEL description="MongoDB MCP Server (Railway-ready fork)"
