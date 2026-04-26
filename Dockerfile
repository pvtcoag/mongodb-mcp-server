FROM node:24-alpine AS builder

RUN corepack enable && corepack prepare pnpm@10.23.0 --activate

WORKDIR /build

ENV CI=true

COPY . .

RUN pnpm install --frozen-lockfile --ignore-scripts
RUN pnpm run build
RUN pnpm prune --prod --ignore-scripts

FROM node:24-alpine AS runner

RUN apk add --no-cache su-exec \
 && addgroup -S mcp && adduser -S mcp -G mcp

WORKDIR /home/mcp

COPY --from=builder --chown=mcp:mcp /build/dist ./dist
COPY --from=builder --chown=mcp:mcp /build/node_modules ./node_modules
COPY --from=builder --chown=mcp:mcp /build/packages ./packages
COPY --from=builder --chown=mcp:mcp /build/package.json ./package.json
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Container starts as root so the entrypoint can chown the Railway-mounted
# volume (mounted root-owned) before dropping to `mcp` via su-exec.
# The Node process never runs as root.

ENV NODE_ENV=production
ENV MDB_MCP_TRANSPORT=http
ENV MDB_MCP_HTTP_HOST=0.0.0.0
ENV MDB_MCP_LOGGERS=stderr,mcp

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh", "node", "dist/index.js"]

LABEL maintainer="pvtcoag"
LABEL description="MongoDB MCP Server (Railway-ready fork)"
