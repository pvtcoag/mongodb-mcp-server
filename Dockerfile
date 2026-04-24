FROM node:24-alpine AS builder

RUN corepack enable && corepack prepare pnpm@10.23.0 --activate

WORKDIR /build

ENV CI=true

COPY . .

RUN pnpm install --frozen-lockfile --ignore-scripts
RUN pnpm run build
RUN pnpm prune --prod --ignore-scripts

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
