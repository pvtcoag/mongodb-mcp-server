#!/bin/sh
set -e

# Railway (and most Docker volume mounts) attach the volume as root-owned.
# The server runs as the unprivileged `mcp` user, so it can't write the OAuth
# tokens file. Fix permissions on any directory the server is told to write to,
# then drop privileges and exec the real command.

fix_dir() {
    dir="$1"
    if [ -n "$dir" ] && [ -d "$dir" ]; then
        chown -R mcp:mcp "$dir" 2>/dev/null || true
    fi
}

if [ "$(id -u)" = "0" ]; then
    # Derive directory from MDB_MCP_OAUTH_TOKENS_FILE if set.
    if [ -n "${MDB_MCP_OAUTH_TOKENS_FILE:-}" ]; then
        token_dir="$(dirname "$MDB_MCP_OAUTH_TOKENS_FILE")"
        mkdir -p "$token_dir" 2>/dev/null || true
        fix_dir "$token_dir"
    fi
    # Common Railway mount path.
    fix_dir /data

    exec su-exec mcp:mcp "$@"
fi

exec "$@"
