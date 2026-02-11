#!/bin/bash
# Launch goose inside the sandbox.
# Requires the proxy to be running first (start-proxy.sh in another terminal).
#
# Usage:
#   ./start-goose.sh                    # interactive session
#   ./start-goose.sh session -r         # resume last session
#   ./start-goose.sh run -i task.md     # run from instruction file

DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_PROFILE="$DIR/sandbox.sb"
PROXY="http://localhost:18080"

# Check proxy is running
if ! curl -sf --max-time 1 -x "$PROXY" http://example.com/ >/dev/null 2>&1; then
    # Try a simple connect test instead
    if ! (echo >/dev/tcp/localhost/18080) 2>/dev/null; then
        echo "ERROR: Proxy not running on localhost:18080"
        echo "Start it first:  ./start-proxy.sh"
        exit 1
    fi
fi

echo "Starting goose in sandbox (outbound network via proxy only)"
echo "Proxy: $PROXY"
echo "Blocked domains: $DIR/blocked.txt"
echo ""

exec sandbox-exec -f "$SANDBOX_PROFILE" -D "SECRETS_DIR=$HOME/.secrets" \
    env \
        http_proxy="$PROXY" \
        https_proxy="$PROXY" \
        HTTP_PROXY="$PROXY" \
        HTTPS_PROXY="$PROXY" \
        no_proxy="localhost,127.0.0.1,::1" \
        NO_PROXY="localhost,127.0.0.1,::1" \
        NODE_OPTIONS="--use-env-proxy" \
    goose "${@-session}"
