#!/bin/bash
# Start the logging proxy in the foreground.
# All connections are logged to stderr (with color) and to connections.log.
# Edit blocked.txt to block domains in real time.
# Set LAUNCHDARKLY_CLIENT_ID to enable LD-based egress control.

DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$LAUNCHDARKLY_CLIENT_ID" ]; then
    echo "LaunchDarkly: enabled"
else
    echo "LaunchDarkly: not configured (set LAUNCHDARKLY_CLIENT_ID to enable)"
fi

exec python3 "$DIR/proxy.py" \
    --port 18080 \
    --blocked "$DIR/blocked.txt" \
    --log "$DIR/connections.log"
