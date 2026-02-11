#!/bin/bash
# Start the logging proxy in the foreground.
# All connections are logged to stderr (with color) and to connections.log.
# Edit blocked.txt to block domains in real time.

DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/proxy.py" \
    --port 18080 \
    --blocked "$DIR/blocked.txt" \
    --log "$DIR/connections.log"
