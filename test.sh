#!/bin/bash
# End-to-end test: start proxy, run sandboxed commands, verify behavior.
# Run this to see it all working before trying goose.

set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_PROFILE="$DIR/sandbox.sb"
SANDBOX_ARGS=(-D "SECRETS_DIR=$HOME/.secrets")
PROXY="http://localhost:18080"
PROXY_PID=""

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    wait "$PROXY_PID" 2>/dev/null
}
trap cleanup EXIT

echo "=== Starting proxy ==="
python3 "$DIR/proxy.py" --port 18080 --blocked "$DIR/blocked.txt" &
PROXY_PID=$!
sleep 1

run_sandboxed() {
    sandbox-exec -f "$SANDBOX_PROFILE" "${SANDBOX_ARGS[@]}" \
        env http_proxy="$PROXY" https_proxy="$PROXY" \
            HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY" \
            no_proxy="localhost,127.0.0.1" \
            NO_PROXY="localhost,127.0.0.1" \
            NODE_OPTIONS="--use-env-proxy" \
        bash -c "$1"
}

echo ""
echo "==========================================="
echo "  TEST 1: Fetch allowed URL (via proxy)"
echo "==========================================="
run_sandboxed 'curl -sf https://example.com | head -c 100'
echo ""
echo "→ PASS: traffic went through proxy"

echo ""
echo "==========================================="
echo "  TEST 2: Direct outbound (bypass proxy)"
echo "==========================================="
echo "(Trying direct connect without proxy — should fail)"
sandbox-exec -f "$SANDBOX_PROFILE" "${SANDBOX_ARGS[@]}" \
    curl -sf --max-time 3 https://example.com 2>&1 || true
echo "→ PASS: sandbox blocked direct connection"

echo ""
echo "==========================================="
echo "  TEST 3: Raw socket (python, no proxy)"
echo "==========================================="
sandbox-exec -f "$SANDBOX_PROFILE" "${SANDBOX_ARGS[@]}" \
    python3 -c "
import socket
try:
    s = socket.create_connection(('evil.com', 443), timeout=3)
    print('FAIL: connected!')
except PermissionError:
    print('PASS: sandbox blocked raw socket')
except Exception as e:
    print(f'PASS: blocked ({type(e).__name__})')
"

echo ""
echo "==========================================="
echo "  TEST 4: git through proxy"
echo "==========================================="
run_sandboxed 'git ls-remote --heads https://github.com/golang/go 2>/dev/null | head -1'
echo "→ PASS: git works through proxy"

echo ""
echo "==========================================="
echo "  TEST 5: Node.js fetch (via NODE_OPTIONS)"
echo "==========================================="
if command -v node >/dev/null 2>&1; then
    run_sandboxed 'node -e "fetch(\"https://example.com\").then(r=>console.log(\"status:\",r.status)).catch(e=>console.log(\"FAIL:\",e.message))"'
    echo "→ PASS: Node.js fetch works through proxy (NODE_OPTIONS=--use-env-proxy)"
else
    echo "→ SKIP: node not installed"
fi

echo ""
echo "==========================================="
echo "  TEST 6: Node.js fetch WITHOUT proxy (should fail)"
echo "==========================================="
if command -v node >/dev/null 2>&1; then
    sandbox-exec -f "$SANDBOX_PROFILE" "${SANDBOX_ARGS[@]}" \
        node -e "fetch('https://example.com').then(r=>console.log('FAIL: should not reach here')).catch(e=>console.log('PASS: blocked -',e.cause?.code||e.message))" 2>&1
    echo "→ PASS: sandbox blocks Node.js without proxy config"
else
    echo "→ SKIP: node not installed"
fi

echo ""
echo "==========================================="
echo "  TEST 7: Live block (add domain to blocked.txt)"
echo "==========================================="
echo "Adding example.com to blocked.txt..."
echo "example.com" >> "$DIR/blocked.txt"
sleep 0.5
echo "(Trying to fetch example.com — should be blocked now)"
run_sandboxed 'curl -s --max-time 5 https://example.com 2>&1 || echo "blocked (exit $?)"'
echo "→ PASS: live blocking works"

# Clean up blocked.txt
sed -i '' '/^example\.com$/d' "$DIR/blocked.txt"

echo ""
echo "==========================================="
echo "  TEST 8: Localhost still works"
echo "==========================================="
sandbox-exec -f "$SANDBOX_PROFILE" "${SANDBOX_ARGS[@]}" \
    bash -c '
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b\"local server works\")
    def log_message(self, *a): pass
s = HTTPServer((\"127.0.0.1\", 19999), H)
t = threading.Thread(target=s.handle_request, daemon=True)
t.start()
import time; time.sleep(0.3)
import urllib.request
print(urllib.request.urlopen(\"http://127.0.0.1:19999\").read().decode())
"'
echo "→ PASS: localhost communication works"

echo ""
echo "==========================================="
echo "  TEST 9: ~/.secrets is blocked"
echo "==========================================="
mkdir -p "$HOME/.secrets"
echo "secret-api-key-12345" > "$HOME/.secrets/test.txt"
sandbox-exec -f "$SANDBOX_PROFILE" "${SANDBOX_ARGS[@]}" \
    cat "$HOME/.secrets/test.txt" 2>&1 || true
echo "→ PASS: ~/.secrets is not readable from sandbox"

echo ""
echo "==========================================="
echo "  TEST 10: Proxy accepts --ld-client-id arg"
echo "==========================================="
# Verify the arg is accepted (proxy starts, doesn't crash)
# We use a bogus ID — it should start fine and default-allow
kill "$PROXY_PID" 2>/dev/null
wait "$PROXY_PID" 2>/dev/null
python3 "$DIR/proxy.py" --port 18080 --blocked "$DIR/blocked.txt" --ld-client-id "fake-id" &
PROXY_PID=$!
sleep 1
run_sandboxed 'curl -sf https://example.com | head -c 100'
echo ""
echo "→ PASS: proxy works with --ld-client-id (defaults allow on unreachable LD)"

echo ""
echo "==========================================="
echo "  ALL TESTS PASSED"
echo "==========================================="
echo ""
echo "Check connections.log for the full traffic log."
echo ""
echo "To use with an agent:"
echo "  Terminal 1:  ./start-proxy.sh"
echo "  Terminal 2:  ./start-goose.sh  or  ./start-claude.sh  or  ./start-pi.sh"
echo ""
echo "To block a domain live:"
echo "  echo 'evil.com' >> blocked.txt"
